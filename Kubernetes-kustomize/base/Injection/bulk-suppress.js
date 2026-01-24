// Dependency-Track - Bulk Vulnerability Suppression Script
// This script adds a "Suppress All" button to the Grouped Vulnerabilities table

(function() {
    'use strict';

    // Configuration
    const API_BASE_URL = window.location.origin;
    const CHECK_INTERVAL = 1000;
    let lastTableHTML = '';
    let lastUrl = '';

    // Check if we're on the grouped vulnerabilities tab specifically
    function isOnGroupedVulnerabilitiesTab() {
        // Method 1: Check the active tab pane content
        const activePane = document.querySelector('.tab-pane.active');
        if (!activePane) return false;
        
        // Look for the grouped vulnerabilities specific elements
        // The grouped tab has specific filter controls like "occurrences-form-group"
        const hasOccurrencesFilter = activePane.querySelector('#occurrences-form-group');
        const hasGroupedFilters = activePane.querySelector('#grouped-showInactive-form-group');
        
        // If we have these specific grouped view filters, we're on the grouped tab
        if (hasOccurrencesFilter || hasGroupedFilters) {
            return true;
        }
        
        // Method 2: Check if the active tab text contains "Grouped"
        const activeTab = document.querySelector('.nav-tabs .nav-link.active');
        if (activeTab) {
            const tabText = activeTab.textContent.trim().toLowerCase();
            if (tabText.includes('grouped')) {
                return true;
            }
        }
        
        return false;
    }

    function getApiKey() {
        const token = sessionStorage.getItem('token');
        if (!token) {
            console.error('No API token found in sessionStorage');
            return null;
        }
        return token;
    }

    function getAuthHeaders() {
        const token = getApiKey();
        if (!token) return {};
        return {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
        };
    }

    function showToast(message, type = 'info') {
        if (window.toastr) {
            toastr[type](message);
        } else {
            alert(`[${type.toUpperCase()}] ${message}`);
        }
    }

    async function getAffectedProjects(vulnId, vulnSource, includeSuppressed = true) {
        const apiKey = getApiKey();
        if (!apiKey) {
            throw new Error('No API key available');
        }

        try {
            const response = await fetch(
                `${API_BASE_URL}/api/v1/vulnerability/source/${vulnSource}/vuln/${vulnId}/projects`,
                {
                    method: 'GET',
                    headers: getAuthHeaders()
                }
            );

            if (!response.ok) {
                throw new Error(`API request failed: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Error fetching affected projects:', error);
            throw error;
        }
    }

    async function getAllFindings(projectUuid) {
        const apiKey = getApiKey();
        if (!apiKey) {
            throw new Error('No API key available');
        }

        try {
            // Make TWO explicit calls: one for suppressed=false, one for suppressed=true
            const [nonSuppressedResponse, suppressedResponse] = await Promise.all([
                fetch(`${API_BASE_URL}/api/v1/finding/project/${projectUuid}?suppressed=false`, {
                    method: 'GET',
                    headers: getAuthHeaders()
                }),
                fetch(`${API_BASE_URL}/api/v1/finding/project/${projectUuid}?suppressed=true`, {
                    method: 'GET',
                    headers: getAuthHeaders()
                })
            ]);

            if (!nonSuppressedResponse.ok) {
                throw new Error(`API request failed: ${nonSuppressedResponse.status}`);
            }

            const nonSuppressed = await nonSuppressedResponse.json();
            const suppressed = suppressedResponse.ok ? await suppressedResponse.json() : [];

            // Combine both arrays
            return [...nonSuppressed, ...suppressed];
        } catch (error) {
            console.error('Error fetching findings:', error);
            throw error;
        }
    }

    async function suppressVulnerability(projectUuid, componentUuid, vulnerabilityUuid, analysisConfig) {
        const apiKey = getApiKey();
        if (!apiKey) {
            throw new Error('No API key available');
        }

        try {
            const body = {
                project: projectUuid,
                component: componentUuid,
                vulnerability: vulnerabilityUuid,
                analysisState: analysisConfig.analysisState || 'FALSE_POSITIVE',
                suppressed: analysisConfig.suppressed
            };

            // Add analysisJustification only if it's not null/empty
            // Should only be set when analysisState is NOT_AFFECTED
            if (analysisConfig.analysisJustification) {
                body.analysisJustification = analysisConfig.analysisJustification;
            }

            // Add optional fields only if they have values
            if (analysisConfig.analysisResponse) {
                body.analysisResponse = analysisConfig.analysisResponse;
            }
            if (analysisConfig.analysisDetails) {
                body.analysisDetails = analysisConfig.analysisDetails;
            }
            if (analysisConfig.comment) {
                body.comment = analysisConfig.comment;
            }

            // isSuppressed is the same as suppressed for backward compatibility
            body.isSuppressed = body.suppressed;

            const response = await fetch(
                `${API_BASE_URL}/api/v1/analysis`,
                {
                    method: 'PUT',
                    headers: getAuthHeaders(),
                    body: JSON.stringify(body)
                }
            );

            if (!response.ok) {
                throw new Error(`Operation failed: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Error updating vulnerability:', error);
            throw error;
        }
    }

    async function getVulnerabilityDetails(vulnSource, vulnId) {
        const apiKey = getApiKey();
        if (!apiKey) {
            throw new Error('No API key available');
        }

        try {
            const response = await fetch(
                `${API_BASE_URL}/api/v1/vulnerability/source/${vulnSource}/vuln/${vulnId}`,
                {
                    method: 'GET',
                    headers: getAuthHeaders()
                }
            );

            if (!response.ok) {
                throw new Error(`API request failed: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Error fetching vulnerability details:', error);
            throw error;
        }
    }

    const ANALYSIS_STATES = [
        { value: 'FALSE_POSITIVE', label: 'False Positive', class: 'primary' },
        { value: 'NOT_SET', label: 'Not Set', class: 'secondary' },
        { value: 'EXPLOITABLE', label: 'Exploitable', class: 'danger' },
        { value: 'IN_TRIAGE', label: 'In Triage', class: 'warning' },
        { value: 'RESOLVED', label: 'Resolved', class: 'info' },
        { value: 'NOT_AFFECTED', label: 'Not Affected', class: 'success' }
    ];

    const ANALYSIS_JUSTIFICATIONS = [
        { value: '', label: '-- None --' },
        { value: 'CODE_NOT_PRESENT', label: 'Code Not Present' },
        { value: 'CODE_NOT_REACHABLE', label: 'Code Not Reachable' },
        { value: 'REQUIRES_CONFIGURATION', label: 'Requires Configuration' },
        { value: 'REQUIRES_DEPENDENCY', label: 'Requires Dependency' },
        { value: 'REQUIRES_ENVIRONMENT', label: 'Requires Environment' },
        { value: 'PROTECTED_BY_COMPILER', label: 'Protected by Compiler' },
        { value: 'PROTECTED_AT_RUNTIME', label: 'Protected at Runtime' },
        { value: 'PROTECTED_AT_PERIMETER', label: 'Protected at Perimeter' },
        { value: 'PROTECTED_BY_MITIGATING_CONTROL', label: 'Protected by Mitigating Control' }
    ];

    const ANALYSIS_RESPONSES = [
        { value: '', label: '-- None --' },
        { value: 'CAN_NOT_FIX', label: 'Can Not Fix' },
        { value: 'WILL_NOT_FIX', label: 'Will Not Fix' },
        { value: 'UPDATE', label: 'Update' },
        { value: 'ROLLBACK', label: 'Rollback' },
        { value: 'WORKAROUND_AVAILABLE', label: 'Workaround Available' }
    ];

    function showProjectSelectionModal(projects, vulnId, vulnDetails, callback) {
        // Create modal backdrop
        const backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop fade show';
        backdrop.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); z-index: 1040;';

        // Create modal
        const modal = document.createElement('div');
        modal.className = 'modal fade show';
        modal.style.cssText = 'display: block; z-index: 1050; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); max-width: 1200px; width: 95%;';
        modal.innerHTML = `
            <div class="modal-dialog modal-xl" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fa fa-shield"></i> Configure Analysis for ${vulnId}
                        </h5>
                    </div>
                    <div class="modal-body" style="max-height: 70vh; overflow-y: auto;">
                        <!-- Global Controls -->
                        <div class="card mb-3">
                            <div class="card-header">
                                <strong>Global Settings - Apply to All Selected Projects</strong>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label class="custom-control custom-checkbox mb-2">
                                            <input type="checkbox" id="select-all-projects" class="custom-control-input">
                                            <span class="custom-control-label"><strong>Select All (${projects.length} projects)</strong></span>
                                        </label>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="form-group mb-2">
                                            <label class="custom-control custom-checkbox">
                                                <input type="checkbox" id="global-suppressed" class="custom-control-input" checked>
                                                <span class="custom-control-label"><strong>Mark as Suppressed</strong></span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-2">
                                        <div class="form-group mb-2">
                                            <label class="custom-control custom-checkbox">
                                                <input type="checkbox" id="global-suppressed" class="custom-control-input" checked>
                                                <span class="custom-control-label"><strong>Suppress</strong></span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="col-md-2">
                                        <div class="form-group">
                                            <label for="global-analysis-state"><strong>Analysis:</strong></label>
                                            <select id="global-analysis-state" class="form-control form-control-sm">
                                                <option value="">-- Individual --</option>
                                                ${ANALYSIS_STATES.map(state => `
                                                    <option value="${state.value}" ${state.value === 'FALSE_POSITIVE' ? 'selected' : ''}>
                                                        ${state.label}
                                                    </option>
                                                `).join('')}
                                            </select>
                                        </div>
                                    </div>
                                    <div class="col-md-2">
                                        <div class="form-group">
                                            <label for="global-justification"><strong>Justification:</strong></label>
                                            <select id="global-justification" class="form-control form-control-sm">
                                                <option value="">-- Individual --</option>
                                                ${ANALYSIS_JUSTIFICATIONS.map(j => `
                                                    <option value="${j.value}">${j.label}</option>
                                                `).join('')}
                                            </select>
                                        </div>
                                    </div>
                                    <div class="col-md-2">
                                        <div class="form-group">
                                            <label for="global-response"><strong>Vendor Response:</strong></label>
                                            <select id="global-response" class="form-control form-control-sm">
                                                <option value="">-- Individual --</option>
                                                ${ANALYSIS_RESPONSES.map(r => `
                                                    <option value="${r.value}">${r.label}</option>
                                                `).join('')}
                                            </select>
                                        </div>
                                    </div>
                                    <div class="col-md-2">
                                        <div class="form-group">
                                            <label for="global-details"><strong>Supp. Details:</strong></label>
                                            <input type="text" id="global-details" class="form-control form-control-sm" placeholder="Optional">
                                        </div>
                                    </div>
                                    <div class="col-md-2">
                                        <div class="form-group">
                                            <label for="global-comment"><strong>Comment:</strong></label>
                                            <input type="text" id="global-comment" class="form-control form-control-sm" placeholder="Optional">
                                        </div>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-12">
                                        <button type="button" class="btn btn-sm btn-primary" id="apply-global-settings">
                                            <i class="fa fa-magic"></i> Apply Global Settings to All
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Projects Table -->
                        <div class="table-responsive">
                            <table class="table table-sm table-hover table-bordered">
                                <thead class="thead-light">
                                    <tr>
                                        <th style="width: 40px;"></th>
                                        <th style="width: 200px;">Project</th>
                                        <th style="width: 80px;">Status</th>
                                        <th style="width: 80px;">Suppress</th>
                                        <th style="width: 140px;">Analysis</th>
                                        <th style="width: 160px;">Justification</th>
                                        <th style="width: 140px;">Vendor Response</th>
                                        <th style="width: 150px;">Suppression Details</th>
                                        <th style="width: 150px;">Comment</th>
                                    </tr>
                                </thead>
                                <tbody id="projects-list">
                                    ${projects.map((project, index) => `
                                        <tr data-project-index="${index}">
                                            <td class="text-center">
                                                <div class="custom-control custom-checkbox">
                                                    <input type="checkbox" 
                                                            class="custom-control-input project-checkbox" 
                                                            id="project-${index}" 
                                                            data-project-uuid="${project.uuid}"
                                                            data-project-name="${project.name || 'Unknown'}"
                                                            checked>
                                                    <label class="custom-control-label" for="project-${index}"></label>
                                                </div>
                                            </td>
                                            <td>
                                                <strong>${project.name || 'Unknown'}</strong><br>
                                                <small class="text-muted">v${project.version || '-'}</small>
                                            </td>
                                            <td class="text-center">
                                                ${project.active ? '<span class="badge badge-success">Active</span>' : '<span class="badge badge-secondary">Inactive</span>'}
                                            </td>
                                            <td class="text-center">
                                                <div class="custom-control custom-checkbox">
                                                    <input type="checkbox" 
                                                            class="custom-control-input suppressed-checkbox" 
                                                            id="suppressed-${index}"
                                                            data-project-index="${index}"
                                                            checked>
                                                    <label class="custom-control-label" for="suppressed-${index}"></label>
                                                </div>
                                            </td>
                                            <td>
                                                <select class="form-control form-control-sm analysis-state-select" 
                                                        data-project-index="${index}">
                                                    ${ANALYSIS_STATES.map(state => `
                                                        <option value="${state.value}" ${state.value === 'FALSE_POSITIVE' ? 'selected' : ''}>
                                                            ${state.label}
                                                        </option>
                                                    `).join('')}
                                                </select>
                                            </td>
                                            <td>
                                                <select class="form-control form-control-sm justification-select" 
                                                        data-project-index="${index}"
                                                        disabled>
                                                    ${ANALYSIS_JUSTIFICATIONS.map(j => `
                                                        <option value="${j.value}">${j.label}</option>
                                                    `).join('')}
                                                </select>
                                            </td>
                                            <td>
                                                <select class="form-control form-control-sm response-select" 
                                                        data-project-index="${index}">
                                                    ${ANALYSIS_RESPONSES.map(r => `
                                                        <option value="${r.value}">${r.label}</option>
                                                    `).join('')}
                                                </select>
                                            </td>
                                            <td>
                                                <input type="text" 
                                                       class="form-control form-control-sm details-input" 
                                                       data-project-index="${index}"
                                                       placeholder="Optional">
                                            </td>
                                            <td>
                                                <input type="text" 
                                                       class="form-control form-control-sm comment-input" 
                                                       data-project-index="${index}"
                                                       placeholder="Optional">
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <span class="mr-auto" id="selection-count">
                            <strong>${projects.length}</strong> of ${projects.length} selected
                        </span>
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-warning" id="confirm-suppress">
                            <i class="fa fa-check"></i> Apply Changes
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Add to DOM
        document.body.appendChild(backdrop);
        document.body.appendChild(modal);

        // Function to update justification field based on analysis state
        function updateJustificationState(index) {
            const stateSelect = modal.querySelector(`.analysis-state-select[data-project-index="${index}"]`);
            const justificationSelect = modal.querySelector(`.justification-select[data-project-index="${index}"]`);
            
            if (stateSelect && justificationSelect) {
                if (stateSelect.value === 'NOT_AFFECTED') {
                    justificationSelect.disabled = false;
                } else {
                    justificationSelect.disabled = true;
                    justificationSelect.value = ''; // Reset to null/empty
                }
            }
        }

        // Add change listeners to all analysis state selects
        modal.querySelectorAll('.analysis-state-select').forEach(select => {
            const index = select.getAttribute('data-project-index');
            // Initial state
            updateJustificationState(index);
            
            // Listen for changes
            select.addEventListener('change', () => {
                updateJustificationState(index);
            });
        });

        // Apply global settings button
        const applyGlobalButton = modal.querySelector('#apply-global-settings');
        applyGlobalButton.addEventListener('click', function() {
            const globalSuppressed = modal.querySelector('#global-suppressed').checked;
            const globalState = modal.querySelector('#global-analysis-state').value;
            const globalJustification = modal.querySelector('#global-justification').value;
            const globalResponse = modal.querySelector('#global-response').value;
            const globalDetails = modal.querySelector('#global-details').value;
            const globalComment = modal.querySelector('#global-comment').value;

            // Apply to all rows
            modal.querySelectorAll('tbody tr').forEach((row, index) => {
                const suppressedCheckbox = modal.querySelector(`#suppressed-${index}`);
                if (suppressedCheckbox) suppressedCheckbox.checked = globalSuppressed;

                const stateSelect = modal.querySelector(`.analysis-state-select[data-project-index="${index}"]`);
                if (stateSelect && globalState) {
                    stateSelect.value = globalState;
                    // Update justification state after changing analysis state
                    updateJustificationState(index);
                }

                const justificationSelect = modal.querySelector(`.justification-select[data-project-index="${index}"]`);
                if (justificationSelect && globalJustification !== null && !justificationSelect.disabled) {
                    justificationSelect.value = globalJustification;
                }

                const responseSelect = modal.querySelector(`.response-select[data-project-index="${index}"]`);
                if (responseSelect && globalResponse !== null) {
                    responseSelect.value = globalResponse;
                }

                const detailsInput = modal.querySelector(`.details-input[data-project-index="${index}"]`);
                if (detailsInput && globalDetails) {
                    detailsInput.value = globalDetails;
                }

                const commentInput = modal.querySelector(`.comment-input[data-project-index="${index}"]`);
                if (commentInput && globalComment) {
                    commentInput.value = globalComment;
                }
            });

            showToast('Global settings applied to all projects', 'success');
        });

        // Update selection count
        function updateSelectionCount() {
            const checkboxes = modal.querySelectorAll('.project-checkbox');
            const checked = Array.from(checkboxes).filter(cb => cb.checked).length;
            const total = checkboxes.length;
            modal.querySelector('#selection-count').innerHTML = `<strong>${checked}</strong> of ${total} selected`;
            modal.querySelector('#confirm-suppress').disabled = checked === 0;
        }

        // Select all functionality
        const selectAllCheckbox = modal.querySelector('#select-all-projects');
        selectAllCheckbox.addEventListener('change', function() {
            const checkboxes = modal.querySelectorAll('.project-checkbox');
            checkboxes.forEach(cb => cb.checked = this.checked);
            updateSelectionCount();
        });

        // Individual checkbox listeners
        modal.querySelectorAll('.project-checkbox').forEach(cb => {
            cb.addEventListener('change', () => {
                updateSelectionCount();
                const allChecked = Array.from(modal.querySelectorAll('.project-checkbox')).every(c => c.checked);
                selectAllCheckbox.checked = allChecked;
            });
        });

        // Close handlers
        function closeModal() {
            backdrop.remove();
            modal.remove();
        }

        modal.querySelector('[data-dismiss="modal"]').addEventListener('click', closeModal);
        backdrop.addEventListener('click', closeModal);

        // Confirm handler
        modal.querySelector('#confirm-suppress').addEventListener('click', function() {
            const selectedProjects = Array.from(modal.querySelectorAll('.project-checkbox:checked'))
                .map(cb => {
                    const index = cb.id.replace('project-', '');
                    const suppressedCheckbox = modal.querySelector(`#suppressed-${index}`);
                    const stateSelect = modal.querySelector(`.analysis-state-select[data-project-index="${index}"]`);
                    const justificationSelect = modal.querySelector(`.justification-select[data-project-index="${index}"]`);
                    const responseSelect = modal.querySelector(`.response-select[data-project-index="${index}"]`);
                    const detailsInput = modal.querySelector(`.details-input[data-project-index="${index}"]`);
                    const commentInput = modal.querySelector(`.comment-input[data-project-index="${index}"]`);
                    
                    // Justification is null unless Analysis State is NOT_AFFECTED
                    const analysisState = stateSelect ? stateSelect.value : 'FALSE_POSITIVE';
                    const justification = (analysisState === 'NOT_AFFECTED' && justificationSelect && !justificationSelect.disabled) 
                        ? justificationSelect.value 
                        : null;
                    
                    return {
                        uuid: cb.dataset.projectUuid,
                        name: cb.dataset.projectName,
                        config: {
                            suppressed: suppressedCheckbox ? suppressedCheckbox.checked : true,
                            analysisState: analysisState,
                            analysisJustification: justification,
                            analysisResponse: responseSelect ? responseSelect.value : '',
                            analysisDetails: detailsInput ? detailsInput.value : '',
                            comment: commentInput ? commentInput.value : ''
                        }
                    };
                });
            
            closeModal();
            callback(selectedProjects, vulnDetails);
        });
    }

    async function handleBulkSuppress(button, vulnId, vulnSource) {
        button.disabled = true;
        button.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Loading...';

        try {
            const vulnDetails = await getVulnerabilityDetails(vulnSource, vulnId);
            if (!vulnDetails || !vulnDetails.uuid) {
                throw new Error('Could not retrieve vulnerability UUID');
            }

            const projects = await getAffectedProjects(vulnId, vulnSource);
            
            if (!projects || projects.length === 0) {
                showToast('No projects found for this vulnerability', 'warning');
                button.disabled = false;
                button.innerHTML = '<i class="fa fa-ban"></i> Suppress All';
                return;
            }

            button.disabled = false;
            button.innerHTML = '<i class="fa fa-ban"></i> Suppress All';

            // Show project selection modal
            showProjectSelectionModal(projects, vulnId, vulnDetails, async (selectedProjects, vulnDetails) => {
                await executeBulkSuppression(button, vulnId, selectedProjects, vulnDetails);
            });

        } catch (error) {
            console.error('Error loading projects:', error);
            showToast(`Error: ${error.message}`, 'error');
            button.disabled = false;
            button.innerHTML = '<i class="fa fa-ban"></i> Suppress All';
        }
    }

    async function executeBulkSuppression(button, vulnId, selectedProjects, vulnDetails) {
        button.disabled = true;
        button.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Processing...';

        try {
            showToast(`Processing ${vulnId} in ${selectedProjects.length} project(s)...`, 'info');

            let successCount = 0;
            let errorCount = 0;

            for (const project of selectedProjects) {
                try {
                    // Get ALL findings with a single API call (no suppressed parameter = all findings)
                    const findings = await getAllFindings(project.uuid);

                    // Filter for our specific vulnerability
                    const relevantFindings = findings.filter(
                        f => f.vulnerability && f.vulnerability.uuid === vulnDetails.uuid
                    );

                    if (relevantFindings.length === 0) {
                        console.warn(`No findings for ${vulnId} in project ${project.name}`);
                        continue;
                    }

                    // DEDUPLICATE by component UUID to avoid processing the same component twice
                    // (same vulnerability can appear as both suppressed and non-suppressed)
                    const uniqueComponents = new Map();
                    for (const finding of relevantFindings) {
                        if (finding.component && finding.component.uuid) {
                            // Keep only the first occurrence of each component
                            if (!uniqueComponents.has(finding.component.uuid)) {
                                uniqueComponents.set(finding.component.uuid, finding);
                            }
                        }
                    }

                    // Update each unique component finding
                    for (const [componentUuid, finding] of uniqueComponents) {
                            await suppressVulnerability(
                                project.uuid,
                            componentUuid,
                                vulnDetails.uuid,
                                project.config
                            );
                            successCount++;
                    }
                } catch (err) {
                    console.error(`Error processing project ${project.name}:`, err);
                    errorCount++;
                }
            }

            if (successCount > 0) {
                showToast(
                    `Successfully processed ${vulnId} in ${successCount} instance(s)!`,
                    'success'
                );
            }
            if (errorCount > 0) {
                showToast(
                    `Failed to process ${errorCount} instance(s)`,
                    'error'
                );
            }

            button.innerHTML = '<i class="fa fa-check"></i> Done';
            setTimeout(() => {
                button.disabled = false;
                button.innerHTML = '<i class="fa fa-ban"></i> Suppress All';
                // Force table refresh without full page reload
                lastTableHTML = '';
            }, 2000);

        } catch (error) {
            console.error('Bulk suppression error:', error);
            showToast(`Error: ${error.message}`, 'error');
            button.disabled = false;
            button.innerHTML = '<i class="fa fa-ban"></i> Suppress All';
        }
    }

    function removeExistingButtons() {
        // Remove Actions column header if exists
        const actionsHeader = document.querySelector('th[data-field="actions"]');
        if (actionsHeader) {
            actionsHeader.remove();
        }

        // Remove all action cells
        const actionCells = document.querySelectorAll('td[data-field="actions"]');
        actionCells.forEach(cell => cell.remove());
    }

    function addSuppressButtons() {
        // Only add buttons if we're on the grouped vulnerabilities tab
        if (!isOnGroupedVulnerabilitiesTab()) {
            // Remove buttons if they exist and we're not on the right tab
            removeExistingButtons();
            lastTableHTML = '';
            return;
        }

        const table = document.querySelector('.fixed-table-body table');
        if (!table) return;

        const currentHTML = table.innerHTML;
        if (currentHTML === lastTableHTML) return;
        lastTableHTML = currentHTML;

        const thead = table.querySelector('thead tr');
        const tbody = table.querySelector('tbody');

        if (!thead || !tbody) return;

        if (!thead.querySelector('th[data-field="actions"]')) {
            const th = document.createElement('th');
            th.setAttribute('data-field', 'actions');
            th.innerHTML = '<div class="th-inner">Actions</div><div class="fht-cell"></div>';
            thead.appendChild(th);
        }

        const rows = tbody.querySelectorAll('tr');
        rows.forEach(row => {
            if (row.querySelector('td[data-field="actions"]')) return;

            const vulnCell = row.querySelector('td:first-child');
            if (!vulnCell) return;

            const vulnLink = vulnCell.querySelector('a');
            if (!vulnLink) return;

            const vulnHref = vulnLink.getAttribute('href');
            const vulnMatch = vulnHref.match(/\/vulnerabilities\/([^\/]+)\/([^\/]+)/);
            if (!vulnMatch) return;

            const vulnSource = vulnMatch[1];
            const vulnId = decodeURIComponent(vulnMatch[2]);

            const td = document.createElement('td');
            td.setAttribute('data-field', 'actions');
            
            const button = document.createElement('button');
            button.className = 'btn btn-sm btn-warning';
            button.innerHTML = '<i class="fa fa-ban"></i> Suppress All';
            button.title = `Suppress ${vulnId} in all projects`;
            button.style.whiteSpace = 'nowrap';
            
            button.addEventListener('click', (e) => {
                e.preventDefault();
                handleBulkSuppress(button, vulnId, vulnSource);
            });

            td.appendChild(button);
            row.appendChild(td);
        });
    }

    // Monitor for tab clicks
    function monitorTabClicks() {
        const tabContainer = document.querySelector('.nav-tabs');
        if (!tabContainer) return;

        tabContainer.addEventListener('click', (e) => {
            // When a tab is clicked, reset and check after delays to ensure DOM is updated
            lastTableHTML = '';
            setTimeout(addSuppressButtons, 100);
            setTimeout(addSuppressButtons, 300);
            setTimeout(addSuppressButtons, 500);
            setTimeout(addSuppressButtons, 1000);
        });
    }

    // Use MutationObserver to detect when tab content changes
    function observeTabChanges() {
        const tabContent = document.querySelector('.tab-content');
        if (!tabContent) return;

        const observer = new MutationObserver(() => {
            lastTableHTML = '';
            addSuppressButtons();
        });

        observer.observe(tabContent, {
            attributes: true,
            attributeFilter: ['class'],
            subtree: true,
            childList: true
        });
    }

    function init() {
        console.log('Dependency-Track Bulk Suppress Script initialized');
        
        // Initial check with multiple retries
        setTimeout(addSuppressButtons, 500);
        setTimeout(addSuppressButtons, 1000);
        setTimeout(addSuppressButtons, 2000);
        
        // Setup monitors
        setTimeout(() => {
            monitorTabClicks();
            observeTabChanges();
        }, 1000);
        
        // Periodic check
        setInterval(addSuppressButtons, CHECK_INTERVAL);
        
        // Monitor for URL/hash changes
        let currentUrl = window.location.href;
        setInterval(() => {
            if (window.location.href !== currentUrl) {
                currentUrl = window.location.href;
                lastTableHTML = '';
                setTimeout(addSuppressButtons, 100);
                setTimeout(addSuppressButtons, 300);
                setTimeout(addSuppressButtons, 500);
            }
        }, 500);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();