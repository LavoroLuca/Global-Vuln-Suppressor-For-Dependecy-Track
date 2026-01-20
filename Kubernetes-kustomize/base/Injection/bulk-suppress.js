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

    async function getAffectedProjects(vulnId, vulnSource) {
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

    async function suppressVulnerability(projectUuid, componentUuid, vulnerabilityUuid, analysisState, isSuppressed) {
        const apiKey = getApiKey();
        if (!apiKey) {
            throw new Error('No API key available');
        }

        try {
            const response = await fetch(
                `${API_BASE_URL}/api/v1/analysis`,
                {
                    method: 'PUT',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({
                        project: projectUuid,
                        component: componentUuid,
                        vulnerability: vulnerabilityUuid,
                        analysisState: analysisState || 'FALSE_POSITIVE',
                        suppressed: isSuppressed,
                        comment: `Bulk ${isSuppressed ? 'suppression' : 'unsuppression'} via custom script - State: ${analysisState || 'FALSE_POSITIVE'}`
                    })
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

    function showProjectSelectionModal(projects, vulnId, vulnDetails, callback) {
        // Create modal backdrop
        const backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop fade show';
        backdrop.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); z-index: 1040;';

        // Create modal
        const modal = document.createElement('div');
        modal.className = 'modal fade show';
        modal.style.cssText = 'display: block; z-index: 1050; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); max-width: 800px; width: 90%;';
        modal.innerHTML = `
            <div class="modal-dialog modal-lg" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fa fa-shield"></i> Select Projects to Suppress ${vulnId}
                        </h5>
                    </div>
                    <div class="modal-body" style="max-height: 60vh; overflow-y: auto;">
                        <div class="mb-3">
                            <div class="row">
                                <div class="col-md-6">
                                    <label class="custom-control custom-checkbox">
                                        <input type="checkbox" id="select-all-projects" class="custom-control-input">
                                        <span class="custom-control-label"><strong>Select All (${projects.length} projects)</strong></span>
                                    </label>
                                </div>
                                <div class="col-md-6">
                                    <div class="form-group mb-0">
                                        <label for="global-analysis-state" class="mb-1"><strong>Set Analysis State for All:</strong></label>
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
                            </div>
                        </div>
                        <hr>
                        <div class="table-responsive">
                            <table class="table table-sm table-hover">
                                <thead>
                                    <tr>
                                        <th style="width: 50px;"></th>
                                        <th>Project Name</th>
                                        <th>Version</th>
                                        <th>Active</th>
                                        <th style="width: 180px;">Analysis State</th>
                                    </tr>
                                </thead>
                                <tbody id="projects-list">
                                    ${projects.map((project, index) => `
                                        <tr>
                                            <td>
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
                                            <td>${project.name || 'Unknown'}</td>
                                            <td>${project.version || '-'}</td>
                                            <td>${project.active ? '<span class="badge badge-success">Yes</span>' : '<span class="badge badge-secondary">No</span>'}</td>
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
                            <i class="fa fa-ban"></i> Suppress Selected
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Add to DOM
        document.body.appendChild(backdrop);
        document.body.appendChild(modal);

        // Global analysis state selector
        const globalStateSelect = modal.querySelector('#global-analysis-state');
        globalStateSelect.addEventListener('change', function() {
            if (this.value) {
                modal.querySelectorAll('.analysis-state-select').forEach(select => {
                    select.value = this.value;
                });
            }
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
                    const stateSelect = modal.querySelector(`.analysis-state-select[data-project-index="${index}"]`);
                    return {
                        uuid: cb.dataset.projectUuid,
                        name: cb.dataset.projectName,
                        analysisState: stateSelect ? stateSelect.value : 'FALSE_POSITIVE'
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
                    const projectResponse = await fetch(
                        `${API_BASE_URL}/api/v1/finding/project/${project.uuid}`,
                        {
                            method: 'GET',
                            headers: getAuthHeaders()
                        }
                    );

                    if (!projectResponse.ok) continue;

                    const findings = await projectResponse.json();
                    const relevantFindings = findings.filter(
                        f => f.vulnerability && f.vulnerability.uuid === vulnDetails.uuid
                    );

                    for (const finding of relevantFindings) {
                        if (finding.component && finding.component.uuid) {
                            // Always set suppressed to true
                            await suppressVulnerability(
                                project.uuid,
                                finding.component.uuid,
                                vulnDetails.uuid,
                                project.analysisState,
                                true  // Always suppress
                            );
                            successCount++;
                        }
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