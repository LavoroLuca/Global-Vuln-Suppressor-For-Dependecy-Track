# Global Vuln Suppressor for Dependency-Track

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Kubernetes](https://img.shields.io/badge/kubernetes-1.24%2B-326CE5?logo=kubernetes)](https://kubernetes.io/)
[![Dependency-Track](https://img.shields.io/badge/dependency--track-4.13.6-blue)](https://dependencytrack.org/)
[![Tested](https://img.shields.io/badge/tested-DT%204.13.6-success)](https://github.com/DependencyTrack/dependency-track/releases/tag/4.13.6)

A Kubernetes-native solution that adds **bulk vulnerability suppression** functionality to Dependency-Track's Grouped Vulnerabilities view. Suppress vulnerabilities across multiple projects with granular control over analysis states - all through an intuitive UI.

![Demo](https://img.shields.io/badge/status-production%20ready-brightgreen)

> ⚠️ **Tested with Dependency-Track 4.13.6 only** - Compatibility with other versions is not guaranteed.

## 🎯 What Does It Do?

This solution enhances Dependency-Track by adding a **"Suppress All"** button in the Grouped Vulnerabilities audit view. When clicked, it:

1. **Shows a modal** with all projects affected by the vulnerability
2. **Lets you select** which projects to suppress (with "Select All" option)
3. **Configure analysis states** individually per project or globally:
   - False Positive
   - Not Set
   - Exploitable
   - In Triage
   - Resolved
   - Not Affected
4. **Bulk suppresses** the vulnerability across selected projects
5. **Provides feedback** via toast notifications

### Why This Matters

In large organizations with hundreds of projects, manually suppressing the same vulnerability across multiple projects is:
- ⏰ **Time-consuming** - Each suppression requires multiple clicks
- 🐛 **Error-prone** - Easy to miss projects or use inconsistent states
- 📊 **Hard to track** - No visibility into bulk operations

This tool solves all these problems with a single, intuitive interface.

### Works Out-of-the-Box with Helm Chart

✨ **Easy Configuration!** This Kustomize deployment works with the standard [Dependency-Track Helm chart](https://github.com/DependencyTrack/helm-charts) installation. Just update the namespace in two files and deploy!

The Helm chart uses a predictable naming pattern: `{namespace}-dependency-track-{component}`

## ✨ Key Features

- ✅ **Project Selection** - Choose which projects to suppress with checkboxes
- ✅ **Granular Analysis States** - Set different states for different projects
- ✅ **Global or Individual** - Apply one state to all, or customize per-project
- ✅ **Real-time Feedback** - Toast notifications show progress and results
- ✅ **Non-invasive** - Works alongside existing Dependency-Track installation
- ✅ **No Backend Changes** - Pure frontend injection via NGINX proxy
- ✅ **JWT Authentication** - Uses existing user session (no additional auth)
- ✅ **Kustomize Ready** - Easy deployment and customization

## 📸 Screenshots

### Before: Standard Grouped Vulnerabilities View
```
┌─────────────────┬──────────┬──────────┬──────────┐
│ Vulnerability   │ Severity │ Projects │ ...      │
├─────────────────┼──────────┼──────────┼──────────┤
│ CVE-2024-12345  │ High     │ 15       │ ...      │
│ CVE-2024-67890  │ Critical │ 8        │ ...      │
└─────────────────┴──────────┴──────────┴──────────┘
```

### After: With Bulk Suppression
```
┌─────────────────┬──────────┬──────────┬──────────────────────┐
│ Vulnerability   │ Severity │ Projects │ Actions              │
├─────────────────┼──────────┼──────────┼──────────────────────┤
│ CVE-2024-12345  │ High     │ 15       │ [Suppress All] 🆕   │
│ CVE-2024-67890  │ Critical │ 8        │ [Suppress All] 🆕   │
└─────────────────┴──────────┴──────────┴──────────────────────┘
```

### Modal: Project Selection with Analysis States
```
┌────────────────────────────────────────────────────────────┐
│  Select Projects to Suppress CVE-2024-12345                │
├────────────────────────────────────────────────────────────┤
│  ☑ Select All (15 projects)    │ State: [False Positive ▼]│
├───┬──────────────────┬─────────┬────────┬─────────────────┤
│ ☑ │ Project Name     │ Version │ Active │ Analysis State  │
├───┼──────────────────┼─────────┼────────┼─────────────────┤
│ ☑ │ frontend-app     │ 2.1.0   │ Yes    │ [False Pos. ▼] │
│ ☑ │ backend-api      │ 3.0.5   │ Yes    │ [Not Affected▼]│
│ ☐ │ legacy-service   │ 1.5.2   │ No     │ [In Triage ▼]  │
└───┴──────────────────┴─────────┴────────┴─────────────────┘
       15 of 15 selected          [Cancel] [Suppress Selected]
```

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────────┐
│   Browser   │─────▶│  NGINX Proxy     │─────▶│  DT Frontend    │
│             │      │  (Injection)     │      │  (Original)     │
└─────────────┘      └──────────────────┘      └─────────────────┘
                              │                          │
                              │ injects                  │
                              ▼                          ▼
                     bulk-suppress.js            Dependency-Track
                     (JavaScript)                Backend API
                                                 (REST API)
```

### How It Works

1. **NGINX Proxy** intercepts HTTP responses from Dependency-Track frontend
2. **JavaScript Injection** - Injects `bulk-suppress.js` before `</body>` tag
3. **DOM Manipulation** - Script adds "Actions" column with buttons
4. **API Calls** - Uses Dependency-Track's REST API with user's JWT token
5. **Bulk Operations** - Processes multiple projects sequentially

## 🚀 Quick Start

### Prerequisites

- Kubernetes cluster (1.24+)
- **Dependency-Track 4.13.6** installed via official Helm chart ([dependencytrack/dependency-track](https://github.com/DependencyTrack/helm-charts))
- `kubectl` configured
- `kustomize` (optional, kubectl has it built-in)

> **💡 Note**: This Kustomize deployment is designed for the official Dependency-Track Helm chart. The Helm chart uses a naming pattern: `{namespace}-dependency-track-{component}`. You'll need to adjust the namespace and service name to match your installation.

> ⚠️ **Compatibility**: This solution has been tested **only with Dependency-Track 4.13.6**. Compatibility with other versions is not guaranteed. If you're using a different version, thorough testing is recommended before production use.

### Step 1: Clone the Repository

```bash
git clone https://github.com/LavoroLuca/Global-Vuln-Suppressor-For-Dependecy-Track.git
cd Global-Vuln-Suppressor-For-Dependecy-Track/Kubernetes-kustomize/overlay/standalone
```

> ⚠️ **Important**: All `kubectl apply -k` commands must be run from the `overlay/standalone/` directory!

### Step 2: Configure Your Namespace and Service

The Helm chart uses a naming pattern based on the namespace: `{namespace}-dependency-track-{component}`

**Edit `overlay/standalone/kustomization.yaml`:**
```yaml
namespace: dtrack  # Change to your actual namespace (e.g., dtrack, production, etc.)
```

**Edit `base/Nginx/default.conf`:**
```nginx
# Line 6: Update both occurrences of 'dtrack' to match your namespace
set $backend "dtrack-dependency-track-frontend.dtrack.svc.cluster.local:8080";
#              ^^^^^                         ^^^^^
#              namespace prefix              namespace
```

**Examples:**

For namespace `production`:
```nginx
set $backend "production-dependency-track-frontend.production.svc.cluster.local:8080";
```

For namespace `dtrack` (default example):
```nginx
set $backend "dtrack-dependency-track-frontend.dtrack.svc.cluster.local:8080";
```

**Find your service name:**
```bash
kubectl get svc -n <your-namespace> | grep frontend
# Output example: dtrack-dependency-track-frontend
```

### Step 3: Deploy with Kustomize

```bash
# Make sure you're in the overlay/standalone directory
pwd
# Should output: .../Kubernetes-kustomize/overlay/standalone

# Deploy
kubectl apply -k .

# Verify deployment
kubectl get pods -n dtrack -l app=dt-frontend-proxy
kubectl logs -n dtrack -l app=dt-frontend-proxy

# Expected output:
# dt-frontend-proxy-xxxxx-xxxxx   1/1     Running   0          30s
```

> 💡 **Tip**: The `-k` flag tells kubectl to use Kustomize. The `.` means "current directory" (overlay/standalone).

### Step 4: Update Your Ingress

You need to route traffic through the new proxy instead of directly to the frontend.

**For Default Helm Chart Installation:**

The default Helm chart creates an Ingress named `{namespace}-dependency-track`. Update it to use the proxy:

```bash
# For namespace 'dtrack' (adjust to your namespace)
kubectl patch ingress dtrack-dependency-track -n dtrack --type='json' -p='[
  {
    "op": "replace",
    "path": "/spec/rules/0/http/paths/0/backend/service/name",
    "value": "dt-frontend-proxy"
  }
]'

# Verify the change
kubectl get ingress dtrack-dependency-track -n dtrack -o yaml | grep -A5 backend
```

**For Different Namespace:**

```bash
# Example for namespace 'production'
kubectl patch ingress production-dependency-track -n production --type='json' -p='[
  {
    "op": "replace",
    "path": "/spec/rules/0/http/paths/0/backend/service/name",
    "value": "dt-frontend-proxy"
  }
]'
```

**Find Your Ingress:**

```bash
# List all ingresses in your namespace
kubectl get ingress -n dtrack

# Expected output: dtrack-dependency-track
```

**Alternative: Kustomize Patch Method**

Create `ingress-patch.yaml` in the `overlay/standalone/` directory:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: dtrack-dependency-track  # Change 'dtrack' to your namespace
  namespace: dtrack               # Your namespace
spec:
  rules:
  - http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: dt-frontend-proxy  # Route to proxy instead
            port:
              number: 8080
```

Add to `overlay/standalone/kustomization.yaml`:

```yaml
patchesStrategicMerge:
  - ingress-patch.yaml
```

Then reapply from the `overlay/standalone/` directory:

```bash
kubectl apply -k .
```

### Step 5: Test It Out! 🎉

1. Open Dependency-Track in your browser
2. Navigate to: **Vulnerability Audit → Grouped Vulnerabilities**
3. You should see a new **"Actions"** column with **"Suppress All"** buttons
4. Click a button to test the bulk suppression feature!

## 📁 Repository Structure

```
Global-Vuln-Suppressor-For-Dependecy-Track/
├── README.md                                    # This file
├── LICENSE                                      # Apache 2.0 License
└── Kubernetes-kustomize/
    ├── base/                                    # Base Kustomize resources
    │   ├── Injection/
    │   │   ├── bulk-suppress.js                # Main JavaScript injection script
    │   │   └── kustomization.yaml              # ConfigMap for script
    │   └── Nginx/
    │       ├── default.conf                    # NGINX configuration
    │       ├── deployment.yaml                 # NGINX proxy deployment
    │       ├── kustomization.yaml              # Nginx base resources
    │       └── service.yaml                    # Service for the proxy
    └── overlay/
        └── standalone/
            └── kustomization.yaml              # Overlay configuration (namespace, etc.)
```

### Key Files

- **`base/Injection/bulk-suppress.js`** - Core JavaScript that adds bulk suppression UI
- **`base/Nginx/default.conf`** - NGINX proxy configuration (modify backend here)
- **`base/Nginx/deployment.yaml`** - Kubernetes deployment for proxy
- **`overlay/standalone/kustomization.yaml`** - Main configuration file (set namespace here)

## 🔧 Configuration

### Default Configuration (Helm Chart)

The Kustomize deployment comes pre-configured for the official Dependency-Track Helm chart with these defaults:

```yaml
# Default namespace: dtrack
# Service: dtrack-dependency-track-frontend
# Ingress: dtrack-dependency-track
# Port: 8080
```

**Pattern**: The Helm chart uses `{namespace}-dependency-track` naming convention.

**You need to update two things:**
1. Change the namespace in `kustomization.yaml`
2. Update the service name in `configs/nginx.conf` to match your namespace

### Quick Configuration

Edit `kustomization.yaml`:
```yaml
namespace: dtrack  # Your Dependency-Track namespace
```

Edit `configs/nginx.conf`:
```nginx
# Replace 'dtrack' with your actual namespace
set $backend "dtrack-dependency-track-frontend.dtrack.svc.cluster.local:8080";
```

**Example for namespace 'production':**
```nginx
set $backend "production-dependency-track-frontend.production.svc.cluster.local:8080";
```

### For Custom Helm Installations

If you installed with a custom release name or values:

```bash
# Example: helm install my-custom-release dependencytrack/dependency-track
# The naming pattern might differ

# Find your actual service names:
kubectl get svc -n your-namespace

# Update configs/nginx.conf accordingly
set $backend "your-actual-frontend-service.your-namespace.svc.cluster.local:8080";
```

**Standard Helm Chart Pattern:**
- Service: `{namespace}-dependency-track-frontend`
- Ingress: `{namespace}-dependency-track`

**Custom Release Pattern (if release name is used):**
- Service: `{release-name}-frontend`
- Ingress: `{release-name}`

### Environment Variables

The script automatically detects configuration from the browser environment:

- `API_BASE_URL` - Automatically set to current origin
- JWT token - Retrieved from `sessionStorage.getItem('token')`

### Customizing NGINX

Edit `base/Nginx/default.conf`:

```nginx
# Change backend service
set $backend "your-service.your-ns.svc.cluster.local:8080";

# Adjust timeouts if needed
proxy_connect_timeout 60s;
proxy_send_timeout 60s;
proxy_read_timeout 60s;

# Customize injection point
sub_filter '</body>' '<script src="/custom/bulk-suppress.js"></script></body>';
```

Apply from `overlay/standalone/`:
```bash
kubectl apply -k .
kubectl rollout restart deployment/dt-frontend-proxy -n dtrack
```

### Customizing the Script

Edit `base/Injection/bulk-suppress.js`:

```javascript
// Change default analysis state
const DEFAULT_STATE = 'NOT_AFFECTED';  // Instead of 'FALSE_POSITIVE'

// Add custom states
const ANALYSIS_STATES = [
    { value: 'MY_CUSTOM_STATE', label: 'My Custom', class: 'info' },
    // ... other states
];

// Customize polling interval
const CHECK_INTERVAL = 2000;  // Check every 2 seconds instead of 1
```

Apply from `overlay/standalone/`:
```bash
kubectl apply -k .
kubectl rollout restart deployment/dt-frontend-proxy -n dtrack
```

### Resource Limits

Edit `base/Nginx/deployment.yaml`:

```yaml
resources:
  requests:
    memory: "128Mi"  # Increase if needed
    cpu: "200m"
  limits:
    memory: "256Mi"
    cpu: "500m"
```

## 🔍 Troubleshooting

### Proxy Pod Not Starting

```bash
# Check pod status
kubectl get pods -n dtrack -l app=dt-frontend-proxy

# Check logs
kubectl logs -n dtrack -l app=dt-frontend-proxy

# Common issues:
# 1. Namespace mismatch - verify namespace in kustomization.yaml
# 2. Service name pattern incorrect - must be: {namespace}-dependency-track-frontend
# 3. ConfigMap not mounted properly - check ConfigMaps exist
```

**For default Helm chart installation**, verify the service naming pattern:
- Namespace: `dtrack` → Service: `dtrack-dependency-track-frontend`
- Namespace: `production` → Service: `production-dependency-track-frontend`

### Buttons Not Appearing

1. **Clear browser cache** and do a hard refresh (Ctrl+F5)
2. **Check browser console** (F12) for JavaScript errors
3. **Verify script injection**:
   ```bash
   # View page source and search for "bulk-suppress.js"
   # Should see: <script src="/custom/bulk-suppress.js"></script>
   ```
4. **Check script is accessible**:
   ```bash
   curl http://your-domain/custom/bulk-suppress.js
   # Should return the JavaScript code
   ```

### 401 Unauthorized Errors

The script uses JWT authentication. If you see 401 errors:

1. **Verify you're logged in** to Dependency-Track
2. **Check token in browser console**:
   ```javascript
   console.log(sessionStorage.getItem('token'));
   // Should show a long JWT token
   ```
3. **Try logout and login again**

### Ingress Not Routing to Proxy

```bash
# Verify ingress configuration (adjust namespace as needed)
kubectl describe ingress dtrack-dependency-track -n dtrack

# Should show:
#   Backend: dt-frontend-proxy:8080

# Test proxy health
kubectl port-forward -n dtrack svc/dt-frontend-proxy 8080:8080
curl http://localhost:8080/health
# Should return: healthy
```

### Service Name Issues

If you're getting "host not found" errors in NGINX logs:

```bash
# 1. Find your actual frontend service name
kubectl get svc -n dtrack | grep frontend
# Expected: dtrack-dependency-track-frontend

# 2. Verify the pattern matches: {namespace}-dependency-track-frontend
# For namespace 'dtrack': dtrack-dependency-track-frontend
# For namespace 'production': production-dependency-track-frontend

# 3. Update configs/nginx.conf if needed
# set $backend "{namespace}-dependency-track-frontend.{namespace}.svc.cluster.local:8080";

# 4. Reapply from overlay/standalone directory
cd Kubernetes-kustomize/overlay/standalone/
kubectl apply -k .
kubectl rollout restart deployment/dt-frontend-proxy -n dtrack
```

## 🛠️ Development

### Local Testing

```bash
# Port-forward the proxy
kubectl port-forward -n dtrack svc/dt-frontend-proxy 8080:8080

# Access in browser
# http://localhost:8080
```

### Modifying the Script

```bash
# Navigate to the script location
cd Kubernetes-kustomize/base/Injection/

# Edit the script
vim bulk-suppress.js

# Go to overlay directory to apply changes
cd ../../overlay/standalone/

# Apply changes (Kustomize will regenerate the ConfigMap)
kubectl apply -k .

# Restart proxy to reload
kubectl rollout restart deployment/dt-frontend-proxy -n dtrack
```

### Modifying NGINX Configuration

```bash
# Navigate to NGINX config
cd Kubernetes-kustomize/base/Nginx/

# Edit the config
vim default.conf

# Go to overlay directory to apply
cd ../../overlay/standalone/

# Apply and restart
kubectl apply -k .
kubectl rollout restart deployment/dt-frontend-proxy -n dtrack
```

### Testing API Calls

Open browser console on Dependency-Track page:

```javascript
// Test authentication
const token = sessionStorage.getItem('token');
console.log('Token:', token);

// Test API call
fetch('/api/v1/vulnerability/source/NVD/vuln/CVE-2024-12345', {
    headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
    }
})
.then(r => r.json())
.then(d => console.log(d));
```

## 📊 Performance Considerations

- **API Rate Limiting**: Requests are sequential to avoid overwhelming the server
- **Large Project Counts**: For 50+ projects, suppression may take 2-5 minutes
- **Browser Performance**: Minimal impact, script runs on-demand only
- **Network Traffic**: ~1KB JavaScript file loaded once, then cached

### Scaling Recommendations

For very large Dependency-Track installations:

1. **Increase NGINX resources** in `deployment.yaml`
2. **Add rate limiting** to the script (customize `bulk-suppress.js`)
3. **Monitor API server** for increased load during bulk operations
4. **Consider backend solution** if you regularly suppress 100+ projects

## 🔐 Security

- ✅ Uses existing JWT authentication (no new credentials)
- ✅ Respects user RBAC permissions
- ✅ All operations logged in Dependency-Track audit trail
- ✅ No data stored by proxy (stateless)
- ✅ JavaScript is open source (inspect in `scripts/bulk-suppress.js`)
- ✅ NGINX runs with minimal privileges

### Security Best Practices

1. **Review the script** before deploying to production
2. **Test in staging** environment first
3. **Monitor audit logs** for unexpected bulk suppressions
4. **Restrict proxy access** to internal networks only
5. **Keep NGINX updated** (use latest stable tag)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Dependency-Track](https://dependencytrack.org/) - The amazing OWASP project this extends
- [NGINX](https://nginx.org/) - For the reliable proxy
- [Kubernetes](https://kubernetes.io/) - For the orchestration platform
- [Bootstrap](https://getbootstrap.com/) - For the UI components (used by DT)

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/LavoroLuca/Global-Vuln-Suppressor-For-Dependecy-Track/issues)
- **Discussions**: Use GitHub Discussions for questions
- **Email**: Create an issue for private inquiries

## 🗺️ Roadmap

- [x] Basic bulk suppression
- [x] Project selection modal
- [x] Granular analysis states
- [x] Kustomize deployment
- [ ] Helm chart support with kustomize installation

## ⚠️ Disclaimer

This is a community project and is not officially affiliated with or endorsed by the OWASP Dependency-Track project. 

**Testing and Compatibility:**
- ✅ Tested with Dependency-Track 4.13.6
- ⚠️ Other versions are not tested and may not work
- 🧪 Always test in a non-production environment first
- 📊 Monitor for any unexpected behavior

Use at your own risk.

---

**Made with ❤️ for the security community**

If this project helped you, consider giving it a ⭐ on GitHub!

**Author comment**
This is an ai generated documentation, please refer to me to any issue