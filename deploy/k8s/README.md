# Watchu Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the Watchu observability system.

## Components

- **Namespace**: Isolated `watchu` namespace
- **PostgreSQL**: Database storage (Deployment + PVC + Service)
- **Gateway**: API gateway service (Deployment + Service)
- **Frontend**: Web UI (Deployment + Service)
- **Tetragon**: eBPF-based security monitoring (DaemonSet)
- **Collector**: Data collector agent (DaemonSet)

## Prerequisites

1. Kubernetes cluster (v1.20+)
2. kubectl CLI tool
3. Container images built and available:
   - `watchu-gateway:latest`
   - `watchu-frontend:latest`
   - `watchu-collector:latest`
4. StorageClass for PostgreSQL PVC

## Quick Deployment

### One-Command Deploy

```bash
kubectl apply -f namespace.yaml && \
kubectl apply -f postgres.yaml && \
kubectl wait --for=condition=ready pod -l app=postgres -n watchu --timeout=300s && \
kubectl apply -f gateway.yaml && \
kubectl apply -f frontend.yaml && \
kubectl apply -f tetragon.yaml && \
kubectl apply -f collector.yaml
```

### Step-by-Step Deploy

#### 1. Create Namespace

```bash
kubectl apply -f namespace.yaml
```

#### 2. Deploy PostgreSQL

```bash
kubectl apply -f postgres.yaml
```

Wait for PostgreSQL to be ready:
```bash
kubectl wait --for=condition=ready pod -l app=postgres -n watchu --timeout=300s
```

#### 3. Deploy Gateway

For production, create a Secret for sensitive configuration:

```bash
kubectl create secret generic gateway-secrets \
  --from-literal=api-base='YOUR_API_BASE' \
  --from-literal=api-key='YOUR_API_KEY' \
  --from-literal=model='YOUR_MODEL' \
  --from-literal=mode='YOUR_MODE' \
  -n watchu
```

Deploy Gateway:
```bash
kubectl apply -f gateway.yaml
```

#### 4. Deploy Frontend

```bash
kubectl apply -f frontend.yaml
```

#### 5. Deploy Tetragon DaemonSet

```bash
kubectl apply -f tetragon.yaml
```

Verify Tetragon is running on all nodes:
```bash
kubectl get ds tetragon -n watchu
```

#### 6. Deploy Collector DaemonSet

```bash
kubectl apply -f collector.yaml
```

Verify Collector is running on all nodes:
```bash
kubectl get ds collector -n watchu
```

## Accessing Services

### Port Forward

#### Frontend (Web UI)
```bash
kubectl port-forward -n watchu svc/frontend 5173:5173
```
Access: http://localhost:5173

#### Gateway (API)
```bash
kubectl port-forward -n watchu svc/gateway 8080:8080
```
Access: http://localhost:8080

### Ingress (Optional)

Create an Ingress resource (requires Ingress Controller):

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: watchu-ingress
  namespace: watchu
spec:
  ingressClassName: nginx
  rules:
  - host: watchu.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: gateway
            port:
              number: 8080
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 5173
```

## Monitoring and Debugging

### Check Pod Status

```bash
kubectl get pods -n watchu
```

### View Logs

```bash
# Gateway logs
kubectl logs -n watchu -l app=gateway -f

# Frontend logs
kubectl logs -n watchu -l app=frontend -f

# Collector logs
kubectl logs -n watchu -l app=collector -f

# Tetragon logs
kubectl logs -n watchu -l app=tetragon -f
```

### Check DaemonSet Status

```bash
kubectl get ds -n watchu
```

### Exec into Pod

```bash
kubectl exec -it -n watchu <pod-name> -- /bin/sh
```

### Check Events

```bash
kubectl get events -n watchu --sort-by='.lastTimestamp'
```

## Configuration Details

### PostgreSQL
- Storage: 10Gi PVC (adjust in postgres.yaml)
- Default credentials: watchu/watchu
- **Production**: Use Secret for credentials

### Gateway
- Environment variables via ConfigMap
- Sensitive data (API keys) should use Secret
- Health check endpoint: `/health`
- Database connection: postgres://watchu:watchu@postgres:5432/watchu

### Frontend
- API base URL configured via environment variable
- Points to internal Gateway service by default
- Port: 5173

### Tetragon (DaemonSet)
- Runs on every node
- Privileged mode required
- Mounts:
  - `/sys/kernel/btf/vmlinux` - BTF (BPF Type Format) data
  - `/var/run/tetragon` - Unix socket directory
- Uses `hostPID: true` and `hostNetwork: true`

### Collector (DaemonSet)
- Runs on every node
- Privileged mode required
- Mounts:
  - `/proc` → `/host/proc` - Process information
  - `/sys/fs/cgroup` → `/host/sys/fs/cgroup` - Container PIDs
  - `/var/run/tetragon` - Tetragon socket
- RBAC: ServiceAccount + ClusterRole for K8s API access
- Uses `hostPID: true` and `hostNetwork: true`

## Container Discovery

The Collector uses the following approach to discover containers:

1. List PIDs for each container:
   ```bash
   cat /sys/fs/cgroup/<controller>/<runtime>-<container-id>.scope/cgroup.procs
   ```

2. Get executable path:
   ```bash
   readlink -v /proc/<pid>/exe
   ```

3. Locate binary on host:
   ```bash
   /proc/<pid>/root/<path>
   ```

## Uninstall

### Remove All Components

```bash
kubectl delete -f collector.yaml
kubectl delete -f tetragon.yaml
kubectl delete -f frontend.yaml
kubectl delete -f gateway.yaml
kubectl delete -f postgres.yaml
kubectl delete -f namespace.yaml
```

### Or Delete Entire Namespace

```bash
kubectl delete namespace watchu
```

**Note**: This will delete all data including PostgreSQL volumes.

## Important Notes

1. **Images**: Ensure all container images are built and accessible to your cluster
2. **StorageClass**: PostgreSQL requires an available StorageClass
3. **Privileged Containers**: Tetragon and Collector require privileged mode
4. **Node Compatibility**: Ensure nodes support BTF (BPF Type Format)
5. **Resource Limits**: Adjust resource requests/limits based on your workload
6. **Security**: Use Secrets for sensitive information in production
7. **Network Policy**: Consider implementing NetworkPolicy for production

## Troubleshooting

### Tetragon Pod Fails to Start

Check if BTF is available:
```bash
ls -l /sys/kernel/btf/vmlinux
```

If not available, ensure your kernel is compiled with BTF support (CONFIG_DEBUG_INFO_BTF=y).

### Collector Cannot Access Tetragon Socket

Check Tetragon is running first:
```bash
kubectl get pods -n watchu -l app=tetragon
```

Verify socket exists on nodes:
```bash
kubectl exec -n watchu <tetragon-pod> -- ls -l /var/run/tetragon/
```

### PostgreSQL Pod Pending

Check PVC status:
```bash
kubectl get pvc -n watchu
```

Ensure a StorageClass is available:
```bash
kubectl get storageclass
```

### Gateway Cannot Connect to Database

Check PostgreSQL service:
```bash
kubectl get svc postgres -n watchu
```

Check Gateway logs:
```bash
kubectl logs -n watchu -l app=gateway
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Namespace: watchu                    │  │
│  │                                                   │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │  │
│  │  │ Frontend │──│ Gateway  │──│  PostgreSQL  │  │  │
│  │  │  (Web)   │  │  (API)   │  │     (DB)     │  │  │
│  │  └──────────┘  └──────────┘  └──────────────┘  │  │
│  │                      │                           │  │
│  │                      │ receives events           │  │
│  │                      │                           │  │
│  │  ┌─────────────────┴──────────────────────┐    │  │
│  │  │         Collector (DaemonSet)          │    │  │
│  │  │  - Collects container metadata         │    │  │
│  │  │  - Reads Tetragon events              │    │  │
│  │  │  - Sends to Gateway                    │    │  │
│  │  └────────────────┬───────────────────────┘    │  │
│  │                   │ reads events                │  │
│  │  ┌────────────────┴───────────────────────┐    │  │
│  │  │         Tetragon (DaemonSet)           │    │  │
│  │  │  - eBPF-based security monitoring      │    │  │
│  │  │  - Process/network event collection    │    │  │
│  │  └────────────────────────────────────────┘    │  │
│  │                                                 │  │
│  └─────────────────────────────────────────────────┘  │
│                                                        │
└────────────────────────────────────────────────────────┘
```

## Support

For issues and questions, please refer to the main Watchu documentation or open an issue in the repository.
