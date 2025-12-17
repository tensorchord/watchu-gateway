# Watchu Kubernetes Deployment

Quick guide to deploy Watchu on Kubernetes.

## Quick Start

Deploy all components with one command:

```bash
kubectl apply -f namespace.yaml && \
kubectl apply -f postgres.yaml && \
kubectl wait --for=condition=ready pod -l app=postgres -n watchu --timeout=300s && \
kubectl apply -f gateway.yaml && \
kubectl apply -f frontend.yaml && \
kubectl apply -f collector.yaml
```

## Access the UI

```bash
kubectl port-forward -n watchu svc/frontend 8080:80
```

Open http://localhost:8080

## Components

- **PostgreSQL 18**: Database (10Gi storage required)
  - Uses `/var/lib/postgresql` mount point (PG 18+ standard)
  - Data stored in `/var/lib/postgresql/18/data` subdirectory
- **Gateway**: API server on port 8080
- **Frontend**: Web UI on port 80 (nginx)
- **Collector**: Event collector (DaemonSet), includes Tetragon sidecar (unix socket)

All images use version tag `v0.1.0` from `ghcr.io/tensorchord/watchu-*`. Update the version in YAML files as needed.

## PostgreSQL 18+ Important Notes

PostgreSQL 18 introduces a new data directory structure:
- Mount point: `/var/lib/postgresql` (not `/var/lib/postgresql/data`)
- Actual data: `/var/lib/postgresql/18/data`
- This design supports `pg_upgrade --link` for seamless upgrades

**Upgrading from older PostgreSQL versions:**
```bash
# Backup your data first!
kubectl exec -n watchu deployment/postgres -- pg_dumpall -U watchu > backup.sql

# Delete old deployment and PVC
kubectl delete deployment postgres -n watchu
kubectl delete pvc postgres-pvc -n watchu

# Redeploy with new configuration
kubectl apply -f postgres.yaml

# Restore data
cat backup.sql | kubectl exec -i -n watchu deployment/postgres -- psql -U watchu
```

## Configuration

Edit `gateway.yaml` ConfigMap to set your LLM API endpoints and keys:

```yaml
data:
  PROMPT_INJECTION_API_BASE: "http://your-api-endpoint"
  PROMPT_INJECTION_API_KEY: "your-api-key"
  PROMPT_INJECTION_MODEL: "gpt-4o"
  THREAT_INSIGHT_BASE_URL: "http://your-threat-api-endpoint"
  THREAT_INSIGHT_API_KEY: "your-threat-api-key"
```

## Uninstall

```bash
kubectl delete namespace watchu
```

## Requirements

- Kubernetes 1.20+
- StorageClass for PostgreSQL PVC
- Nodes with BTF support (for Tetragon)

## Troubleshooting

**Check pod status:**
```bash
kubectl get pods -n watchu
```

**View logs:**
```bash
kubectl logs -n watchu -l app=gateway -f
kubectl logs -n watchu -l app=frontend -f
kubectl logs -n watchu -l app=collector -f
kubectl logs -n watchu -l app=collector -c tetragon -f
kubectl logs -n watchu -l app=postgres -f
```
