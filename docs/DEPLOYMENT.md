# JADE Ultimate Security Platform - Deployment

## Prerequisites

- Kubernetes 1.21+
- Helm 3.x
- Docker (for local build)
- Terraform (optional for IaC)
- Cloud provider or Minikube

## Quick Deploy (Helm)

```bash
kubectl create ns jade-security
helm install jade-ultimate ./deployment/kubernetes/helm -n jade-security
```

## Terraform

```bash
cd deployment/terraform
terraform init
terraform apply
```

## Manual

1. Edit `deployment/kubernetes/secret.yaml` and `configmap.yaml` for secrets and configs.
2. Apply all manifests:

```bash
kubectl apply -f deployment/kubernetes/
```

## Monitoring

- Prometheus metrics at `/metrics` on backend
- Grafana dashboard via separate deployment

## SSL

- Managed by cert-manager, with Let's Encrypt

## Notes

- For production, make sure all secrets are strong and not defaults!
- RBAC and network policies recommended.