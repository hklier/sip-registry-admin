# Kubernetes deployment

Argo CD manages the namespace, Deployment, and external LoadBalancer Service from `deploy/kubernetes/base`.

Create these secrets outside Git before applying the Argo CD Application:

- `sip-registry-admin-auth`: `ADMIN_USERNAME` and `ADMIN_PASSWORD`
- `sip-registry-admin-db`: `mariadb-credentials`, containing the three-line host/user/password file
- `sip-registry-admin-tls`: an HTTPS certificate and private key

The service exposes TCP 443 and receives its external address from the cluster LoadBalancer implementation. The credential and TLS secrets are intentionally not declared in the Kustomization so automated reconciliation cannot overwrite them.
