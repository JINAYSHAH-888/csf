# CSF on Kubernetes

The gateway and the S1 sidecar run as **two containers in one pod**, sharing the
unix socket over an `emptyDir` — the same topology as `compose.yaml`, for the
same reason (ADR-0010): S1 is an internal detail of the gateway, never a service
on the network.

Apply order:
```bash
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml      # gateway config + CRS exclusions
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

Before enforcing: run a shadow period, then calibrate the operating point from
this deployment's own traffic (`backend/scripts/calibrate.py`, ADR-0017) and set
`mode: enforce` in the ConfigMap. See `docs/runbooks/`.

Images must be published to a registry your cluster can pull; the manifests
reference `csf-gateway:dev` / `csf-s1:dev` as placeholders.
