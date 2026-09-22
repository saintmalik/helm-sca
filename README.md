# helm-sca

Supply chain security on the images your GitOps/ops repo would deploy (Argo, Flux, Helm, Terraform), not an app CI image scans. Syft → Grype. Inventory scopes that set; `scan` is the gate.

Runs in CI against what GitOps would apply: Argo `Application`, Flux `HelmRelease`/`Kustomization`, charts, rendered manifests, and best-effort Terraform `helm_release`.

Blog: [supply chain risk in Helm charts](https://blog.saintmalik.me/helm-gitops-supply-chain-checks/)

GitHub Action that runs this in CI: [`saintmalik/helm-sca-action`](https://github.com/saintmalik/helm-sca-action)

## Install

Needs `helm` on PATH for chart/GitOps/Terraform chart paths. `scan` also needs [`syft`](https://github.com/anchore/syft) and [`grype`](https://github.com/anchore/grype). Kustomize sources need `kubectl` or `kustomize`.

```bash
# Linux amd64 example (also: darwin, arm64)
curl -sSfL \
  "https://github.com/saintmalik/helm-sca/releases/download/v0.0.1/helm-sca_linux_amd64.tar.gz" \
  | tar -xz -C /usr/local/bin helm-sca

# or
go install github.com/saintmalik/helm-sca/cmd/helm-sca@v0.0.1
```

## Usage

```bash
helm-sca inventory --manifests ./rendered --format json
helm-sca inventory --chart ./charts/demo -f ./charts/demo/values.yaml
helm-sca inventory --argo-apps ./apps --repo-root .
helm-sca inventory --flux ./clusters --repo-root .
helm-sca inventory --gitops ./deploy --repo-root .          # Argo + Flux
helm-sca inventory --terraform ./tf --repo-root .
helm-sca inventory --terraform-json ./plan.json             # terraform show -json

helm-sca scan --flux ./clusters --repo-root . --out-dir ./out --fail-on high
```

Formats: `list` (default), `json`, `yaml`, `cyclonedx-json`

Workflow examples live in the [action repo](https://github.com/saintmalik/helm-sca-action/tree/main/examples).

## Release

Tag-driven via GoReleaser. First release:

```bash
git tag v0.0.1
git push origin v0.0.1
```

## License

MIT
