package cli

import (
	"fmt"
	"os"

	"github.com/saintmalik/helm-sca/internal/inventory"
	"github.com/saintmalik/helm-sca/internal/recommend"
	"github.com/saintmalik/helm-sca/internal/scan"
	"github.com/saintmalik/helm-sca/internal/version"
	"github.com/spf13/cobra"
)

var (
	chart         string
	manifests     string
	argoApps      string
	flux          string
	gitops        string
	terraform     string
	terraformJSON string
	release       string
	values        []string
	setVals       []string
	format        string
	repoRoot      string
	outDir        string
	failOn        string
	onlyFixed     bool
	maxApps       int
	skipStatic    bool
	skipRegex     bool
)

// Execute runs the root command.
func Execute() error {
	root := &cobra.Command{
		Use:   "helm-sca",
		Short: "GitOps + Helm supply chain security inventory and scan",
		Long: `helm-sca runs supply chain checks on container images from what would deploy:
Helm charts, rendered manifests, Argo CD Applications, Flux HelmReleases, or
best-effort Terraform/OpenTofu Helm pins. Optionally runs Syft → Grype in CI
against what GitOps would apply.

Not Argo-only: use --argo-apps, --flux, --gitops (auto), --manifests, --chart,
or --terraform / --terraform-json.

Workflow examples live in the sibling repo: https://github.com/saintmalik/helm-sca-action`,
	}

	root.PersistentFlags().StringVar(&repoRoot, "repo-root", ".", "repository root for resolving local paths / valueFiles")

	root.AddCommand(inventoryCmd())
	root.AddCommand(scanCmd())
	root.AddCommand(recommendCmd())
	root.AddCommand(versionCmd())

	return root.Execute()
}

func inventoryFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&chart, "chart", "", "Helm chart path or ref")
	cmd.Flags().StringVar(&manifests, "manifests", "", "directory of already-rendered Kubernetes YAML")
	cmd.Flags().StringVar(&argoApps, "argo-apps", "", "Argo CD Application YAML file or directory")
	cmd.Flags().StringVar(&flux, "flux", "", "Flux HelmRelease / Kustomization YAML file or directory")
	cmd.Flags().StringVar(&gitops, "gitops", "", "directory: auto-detect Argo Applications + Flux resources")
	cmd.Flags().StringVar(&terraform, "terraform", "", "Terraform/OpenTofu .tf directory or file (best-effort)")
	cmd.Flags().StringVar(&terraformJSON, "terraform-json", "", "terraform show -json / plan JSON path")
	cmd.Flags().StringVar(&release, "release", "helm-sca", "helm template release name (chart mode)")
	cmd.Flags().StringArrayVarP(&values, "values", "f", nil, "Helm values file (repeatable)")
	cmd.Flags().StringArrayVar(&setVals, "set", nil, "Helm --set key=value (repeatable)")
	cmd.Flags().StringVar(&format, "format", "list", "output format: list|json|yaml|cyclonedx-json")
	cmd.Flags().BoolVar(&skipStatic, "skip-static", false, "skip static-YAML fallback detectors")
	cmd.Flags().BoolVar(&skipRegex, "skip-regex", false, "skip regex fallback detectors")
}

func invOptions() inventory.Options {
	return inventory.Options{
		Chart:         chart,
		Manifests:     manifests,
		ArgoApps:      argoApps,
		Flux:          flux,
		Gitops:        gitops,
		Terraform:     terraform,
		TerraformJSON: terraformJSON,
		Release:       release,
		Values:        values,
		Set:           setVals,
		RepoRoot:      repoRoot,
		SkipStatic:    skipStatic,
		SkipRegex:     skipRegex,
	}
}

func inventoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Inventory container images from chart, manifests, GitOps, or Terraform",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, warnings, err := inventory.Run(invOptions())
			for _, w := range warnings {
				fmt.Fprintln(os.Stderr, "warning:", w)
			}
			if err != nil {
				return err
			}
			return inventory.Write(cmd.OutOrStdout(), result, format)
		},
	}
	inventoryFlags(cmd)
	return cmd
}

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Inventory images then run Syft → Grype (fail on severity threshold)",
		RunE: func(cmd *cobra.Command, args []string) error {
			res, warnings, err := scan.Run(cmd.Context(), scan.Options{
				Inventory: invOptions(),
				OutDir:    outDir,
				FailOn:    failOn,
				OnlyFixed: onlyFixed,
				Format:    format,
			})
			for _, w := range warnings {
				fmt.Fprintln(os.Stderr, "warning:", w)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "images=%d findings=%d reports=%s\n", len(res.Images), res.FindingCount, res.ReportsDir)
			return err
		},
	}
	inventoryFlags(cmd)
	cmd.Flags().StringVar(&outDir, "out-dir", "helm-sca-out", "directory for inventory, SBOMs, and Grype reports")
	cmd.Flags().StringVar(&failOn, "fail-on", "none", "fail when findings at or above severity: none|low|medium|high|critical")
	cmd.Flags().BoolVar(&onlyFixed, "only-fixed", true, "pass --only-fixed to Grype")
	return cmd
}

func recommendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recommend",
		Short: "Recommend chart/release pin bumps (stub in v1)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return recommend.Run(cmd.OutOrStdout(), recommend.Options{
				ArgoApps: argoApps,
				OutDir:   outDir,
				MaxApps:  maxApps,
			})
		},
	}
	cmd.Flags().StringVar(&argoApps, "argo-apps", "", "Argo Application YAML file or directory")
	cmd.Flags().StringVar(&flux, "flux", "", "Flux resources (reserved for future recommend)")
	cmd.Flags().StringVar(&outDir, "out-dir", "helm-sca-out", "output directory for future recommendation artifacts")
	cmd.Flags().IntVar(&maxApps, "max-apps", 12, "cap apps to re-score (reserved)")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.String())
		},
	}
}
