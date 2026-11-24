#K8S audit

**Security audit for Kubernetes manifests.** k8s-audit runs [Trivy](https://github.com/aquasecurity/trivy) and [Kubescape](https://github.com/kubescape/kubescape) on your YAML files, merges their findings into a single list sorted by severity, and produces reports you can actually read: Markdown, HTML, CSV and Excel.

It runs locally, in Docker (nothing to install), or in CI, where it can block a deployment when a critical misconfiguration is found.

## Why

Most Kubernetes security incidents start with a misconfiguration, not an exploit: a privileged container, a workload running as root, a secret in plain text. These mistakes are easy to catch before deployment, but each scanner covers a different set of rules and reports them in its own format.

k8s-audit combines two of the most widely used open-source scanners and gives you one answer: what is wrong, how serious it is, and how to fix it.

This project grew out of my master's research at UQAM on security analysis of Kubernetes manifests.

## Results on real-world commits

The repository includes a dataset of **44 commits** of real Kubernetes manifests, in [`data/commits/`](data/commits/). Each sub-folder is named after a commit SHA and holds the manifest files from that commit.

Scanning the whole dataset:

| Severity | Findings |
|---|---:|
| CRITICAL | 41 |
| HIGH | 671 |
| MEDIUM | 948 |
| LOW | 904 |
| **Total** | **2,564** |

That is an average of about **58 findings per commit**. The CI pipeline re-runs this analysis on every push: open the latest run in the [Actions tab](https://github.com/krmsight/k8s-audit/actions) to see the summary, or download the `audit-reports` artifact for the HTML report, the Excel workbook and the per-commit CSV.

**Dataset source:** The manifests come from public commits in open-source projects on GitHub, collected for my master's research on Kubernetes manifest security. Each folder is named after the original commit SHA, so every file can be traced back to its source. All files remain under the licenses of their original projects.

## Features

- **Two scanners, one report**: Trivy and Kubescape findings are normalized to the same severity scale and deduplicated
- **Docker mode**: no local install; the tools run in containers and are removed afterwards
- **Batch analysis**: scan a folder of commits and get one row per commit, worst first
- **Before / after comparison**: see which issues a change fixed, introduced or left in place
- **Readable output**: Markdown, a filterable HTML report, CSV and a formatted Excel workbook
- **CI-ready**: exits with code 1 above a severity threshold, and writes a summary straight onto the GitHub Actions job page

## Quick start

Requirements: Python 3.10+ and either Docker, or Trivy and Kubescape installed locally.

```bash
git clone https://github.com/krmsight/k8s-audit.git
cd k8s-audit
pip install openpyxl        # only needed for Excel output

python audit.py data/commits --docker --html reports/commits.html
```

```
[*] Trivy… (Docker)
[*] Kubescape… (Docker)

Summary:
  CRITICAL  41
  HIGH      671
  MEDIUM    948
  LOW       904
  TOTAL     2564

Report written to reports/report.md
```

If Trivy and Kubescape are not installed but Docker is, Docker mode turns on automatically.

## Usage

```bash
# Full analysis of the dataset: every output format
python audit.py data/commits \
  -o reports/commits.md \
  --html reports/commits.html \
  --excel reports/results.xlsx \
  --by-commit reports/commits.csv

# Scan a single commit
python audit.py data/commits/<commit-sha>

# Compare a new version of your manifests against the previous one
python audit.py k8s-new/ --baseline k8s-old/

# Fail on HIGH or above (for CI)
python audit.py k8s/ --fail-on HIGH
```

| Option | Description |
|---|---|
| `-o, --output` | Markdown report path (default: `reports/report.md`) |
| `--html` | Also write a self-contained HTML report with filters and search |
| `--excel` | Also write an Excel workbook: Summary, By commit, Rules, Details |
| `--by-commit` | Write a per-commit CSV summary (one sub-folder per commit) |
| `--baseline DIR` | Compare against a previous version: fixed, new and remaining findings |
| `--fail-on` | Exit with code 1 at `CRITICAL` (default), `HIGH`, `MEDIUM` or `LOW`; `NONE` never fails |
| `--docker` | Run Trivy and Kubescape in Docker instead of local binaries |

## How it works

```
manifests/ ──┬──► Trivy (trivy config)      ──┐
             │                                ├──► normalize ──► deduplicate ──► sort ──► reports
             └──► Kubescape (kubescape scan) ─┘
```

1. **Scan**: Trivy and Kubescape each analyze the same folder and output JSON.
2. **Normalize**: Kubescape scores controls from 1 to 10, so scores are mapped to Trivy's scale: 9 and above is CRITICAL, 7 to 9 is HIGH, 4 to 7 is MEDIUM and below 4 is LOW.
3. **Merge**: duplicates are removed, and findings are sorted by severity, then by file.
4. **Report**: every finding keeps its tool, rule ID, file, commit and remediation advice.

## Use it in CI

The workflow in [`.github/workflows/audit.yml`](.github/workflows/audit.yml) audits the dataset on every push and pull request, posts a summary on the job page and uploads all reports as a downloadable artifact. It uses `--fail-on NONE` because the dataset is real-world data under study, not code to block.

To protect your own project, add a step like this to its workflow. Here the build fails as soon as a HIGH or CRITICAL issue appears:

```yaml
- name: Kubernetes security audit
  run: |
    git clone --depth 1 https://github.com/krmsight/k8s-audit.git /tmp/k8s-audit
    python /tmp/k8s-audit/audit.py k8s/ --docker --fail-on HIGH
```

## Project structure

```
k8s-audit/
├── audit.py                    # the tool
├── data/
│   └── commits/                # 44 commits of real-world manifests, one folder per SHA
└── .github/workflows/audit.yml # CI pipeline
```

## Author

**Ala Karmous**, DevSecOps engineer, Montréal · contact@alakarmous.com
