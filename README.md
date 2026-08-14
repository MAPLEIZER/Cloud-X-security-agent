# Cloud-X Security Agent — Legacy Installer & Policy Repository

> **Status: legacy migration source.** Active Cloud-X product development has moved to [`MAPLEIZER/Cloud-X-MVP`](https://github.com/MAPLEIZER/Cloud-X-MVP).

This repository preserves the earlier Windows/Linux Wazuh installer, endpoint configuration and active-response work that informed the current Cloud-X packaging layer. It is retained for provenance and migration review; it is **not the supported installation channel** for current Cloud-X builds.

## Do not install from mutable `main`

Historical versions of this README used commands that downloaded PowerShell directly from the repository's mutable `main` branch and executed it with Administrator privileges. That is no longer an approved deployment pattern.

For future Cloud-X releases, endpoint bootstrap artifacts are intended to be:

- immutable and versioned;
- signed/verified where the platform supports it;
- tied to an explicit Wazuh compatibility manifest;
- suitable for unattended deployment through existing RMM/MDM/GPO/configuration-management tools;
- provisioned with short-lived enrolment material rather than long-lived administrator credentials.

Until the canonical project publishes a supported release artifact, treat the scripts in this repository as historical development material only.

## Relationship to the current project

| Repository | Role |
|---|---|
| [`Cloud-X-MVP`](https://github.com/MAPLEIZER/Cloud-X-MVP) | **Canonical Cloud-X product repository** |
| `Cloud-X-security-agent` | Legacy installer/configuration source and provenance |
| [`Cloud-X-Dashboard`](https://github.com/MAPLEIZER/Cloud-X-Dashboard) | Legacy dashboard/UI snapshot |

The hardened installer and active-response baseline now lives in the canonical repository. Older executable scripts here should not be copied back merely because they contain additional code; any migration requires a security review and a clear product need.

## What remains useful here

- historical Windows/Linux deployment approaches;
- Wazuh endpoint configuration and policy experiments;
- active-response design history;
- documentation useful for comparing old and current packaging choices.

The next product direction is **not** a separate proprietary endpoint agent. Cloud-X will initially use the supported upstream Wazuh agent while Cloud-X owns the trusted bootstrap/enrolment, policy abstraction, tenant workflow, findings, remediation and reporting layers.

## Canonical roadmap

See the current roadmap and architecture in `Cloud-X-MVP`:

- `docs/ROADMAP.md`
- `docs/ARCHITECTURE.md`
- `docs/PHASE0_INVENTORY.md`
- `docs/research/2026-08-14-smb-msp-soc-product-decision.md`

## Licensing and provenance

Cloud-X-authored code in this repository is provided under the [MIT License](LICENSE), unless a file states otherwise. Wazuh and any other third-party components remain under their respective upstream licenses. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Archive plan

This repository can be archived after:

1. all unique useful installer/policy work has been intentionally migrated or rejected;
2. no deployment process depends on raw files from this repository;
3. current-tree provenance and security-sensitive artifacts have been reviewed;
4. the canonical repository has a supported versioned endpoint packaging path.
