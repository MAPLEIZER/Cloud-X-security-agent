# Third-Party Notices

This repository is a legacy Cloud-X installer/configuration snapshot. The MIT license applies to Cloud-X-authored code unless a file states otherwise; it does not relicense upstream software or copied/adapted third-party material.

## Wazuh

The repository installs/configures and contains configuration work intended for Wazuh. Wazuh is an independent open-source project distributed under its own upstream licensing terms (project-level GPL-2.0 licensing). Cloud-X does not claim ownership of Wazuh.

Upstream: https://github.com/wazuh/wazuh

## Other tools/components

Historical scripts or documentation may reference external tools such as Sysmon, Python packages or operating-system package repositories. Those components remain subject to their own licenses and distribution terms.

## Migration rule

Before any file from this legacy repository is included in a supported Cloud-X release:

- identify whether the file is wholly Cloud-X-authored or adapted from upstream material;
- preserve required copyright/license notices;
- review the exact dependency/package licenses for the release;
- prefer supported upstream packages/APIs over vendoring third-party source;
- record migrated provenance in the canonical `Cloud-X-MVP/THIRD_PARTY_NOTICES.md`.
