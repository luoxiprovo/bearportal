# Artifact versions and rollback plans

The normal installer path resolves the current `luoxiprovo/bearmail` main SHA for a preparation and downloads the installer and four release artifacts at that SHA. It calculates `SHA256SUMS` for the artifacts. There is no fixed production release directory that startup waits for, and generated download checksums are not release signatures.

A retry/preparation may resolve a newer SHA; an operation's input/fingerprint does not constitute a permanent artifact lock. Record the resolved commit and any local overrides in evidence. The controlled development run required local script overrides, described in [../release-evidence/2026-11-05-ssh-install.md](../release-evidence/2026-11-05-ssh-install.md). The fixes were subsequently published as Bearmail commit `c380d1a9d50a4b6aca0c7de948d5fdeef1fba521`. Fresh startup resolves published main.

Explicit `buildServer` release/runner injection remains available for tests or configured integrations. A release-layout check verifies names and checksums but does not establish a live install.

## Upgrade/rollback records

`POST /v1/admin/deployments/:id/upgrade-plan` records compatibility and the named backup. A later unrelated backup does not satisfy that plan. States are `blocked`, `preserve_required`, `rollback_required` and `pending`.

The database constraint forces `executed`, `binaries_executed` and `data_rollback` false. This route neither executes an upgrade nor performs a rollback. An operator must preserve mail data and run/verify any external maintenance separately.

## Evidence

`GET /v1/admin/release-checklist` hardcodes incomplete live, soak, restore, upgrade and cancellation-stop flags. The one live install does not make the entire checklist pass. Future records should distinguish source version, locally modified scripts, mock tests, host/service observations, external delivery and recovery drills.

See [../release-evidence/README.md](../release-evidence/README.md) and [../local-validation.md](../local-validation.md).
