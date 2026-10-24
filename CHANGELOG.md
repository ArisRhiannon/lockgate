# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-24
### Added
- Diff mode (`--base <git-ref|file>`) and single-file audit mode for npm `package-lock.json` v1, v2 and v3.
- Rules LG001-LG009: integrity changed, non-registry source, insecure protocol, new install script, missing integrity, source changed, downgrade, package added, tarball name mismatch.
- Text, JSON and SARIF 2.1.0 output; `--fail-on`, `--registry`, `--ignore`.
- Composite GitHub Action (`action.yml`).
