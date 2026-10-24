# lockgate

**Offline npm lockfile diff gate for pull requests.** lockgate reviews `package-lock.json` changes and flags supply-chain red flags (a dependency that suddenly runs a `preinstall` script, a changed integrity hash, a git or tarball source) before anyone runs `npm install`.

[![CI](https://github.com/ArisRhiannon/lockgate/actions/workflows/ci.yml/badge.svg)](https://github.com/ArisRhiannon/lockgate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![Offline](https://img.shields.io/badge/network-none-informational)

```bash
npx lockgate --base origin/main
```

```
HIGH     LG004 left-pad now runs an install script (1.3.0 -> 1.3.1)
CRITICAL LG001 chalk@5.3.0 integrity changed from sha512-XExcO+dvLKvVt… to sha512-TAMPERED…
INFO     LG008 added is-even@1.0.0

lockgate: 412 packages | +1 added, -0 removed, ~2 changed
findings: 1 critical, 1 high, 1 info
```

## Why

Lockfile diffs are thousands of lines long, and nobody reads them. Attackers count on that.

- **npm worms add install scripts.** Shai-Hulud (Sept 2025), [Shai-Hulud 2.0](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/) (Nov 2025), [the May 2026 wave](https://research.jfrog.com/post/shai-hulud-here-we-go-again/) and [ChainDrop](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/) (Aug 2026) all spread the same way: steal an npm token, inject a payload, **add a `preinstall` hook, bump the patch version**, republish. npm records that in your lockfile as `"hasInstallScript": true`. lockgate turns that one line into a failing check.
- **Lockfile injection.** A PR can swap a `resolved` URL to an attacker's tarball or change an `integrity` hash while the version number stays the same. Published npm versions are immutable, so a changed hash for the same version is never routine.
- **Offline by design.** lockgate reads two JSON files (or one file and a git ref) and nothing else. No account, no API key, no telemetry, no registry calls. It works in air-gapped CI and on forks without secrets.

## Install

```bash
npx lockgate --help          # no install
npm i -D lockgate            # per project
npm i -g lockgate            # global
```

Requires Node.js 18+. Zero runtime dependencies.

## Quickstart

```bash
# Review the lockfile changes in your branch against main
lockgate --base origin/main

# Compare two files
lockgate --base old-package-lock.json package-lock.json

# Audit a single lockfile (non-registry sources, http, missing integrity, name mismatch)
lockgate --list-install-scripts

# Machine-readable output
lockgate --base origin/main --format json
lockgate --base origin/main --format sarif --output lockgate.sarif

# Private registry
lockgate --base origin/main --registry https://npm.mycorp.example/
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`), `2` usage or parse error.

## GitHub Action

```yaml
name: lockgate
on:
  pull_request:
    paths: ['**/package-lock.json']
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
jobs:
  lockgate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: ArisRhiannon/lockgate@v0.1.0
        with:
          fail-on: high
          sarif: 'true'
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: lockgate.sarif }
```

`fetch-depth: 0` is needed so the base branch exists locally. Pin the action to a commit SHA in production.

## Rules

| ID | Severity | Name | Fires when |
|----|----------|------|------------|
| LG001 | critical | integrity-changed | Same name and version, different `integrity` hash |
| LG002 | high | non-registry-source | Resolved from git, a tarball URL, or a host not in `--registry` |
| LG003 | high | insecure-protocol | Resolved over `http://` or `git://` |
| LG004 | high | new-install-script | A new package runs install scripts, or an existing one starts to |
| LG005 | medium | missing-integrity | Registry package without an integrity hash |
| LG006 | medium | source-changed | Same version, different `resolved` URL |
| LG007 | low | version-downgrade | A package moved to a lower version |
| LG008 | info | package-added | A package entered the tree (context for reviewers) |
| LG009 | high | name-mismatch | Install path says `react`, tarball URL says `reakt` |

`lockgate --rules` prints the full descriptions. Silence a rule or package with `--ignore LG007` or `--ignore some-package`.

## Comparison

| | lockgate | [lockfile-lint](https://github.com/lirantal/lockfile-lint) | [dependency-review-action](https://github.com/actions/dependency-review-action) | Socket / commercial scanners |
|---|---|---|---|---|
| Looks at the **diff** between base and PR | yes | no (single file) | yes | yes |
| Flags packages that **start** running install scripts | yes | no | no | yes |
| Integrity hash changed for the same version | yes | no | no | varies |
| Host / https / integrity policy | yes | yes | no | yes |
| Known CVEs and licenses | no | no | yes | yes |
| Needs network or an account | **no** | no | yes (GitHub API) | yes |

lockgate does not replace a vulnerability scanner. Run it next to `npm audit` or dependency-review: they answer "is this version known-bad?", lockgate answers "did this PR change something it shouldn't have?", including in the hours before an advisory exists.

## FAQ

**Does it support yarn, pnpm or bun lockfiles?**
Not yet. v0.1 reads npm `package-lock.json` (lockfileVersion 1, 2 and 3; v1 has no `hasInstallScript`, so LG004 cannot fire on it). pnpm and yarn support are on the roadmap; PRs welcome.

**Will it block every Dependabot PR?**
No. Plain version bumps of registry packages with no new install script produce only `info` findings, which don't fail at the default `--fail-on high`.

**Does a clean run mean my dependencies are safe?**
No. lockgate catches suspicious *changes in the lockfile*. A malicious version that adds no install script and comes from the normal registry will look like an ordinary upgrade. Pair it with `npm ci --ignore-scripts`, a release-age cooldown, and a vulnerability scanner.

**Why not just use `npm ci --ignore-scripts`?**
You should. lockgate makes the decision visible in review: it tells you *which* dependency changed its install behavior, so you can catch a compromised release instead of only defusing it on one machine.

**Is any data sent anywhere?**
No. lockgate makes no network requests. In `--base <git-ref>` mode it runs `git show` locally.

## Related tools by the same author

- [wormguard](https://github.com/ArisRhiannon/wormguard): behavioral audit of npm install scripts in `node_modules`
- [envlint](https://github.com/ArisRhiannon/envlint): validate `.env` files against `.env.example`
- [caplabel](https://github.com/ArisRhiannon/caplabel): static capability analysis for JavaScript

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
