# Contributing to lockgate

Thanks for helping. lockgate stays small on purpose: zero runtime dependencies,
no network access, deterministic output.

## Dev setup

```bash
git clone https://github.com/ArisRhiannon/lockgate && cd lockgate
npm test               # node:test, no install needed (Node >= 18)
node bin/lockgate.js --help
```

## Adding a rule

1. Add it to `RULES` in `src/rules.js` with the next `LGxxx` id, a severity and a one-paragraph `help`.
2. Emit it from `src/analyze.js`.
3. Add tests in `test/analyze.test.js`: one true positive and one near-miss that must **not** fire.
4. Update the rule table in `README.md` and `CHANGELOG.md`.

Rules must work from lockfile contents alone. Anything that needs the registry
or the internet belongs in a different tool.

## Commit style

Short imperative subject (`add LG010 ...`, `fix scoped tarball parsing`).
