# Contributing to findcrypt

Thanks for your interest — issues and pull requests are welcome.

## Getting set up

```bash
git clone https://github.com/kn1ght073/findcrypt.git
cd findcrypt
npm ci          # installs exactly the locked dependency set
npm run check   # strict TypeScript compile (tsc --noEmit)
npm run build   # tsup dual-format build (ESM + CJS) into dist/
npm test        # vitest suite, including the fixture drift gate
```

Node 18 or newer is required (see `engines` in package.json).

## Before opening a pull request

- `npm run check`, `npm run build` and `npm test` all pass locally.
- New signatures follow the add-a-signature loop documented in TESTING.md:
  constant data in `src/signatures/db.ts` with its standard's citation, a
  fixture planted by `scripts/gen-fixtures.mjs`, and the expected-entry
  extension in `test/scanner.test.ts`.
- Fixtures are deterministic — never edit a `.bin` fixture by hand; regenerate
  with `npm run fixtures` and commit the result (`npm run fixtures:check`
  guards against drift in CI).
- Keep pull requests focused: one logical change per request.

## Reporting bugs

Open an issue with the file (or a hex dump excerpt) you scanned, the exact
command you ran, and what you expected vs. what you got. False positives from
real binaries are especially valuable.
