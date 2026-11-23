## What does this PR do?

<!-- A short summary of the change and why it's needed. -->

Closes #<!-- issue number, if any -->

## Type of change

- [ ] Bug fix
- [ ] New signature or verdict rule
- [ ] Documentation
- [ ] Refactor / tests / tooling

## How was it tested?

<!-- Describe the tests you added or ran. For a new signature, name the
standard it comes from and the fixture that proves the pattern. -->

## Checklist

- [ ] `npm run check`, `npm run build` and `npm test` all pass
- [ ] `npm run fixtures:check` passes — fixtures regenerated with
      `npm run fixtures`, never edited by hand
- [ ] New signatures follow the TESTING.md loop: a `src/signatures/db.ts`
      entry with its citation, a generator-planted fixture, and the expected
      entries in `test/scanner.test.ts`
- [ ] Existing signature ids are unchanged (or the change is called out
      explicitly and justified)
- [ ] README or docs updated if behavior changed
- [ ] No secrets, private binaries, or live malware samples are included —
      hex excerpts only
