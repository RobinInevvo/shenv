# shenv

Go CLI that shares age-encrypted, signed `.env` files. Threat model: `docs/security.md`.

## Checks

`just ci` before calling work done.

## Changelog

Every user-visible change (feature, fix, behavior change, security hardening) gets a
changelog note in the same change:

```sh
just note fixed "One or two short sentences, written for users: what changed and what they notice."
```

Kinds: `added`, `changed`, `fixed`, `removed`, `security`, `deprecated`. Notes land in
`.stamp/changelog/` and are folded into `CHANGELOG.md` by `stamp release`; never edit
`CHANGELOG.md` or `VERSION` by hand. Internal refactors, tests and CI changes get no note.
