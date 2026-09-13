# depguard-demo-vulnerable

A tiny, deliberately vulnerable npm project used to demo and evaluate
[DepGuard](https://github.com/priyanshiiitr/depguard) at a hackathon.

It pins three dependencies with known, real OSV.dev advisories:

- `lodash@4.17.15` — prototype pollution (fixed upstream)
- `minimist@1.2.5` — prototype pollution, CVE-2021-44906 (fixed in 1.2.6)
- `axios@0.21.0` — SSRF, CVE-2020-28168 (fixed in 0.21.1)

Do not use this repository's dependencies in any real project.
