# Detection coverage matrix

| Source | Exact detection | Heuristic/potential detection | Main caveat |
|---|---|---|---|
| Installed dependency tree | name + exact version | suspicious lifecycle filename | match does not prove lifecycle execution |
| npm lockfile | resolved exact version | declaration range handled separately | stale lockfile may not reflect current install |
| pnpm lockfile | modern/legacy package keys and importer versions | alias/importer fallback | unusual future syntax can require parser updates |
| Yarn lockfile | Classic/Berry resolution and version | selector fallback | malformed blocks become incomplete coverage |
| Bun text lock | package/version text | — | depends on text lock structure |
| Bun binary lock | Bun-resolved dependency list | byte-string fallback | fallback marks scan incomplete |
| npm cacache | registry tarball key, metadata, SRI hash | missing content tolerated when index survives | cache presence does not prove execution |
| pnpm store | metadata and package manifests | encoded paths | content-addressable layouts vary by pnpm version |
| Yarn cache | archived package manifest and filename | extensionless archive magic | encrypted/unsupported or corrupt relevant ZIP entry is a gap |
| Bun cache | package manifests and relevant archives | encoded paths and extensionless archive magic | layout changes can reduce coverage |
| Source repository | exact affected package manifest | dependency ranges/tags, candidate filenames | mutable tags require lockfile confirmation |
| Payload files | exact SHA-256 by candidate name; every file with `--hash-all` | filename + marker combinations | a new, previously unknown payload hash can evade exact matching |
| Tarball | exact SHA-512 for known keyv tarball | archived package/version | other malicious tarballs are version-IOC based; corrupt TAR headers fail closed |
| Claude/VS Code hooks | documented filename reference | — | deleted hooks leave no local evidence |
| Persistence | exact documented path | content markers | Windows persistence was not documented in the primary source |
| Processes | command-line indicators | — | command-line visibility depends on OS permissions |

A negative result is meaningful only when `coverage.complete` is true and the IOC feed is fresh and validated.
