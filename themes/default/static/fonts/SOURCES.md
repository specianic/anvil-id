# Font sources

The default theme self-hosts two font families. Every file in this directory is byte-identical to
the upstream release named below: nothing was subset, converted or otherwise modified. The only
change is a file rename for the Hanken Grotesk font (`[wght]` is awkward in URLs). `SHA256SUMS`
records the sha256 of the upstream bytes and `scripts/check-fonts.sh` verifies them (it runs in
`just ci`).

Retrieved 2026-11-28.

## Hanken Grotesk

- Upstream: the google/fonts repository, directory `ofl/hankengrotesk`, pinned commit
  `c1eda9233c33ad7775b27efd794f931095cf6133`
  (https://github.com/google/fonts/tree/c1eda9233c33ad7775b27efd794f931095cf6133/ofl/hankengrotesk).
- Files:
  - `HankenGrotesk-wght.ttf` = upstream `HankenGrotesk[wght].ttf` (variable font, weight axis
    100-900; 132,892 bytes), renamed only.
  - `OFL-HankenGrotesk.txt` = upstream `OFL.txt` ("Copyright 2021 The Hanken Grotesk Project
    Authors").
- Licence: SIL Open Font License 1.1. The licence text declares no Reserved Font Name.

## IBM Plex Mono

- Upstream: the IBM/plex GitHub release `@ibm/plex-mono@2.5.0`
  (https://github.com/IBM/plex/releases/tag/%40ibm/plex-mono%402.5.0), asset
  `ibm-plex-mono.zip`.
- Files:
  - `IBMPlexMono-Regular.woff2` = `ibm-plex-mono/fonts/complete/woff2/IBMPlexMono-Regular.woff2`
  - `IBMPlexMono-Medium.woff2` = `ibm-plex-mono/fonts/complete/woff2/IBMPlexMono-Medium.woff2`
  - `OFL-IBMPlex.txt` = `ibm-plex-mono/LICENSE.txt` (CRLF line endings kept as shipped)
- Licence: SIL Open Font License 1.1, "Copyright 2017 IBM Corp. with Reserved Font Name "Plex"".
- Reserved Font Name: under the OFL a Modified Version may not use the name "Plex". These are the
  complete (not split) upstream files and must stay unmodified: do not subset, convert or
  re-encode them. To update, replace them with files from a newer official release and update
  `SHA256SUMS` and this file.
