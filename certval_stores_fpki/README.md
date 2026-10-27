# certval_stores_fpki

Federal PKI trust store for certval.

## What makes this one different

The other providers in this family carry a handful of independent roots. The FPKI
is not shaped that way: it is a **cross-certified mesh with a single anchor**. The
`FPKI` environment therefore carries exactly one trust anchor — Federal Common
Policy CA G2 — and every other participant (DoD, Treasury, Entrust, DigiCert,
State, WidePoint/ORC, CertiPath, Boeing, Northrop Grumman, …) is reached through
cross-certificates in the CA store. One root is the correct count, not a gap.

| Feature | Env | Anchors | CA store |
|---------|-----|---------|----------|
| `fpki` (default) | `FPKI` | 1 — Federal Common Policy CA G2 | 133 intermediates, 142 partial paths |
| `fpki_legacy` | `FPKI_LEGACY` | 1 — Federal Common Policy CA (G1, retired) | none |

`fpki_legacy` is anchors-only: the G1 mesh is no longer published, so there is no
CA store to pair with it. Enable it only to validate paths that predate the G2
migration. G1 is valid until 2030-12-01 but is not the current anchor — keep the
two environments distinct rather than merging the roots.

## Provenance of the embedded material

| File | Source |
|------|--------|
| `roots/fpki/Federal_Common_Policy_CA_G2.der` | `https://repo.fpki.gov/fcpca/fcpcag2.crt` |
| `roots/legacy/Federal_Common_Policy_CA.der` | `https://repo.fpki.gov/fcpca/fcpca.crt` |
| `cas/fpki/fpki.cbor` | built by walking the mesh from the G2 anchor; see below |

The FPKI is a cross-certified mesh, and it publishes no single artifact to build from: its
certificates name bundles of their neighbours, SIA `caRepository` for what a CA issued and AIA
`caIssuers` for what was issued to a certificate's issuer. `certval-store-gen fpki-crawl` walks
both from Federal Common Policy CA G2, as certval's graph builder does, and commits:

- `inputs/crawl/<host>/<path>`: every bundle the walk read, exactly as its repository served it.
  These are the publishers' own artifacts, BER included, so a refresh diff names the repository
  that changed.
- `provenance/fpki/collected.txt`: the day of the walk, which the `FPKI` entry reports as
  `collected`. It is also the date the store is validated at: a certificate the mesh still
  publishes after it expired is left out and listed in `provenance/fpki/dropped.txt`. A mesh
  states no publication date, so the entry reports none.
- `cas/fpki/fpki.cbor`: the store.

The anchors are never written by the walk. `FPKI_LEGACY` reports no publication date — the G1
mesh is no longer published — and gives the day its anchor reached this repository as the
collection date, the latest it can have been fetched.

`the_store_is_what_the_committed_walk_generates` regenerates the store from the committed
bundles at the recorded date and compares certificate sets, as the DoD providers do with their
streams. The two anchors above are files, and `conformance::check_root_inputs` asserts each
directory holds exactly what `src/lib.rs` `include_bytes!`es — both environments are
single-anchor, so a second `.der` appearing in either directory is the drift it catches.

Until 2026-10-27 the store was built from GSA's FPKI crawler bundle
(`CACertificatesValidatingToFederalCommonPolicyG2.p7b`). The walk replaced it because that bundle
lagged the mesh and left out the two Northrop Grumman signing CAs, whose repository serves BER.

## Refreshing

The mesh moves whenever a participant's cross-certificates change, so treat the embedded store
as a snapshot with a date, not a constant. `refresh-fpki.yml` walks it daily and opens a pull
request when the material moved. By hand, from the workspace root:

```sh
cargo run -p certval-store-gen -- fpki-crawl
```

The FPKI's repositories are not reliably up. A repository that gives no answer after the walk's
retries is read from its bundle under `inputs/crawl/` instead, and the walk continues through it,
so one host being down does not cost the subtree beneath it; anything in that earlier copy that
has expired since is pruned like any other expired certificate. A repository with no committed
copy is skipped and logged, since the store held nothing from it before either. A repository
answering that it has nothing (a 4xx) is recorded as such; the mesh has at least one such URI
permanently. `--from-committed`
regenerates from the bundles already committed and fetches nothing, for when the generator's
rules change rather than the mesh.

Self-signed certificates the walk reaches are dropped by **verifying self-signatures**, not by
comparing issuer to subject — the FPKI contains self-issued rollover certificates (issuer ==
subject, signed by the predecessor key) that a naive comparison would misfile as roots.

After refreshing, review the diff, then update the pins and re-run the tests:

```sh
UPDATE_PINS=1 cargo test -p certval_stores_fpki --all-features
cargo test -p certval_stores_fpki --all-features
```

## Sanity check against pittv3

```sh
pittv3 -b cas/fpki/fpki.cbor -t roots/fpki -e <some-fpki-cert>.der -v
```

For the 2026-08-12 snapshot, `--list-partial-paths` reports 133 certificates
yielding 12 paths of 1 certificate, 45 of 2, 37 of 3, and 48 of 4.

Note that FPKI path validation reaches a lot of CRL distribution points across many
agency repositories; `RevocationStatusNotDetermined` on a network-restricted host
usually means an unreachable CRL DP rather than a defective store.
