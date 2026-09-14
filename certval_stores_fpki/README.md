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
| `cas/fpki/fpki.cbor` | built from `CACertificatesValidatingToFederalCommonPolicyG2.p7b` |

That `.p7b` is the FPKI crawler's output (`GSA/FPKIcrawler`) — the same data behind
the FPKI graph on idmanagement.gov — published in the `GSA/idmanagement.gov` repo
at `_implement/tools/`. Snapshot taken **2026-08-12** from a bundle the crawler
published **2026-08-10**.

Those two dates are what the `FPKI` entry reports as `published` and `collected`.
They are literals in `src/lib.rs` here, unlike the DoD providers' generator-written
files: the `.p7b` states neither date, so both come off the GSA repository it was
downloaded from. `FPKI_LEGACY` reports no publication date at all — the G1 mesh is
no longer published — and gives the day its anchor reached this repository as the
collection date, the latest it can have been fetched.

The store is built from that bundle rather than from `.der` files kept beside it,
so there is no generator-input check here as there is in the DoD providers. The
two anchors above are files, though, and `conformance::check_root_inputs` asserts
each directory holds exactly what `src/lib.rs` `include_bytes!`es — both
environments are single-anchor, so a second `.der` appearing in either directory
is the drift it catches.

## Refreshing

Unlike the DoD stores, this material moves: the crawler republishes automatically
whenever the mesh changes, so treat the embedded store as a snapshot with a date,
not a constant.

```sh
curl -sSfO https://raw.githubusercontent.com/GSA/idmanagement.gov/staging/_implement/tools/CACertificatesValidatingToFederalCommonPolicyG2.p7b

# the adapter takes DER; the published bundle is PEM-wrapped PKCS#7
openssl pkcs7 -inform PEM -in CACertificatesValidatingToFederalCommonPolicyG2.p7b \
              -outform DER -out fpki-bundle.der.p7b

# redhound/certval-store-gen
certval-store-gen --out-dir ./out fpki --p7 ./fpki-bundle.der.p7b
cp out/ca.cbor cas/fpki/fpki.cbor
```

`certval-store-gen` splits the bundle into anchors and intermediates by
**verifying self-signatures**, not by comparing issuer to subject — the FPKI
contains self-issued rollover certificates (issuer == subject, signed by the
predecessor key) that a naive comparison would misfile as roots. It should report
`1 trust anchors, 133 intermediates`; its `ta.cbor` is redundant here because the
single anchor is embedded as DER instead.

After refreshing, update `EXPECTED_INTERMEDIATES` in `tests/tests.rs` if the count
moved, and re-run `cargo test -p certval_stores_fpki --all-features`.

## Sanity check against pittv3

```sh
pittv3 -b cas/fpki/fpki.cbor -t roots/fpki -e <some-fpki-cert>.der -v
```

For the 2026-08-12 snapshot, `--list-partial-paths` reports 133 certificates
yielding 12 paths of 1 certificate, 45 of 2, 37 of 3, and 48 of 4.

Note that FPKI path validation reaches a lot of CRL distribution points across many
agency repositories; `RevocationStatusNotDetermined` on a network-restricted host
usually means an unreachable CRL DP rather than a defective store.
