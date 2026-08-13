# certval_stores_nipr

NIPR (DoD PKI) trust stores for certval — the production and operational-test
(JITC) environments.

## What this crate carries

| Feature | Env | Anchors | CA store |
|---------|-----|---------|----------|
| `nipr` | `NIPR` | 3 — DoD Root CA 3, 5, 6 | 37 intermediates, 37 partial paths |
| `om_nipr` | `OM_NIPR` | 3 — DoD JITC Root CA 3, 5, 6 | 45 intermediates, 45 partial paths |

Neither is on by default: the crate's only default feature is `reqwest-client`,
so a consumer elects the environment(s) it needs. With neither enabled the crate
builds and its provider yields no entries.

| Anchor | Key | Expires | CAs beneath it |
|--------|-----|---------|----------------|
| DoD Root CA 3 | RSA 2048, sha256 | 2029-12-30 | 14 |
| DoD Root CA 5 | ECDSA P-384 | 2041-06-14 | 2 |
| DoD Root CA 6 | RSA 4096, sha384 | 2053-01-24 | 21 |
| DoD JITC Root CA 3 | RSA 2048, sha256 | 2029-12-30 | 14 |
| DoD JITC Root CA 5 | ECDSA P-384 | 2041-05-31 | 2 |
| DoD JITC Root CA 6 | RSA 4096, sha384 | 2053-01-11 | 29 |

Both stores are **flat**, unlike `certval_stores_fpki`'s cross-certified mesh:
every CA is issued directly by one of that environment's own roots, so every
serialized partial path is a single certificate. The CAs are the usual DoD
families — ID, Email, SW (software/PIV-auth), and Derility (derived credential)
— with the operational-test store carrying both `DOD JITC …` and `DOD OM …`
issuers, including their `AE` variants.

## The embedded material

The DER inputs the stores were generated from ship beside each `.cbor`
(`cas/prod/`, `cas/om/`), and `conformance::check_generator_inputs` asserts they
still match what the store carries — nothing `include_bytes!`es those files, so
without that check they would drift in silence. Regenerating from them reproduces
the committed `.cbor` byte for byte (verified 2026-08-13).

The production anchors can be corroborated against a public source: the DoD Root
CA 3 and DoD Root CA 6 public keys embedded here match those in cross-certificates
carried in the GSA FPKI crawler bundle — the same bundle `certval_stores_fpki` is
built from — issued by DoD Interoperability Root CA 2 (checked 2026-08-13). DoD
Root CA 5 and the JITC roots do not appear in it.

`cas/om/` holds 46 `.der` files for 45 CAs: `DOD_OM_AE_Derility_CA_2.der` and
`DOD_OM_Derility_CA_2.der` are byte-identical. The store is correct either way
(both files are present in it, so `check_generator_inputs` passes), but the file
count is not the CA count.

## Refreshing

The stores are built from the checked-in DER folders, so refreshing means
replacing certificates in `roots/` and `cas/` and regenerating:

```sh
# redhound/certval-store-gen
certval-store-gen --out-dir ./out local --tas roots/prod --cas cas/prod
cp out/ca.cbor cas/prod/prod.cbor

certval-store-gen --out-dir ./out local --tas roots/om --cas cas/om
cp out/ca.cbor cas/om/om.cbor
```

It reports `3 trust anchors, 37 intermediates` for production and
`3 trust anchors, 45 intermediates` for O&M. `--cas` may point at the folder that
already holds the `.cbor`; non-certificate files are ignored. The `ta.cbor` it
also writes is unused here — the anchors are embedded as DER, because
`reqwest::Certificate::from_der` takes only a bare `Certificate`.

Then update `EXPECTED_NIPR_INTERMEDIATES` / `EXPECTED_OM_NIPR_INTERMEDIATES` in
`tests/tests.rs` if a count moved, and re-run
`cargo test -p certval_stores_nipr --all-features`.

## Sanity check against pittv3

```sh
pittv3 -b cas/prod/prod.cbor -t roots/prod --list-partial-paths
pittv3 -b cas/om/om.cbor     -t roots/om   --list-partial-paths
```

For the committed material these report `37 certificates yielded: 37 paths with
1 certificate` and `45 certificates yielded: 45 paths with 1 certificate`. A CA
that appears in no path is unreachable to an offline consumer however
well-connected it looks.
