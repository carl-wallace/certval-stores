# certval_stores_nipr

NIPR (DoD PKI) trust stores for certval — the production and operational-test
(JITC) environments.

## What this crate carries

| Feature | Env | Anchors | CA store |
|---------|-----|---------|----------|
| `nipr` | `NIPR` | 4 — DoD Root CA 3, 4, 5, 6 | 41 intermediates, 41 partial paths |
| `om_nipr` | `OM_NIPR` | 4 — DoD JITC Root CA 3, 4, 5, 6 | 53 intermediates, 53 partial paths |

Neither is on by default: the crate's only default feature is `reqwest-client`,
so a consumer elects the environment(s) it needs. With neither enabled the crate
builds and its provider yields no entries.

| Anchor | Key | Expires | CAs beneath it |
|--------|-----|---------|----------------|
| DoD Root CA 3 | RSA 2048, sha256 | 2029-12-30 | 14 |
| DoD Root CA 4 | ECDSA P-256, sha256 | 2032-07-25 | 0 |
| DoD Root CA 5 | ECDSA P-384, sha384 | 2041-06-14 | 6 |
| DoD Root CA 6 | RSA 4096, sha384 | 2053-01-24 | 21 |
| DoD JITC Root CA 3 | RSA 2048, sha256 | 2029-12-30 | 17 |
| DoD JITC Root CA 4 | ECDSA P-256, sha256 | 2032-05-31 | 0 |
| DoD JITC Root CA 5 | ECDSA P-384, sha384 | 2041-05-31 | 7 |
| DoD JITC Root CA 6 | RSA 4096, sha384 | 2053-01-11 | 29 |

Root CA 4 carries no subordinate CAs in either environment. It is published as an
anchor and installed as one; whether anything is issued beneath it is the
publisher's business, and a store that dropped it for being empty would be
answering a question it was not asked.

Both stores are **flat**, unlike `certval_stores_fpki`'s cross-certified mesh:
every CA is issued directly by one of that environment's own roots, so every
serialized partial path is a single certificate. The CAs are the usual DoD
families — ID, Email, SW (software/PIV-auth), and Derility (derived credential)
— with the operational-test store carrying both `DOD JITC …` and `DOD OM …`
issuers, including their `AE` variants.

## Where the material comes from

`inputs/DoD.ir4` and `inputs/JITC.ir4` are the artifacts of record. They are DoD
InstallRoot streams — RFC 4073 collections of separately signed RFC 5934 TAMP
updates, published at `https://crl.gds.disa.mil/pke/config/` — and everything in
`roots/` and `cas/` is generated from them. A signed message is a better record
of what DoD publishes than a folder of files someone collected by hand, which is
what these directories used to be.

`DoD.ir4` maps to the production environment and `JITC.ir4` to operational test.
Only the `Root` and `CA` messages are read, and only their `add` entries: the
streams are used here as a trust store rather than applied as updates, so there
is no prior state for `remove` and `change` to act on. The
`RemoveCertificateHintList` message is skipped for that reason and one sharper
one — its entries are structurally `add`, but each shares a public key with a
`remove` elsewhere in the same file, so reading it would install exactly the
certificates being withdrawn.

`JITC.ir4` also publishes NSS and ECA anchors, which are different PKIs and
belong to different crates. The generator selects the DoD population by anchor,
takes the CAs that chain to it, and logs the rest rather than dropping it
silently.

**Signatures are not verified yet.** Requiring a good signature belongs in
generation, where the anchors are already in hand, and it is not built. Until it
is, treat the streams as material of stated rather than proven provenance.

The generated DER ships beside each `.cbor` (`cas/prod/`, `cas/om/`), and
`conformance::check_generator_inputs` asserts it still matches what the store
carries — nothing `include_bytes!`es those files, so without that check they
would drift in silence. Byte-for-byte reproducibility is not a property to rely
on: the generator folds certificates in the order the filesystem lists them, so a
regeneration elsewhere can reorder the buffers without changing the material. The
set is what matters, and `check_generator_inputs` is what asserts it.

The anchors in `roots/prod/` and `roots/om/` *are* `include_bytes!`d, one line
per file in `src/lib.rs`, and `conformance::check_root_inputs` asserts the
directory and that list agree. The compiler checks only half of it: removing a
`.der` breaks the build, while adding one leaves a file that ships and reads as
an anchor without being in the trust set.

The production anchors can be corroborated against a public source: the DoD Root
CA 3 and DoD Root CA 6 public keys embedded here match those in cross-certificates
carried in the GSA FPKI crawler bundle — the same bundle `certval_stores_fpki` is
built from — issued by DoD Interoperability Root CA 2 (checked 2026-08-13). DoD
Root CA 4, DoD Root CA 5 and the JITC roots do not appear in it.

Filenames under `cas/` are kept as they were where the certificate itself is
unchanged, so a refresh diff shows the certificates that moved rather than a wall
of renames. New certificates are named from their common name. The anchors under
`roots/` are named by the generator throughout, since their `include_bytes!` list
is rewritten with them.

## Refreshing

Replace the stream in `inputs/` with a freshly downloaded one and regenerate.
Both `roots/<env>/` and `cas/<env>/` are output, so nothing there is edited by
hand:

```sh
# redhound/certval-store-gen
certval-store-gen installroot --stream inputs/DoD.ir4  --population dod \
    --provider-dir . --env prod --dry-run   # read the diff first
certval-store-gen installroot --stream inputs/DoD.ir4  --population dod \
    --provider-dir . --env prod

certval-store-gen installroot --stream inputs/JITC.ir4 --population dod \
    --provider-dir . --env om
```

`--dry-run` reports what would change by subject and serial and writes nothing,
which is the form to run first: a re-issued certificate keeps its subject and its
key, so a serial is what tells you it moved. Writing also prints the
`include_bytes!` list for the environment, which goes into `src/lib.rs` — the
anchors are embedded as DER rather than read from the store, because
`reqwest::Certificate::from_der` takes only a bare `Certificate`.

Then update `EXPECTED_NIPR_INTERMEDIATES` / `EXPECTED_OM_NIPR_INTERMEDIATES` in
`tests/tests.rs` if a count moved, and re-run
`cargo test -p certval_stores_nipr --all-features`. Those counts exist to make a
change in trust material show up in review rather than arrive silently.

## Sanity check against pittv3

```sh
pittv3 -b cas/prod/prod.cbor -t roots/prod --list-partial-paths
pittv3 -b cas/om/om.cbor     -t roots/om   --list-partial-paths
```

For the committed material these report `41 certificates yielded: 41 paths with
1 certificate` and `53 certificates yielded: 53 paths with 1 certificate`. A CA
that appears in no path is unreachable to an offline consumer however
well-connected it looks — which is why generation disables the time of interest:
an expired CA that was serialized without a path would be missing from a
validation run against an earlier time, when it was current.
