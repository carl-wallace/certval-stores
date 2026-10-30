# certval_stores_nipr

![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

NIPR (DoD PKI) trust stores for certval — the production and operational-test
(JITC) environments.

## What this crate carries

| Feature | Constant (id) | Anchors | CA store |
|---------|---------------|---------|----------|
| `nipr` | `NIPR_PROD` (`dod_nipr_prod`) | DoD Root CA 3, 4, 5, 6 | intermediates and partial paths |
| `om_nipr` | `NIPR_OM` (`dod_nipr_om`) | DoD JITC Root CA 3, 4, 5, 6 | intermediates and partial paths |
| `nipr_interop` | `NIPR_INTEROP` (`dod_nipr_interop`) | DoD Root CA 3, 4, 5, 6 and DoD Interoperability Root CA 2 | intermediates and partial paths, reaching ECA and the federal mesh |
| `nipr_cceb_interop` | `NIPR_CCEB_INTEROP` (`dod_nipr_cceb_interop`) | DoD Root CA 3, 4, 5, 6 and US DoD CCEB Interoperability Root CA 2 | intermediates and partial paths, reaching allied national PKIs |

None is on by default, so a consumer elects the environment(s) it needs. With none
enabled the crate builds and its provider yields no entries.

| Anchor | Key | Expires |
|--------|-----|---------|
| DoD Root CA 3 | RSA 2048, sha256 | 2029-12-30 |
| DoD Root CA 4 | ECDSA P-256, sha256 | 2032-07-25 |
| DoD Root CA 5 | ECDSA P-384, sha384 | 2041-06-14 |
| DoD Root CA 6 | RSA 4096, sha384 | 2053-01-24 |
| DoD JITC Root CA 3 | RSA 2048, sha256 | 2029-12-30 |
| DoD JITC Root CA 4 | ECDSA P-256, sha256 | 2032-05-31 |
| DoD JITC Root CA 5 | ECDSA P-384, sha384 | 2041-05-31 |
| DoD JITC Root CA 6 | RSA 4096, sha384 | 2053-01-11 |

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

`provenance/<env>/published.txt` and `provenance/<env>/collected.txt` carry the two
dates the entries report, written by the generator from the stream itself:
`published` is `TSTInfo.genTime` from the verified RFC 3161 timestamp on the
InstallRoot messages read — DoD asserts no `signingTime` of its own — and `collected`
the day the stream was fetched. They are files rather than literals in `src/lib.rs`
so that a refresh moves them with the material. The gap between them is the point —
`JITC.ir4` was signed **2025-02-03** and fetched **2026-09-11**, so a consumer told
only when the store was built would read nineteen months of DoD anchor changes as
freshness.

**The streams are verified at generation**, where the anchors are already in hand:
each member's signature, the timestamp over that signature, the signer's chain
to a DoD root pinned in `certval-store-gen/anchors/` under the code-signing EKU, and
the revocation status of every certificate in that chain, read from the OCSP responses
the stream staples — all at the time the timestamp establishes, which is when those
responses were current.

Your build fetches nothing: the timestamp authority's own chain, which nothing staples,
is checked against a responder only by `verify --stream` and by a source checkout that is
already refreshing its inputs. CI runs that gate on these committed bytes. A member that fails refuses the whole stream, so
what these stores carry is material of proven rather than stated provenance.
`cargo run -p certval-store-gen -- verify --stream inputs/*.ir4` re-runs those checks
against the committed files on their own, and CI does.

The generated DER ships beside each `.cbor` (`cas/prod/`, `cas/om/`), and
`conformance::check_generator_inputs` asserts it still matches what the store
carries — nothing `include_bytes!`es those files, so without that check they
would drift in silence. Byte-for-byte reproducibility is not a property to rely
on: the generator folds certificates in the order the filesystem lists them, so a
regeneration elsewhere can reorder the buffers without changing the material. The
set is what matters, and `check_generator_inputs` is what asserts it.

The anchors in each `roots/<env>/` *are* `include_bytes!`d, one line per file in
`src/roots_<env>.rs`, which the generator writes with the directory, and `conformance::check_root_inputs` asserts the
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

## Using it

Load a store into a certval `PkiEnvironment` with `certval_stores_core`, naming the store by its
constant:

```rust
# #[cfg(feature = "nipr")] {
use certval::PkiEnvironment;
use certval_stores_core::prepare_certval_environment;

let mut pe = PkiEnvironment::default();
pe.populate_5280_pki_environment();
prepare_certval_environment(
    &[certval_stores_nipr::provider()],
    &mut pe,
    certval_stores_nipr::NIPR_PROD,
)?;
# }
# Ok::<(), certval::Error>(())
```

The trust material is embedded as it was committed, and nothing in this package lets you re-check
where it came from: using it means trusting this crate's publisher, and the review each refresh
received before it was merged. How the material is obtained and authenticated is described in this
README and in the repository's
[MAINTENANCE.md](https://github.com/carl-wallace/certval-stores/blob/main/MAINTENANCE.md).

## Versioning

This crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html), and the version
number also says what changed in the trust material:

- A **patch** release (1.0.0 to 1.0.1) changes intermediate CA certificates, partial paths, or a
  store's dates or label. No store's trust anchors change.
- A **minor** release (1.0.x to 1.1.0) adds or removes trust anchors in a store, adds a store, or
  adds to the API without breaking code that uses it.
- A **major** release (1.x to 2.0.0) changes the API in a way that breaks code that uses it, for
  example by removing a store along with its feature and constant.

With an ordinary requirement such as `certval_stores_nipr = "1.0"`, `cargo update` takes every
1.x release, including a minor release that adds or removes trust anchors. With
`certval_stores_nipr = "~1.0"`, `cargo update` takes 1.0.1, 1.0.2 and so on, which change only
intermediate CA certificates, partial paths or dates, and does not take 1.1.0, so the trust anchors
stay those of 1.0 until the requirement is changed to `~1.1`. Each release's changes are listed in
`CHANGELOG.md`.

## Refreshing

A scheduled workflow does it: `.github/workflows/refresh.yml` asks the publisher for each stream,
regenerates the environments whose stream moved, and opens a pull request. CI on that pull request
is expected to fail — the tests pin the counts and a digest of the certificate set, which is what
makes a change in trust material announce itself (see `MAINTENANCE.md`).

Locally it is two commands. `refresh` fetches a stream and replaces `inputs/DoD.ir4` or
`inputs/JITC.ir4` when the publisher's own date is newer; a stream published older than the
committed one is refused as a rollback rather than taken:

```sh
# certval-store-gen, a member of this workspace: cargo run -p certval-store-gen --
certval-store-gen refresh --url https://crl.gds.disa.mil/pke/config/DoD.ir4 \
    --into inputs/DoD.ir4 --population dod
```

Generation is a separate run, and is also how to take a stream downloaded by hand: replace the one
in `inputs/` and regenerate. One stream can feed more than one environment, so it runs once per
environment. `roots/<env>/`, `cas/<env>/` and `src/roots_<env>.rs` are output, so nothing there is
edited by hand:

```sh
# certval-store-gen, a member of this workspace: cargo run -p certval-store-gen --
certval-store-gen installroot --stream inputs/DoD.ir4  --population dod \
    --provider-dir . --env prod --dry-run   # read the diff first
certval-store-gen installroot --stream inputs/DoD.ir4  --population dod \
    --provider-dir . --env prod

certval-store-gen installroot --stream inputs/JITC.ir4 --population dod \
    --provider-dir . --env om
```

`--dry-run` reports what would change by subject and serial and writes nothing,
which is the form to run first: a re-issued certificate keeps its subject and its
key, so a serial is what tells you it moved. Writing also rewrites
`src/roots_<env>.rs`, the `include_bytes!` list that embeds the environment's
anchors — as DER rather than read from the store, because
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

Every certificate in each store should yield a path of one certificate: the DoD
intermediates are issued directly by the roots. A CA
that appears in no path is unreachable to an offline consumer however
well-connected it looks — which is why generation disables the time of interest:
an expired CA that was serialized without a path would be missing from a
validation run against an earlier time, when it was current.

[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.88+-blue.svg
