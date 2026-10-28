# certval_stores_eca

ECA trust store for certval — the DoD External Certification Authority program,
under which commercial vendors issue certificates to people and systems outside
the department that need to interoperate with it.

## What this crate carries

| Feature | Constant (id) | Anchors | CA store |
|---------|---------------|---------|----------|
| `eca` | `ECA` (`dod_eca`) | ECA Root CA 4, 5 | intermediates and partial paths |

`eca` is on by default. This crate has one
environment, so there is nothing for a consumer to choose between — unlike
`certval_stores_nipr`, where neither environment is default and the consumer
says which it wants.

| Anchor | Key | Expires |
|--------|-----|---------|
| ECA Root CA 4 | RSA 2048, sha256 | 2029-12-30 |
| ECA Root CA 5 | RSA 4096, sha384 | 2050-03-12 |

The CAs are the program's vendors: IdenTrust (`IdenTrust ECA S23`, `S24`, and the
matching `Component` pair) and WidePoint (`WidePoint ECA 8`, `9`). The store is
**flat**, like `certval_stores_nipr` and unlike `certval_stores_fpki`'s
cross-certified mesh: every CA is issued directly by one of the two roots, so
every serialized partial path is a single certificate.

## Where the material comes from

`inputs/ECA.ir4` is the artifact of record. It is a DoD InstallRoot stream — an
RFC 4073 collection of separately signed RFC 5934 TAMP updates, published at
`https://crl.gds.disa.mil/pke/config/` — and everything in `roots/` and `cas/` is
generated from it.

Only the `Root` and `CA` messages are read, and only their `add` entries: the
stream is used here as a trust store rather than applied as an update, so there
is no prior state for `remove` and `change` to act on. The
`RemoveCertificateHintList` message is skipped for that reason and one sharper
one — its entries are structurally `add`, but each shares a public key with a
`remove` elsewhere in the same file, so reading it would install exactly the
certificates being withdrawn.

**The stream is verified at generation**, where the anchors are already in hand:
the member signatures, the timestamps over them, the signer's chain to a pinned DoD
root under the code-signing EKU, and the revocation status of that chain from the OCSP
responses the stream staples — all at the time those timestamps establish, which is when
those responses were current. One bad member refuses the whole stream. Your build fetches
nothing; the timestamp authority's own status is asked of a responder by `verify --stream`,
which CI runs on these committed bytes. Note whose root that is — `ECA.ir4` is signed by a
DISA code-signing certificate chaining to **DoD** Root CA 3, not to an ECA root,
which is why the anchors are pinned in the generator rather than taken from the crate
being generated.

`provenance/prod/published.txt` and `provenance/prod/collected.txt` carry the dates
the entry reports — the verified timestamp on the InstallRoot messages read, and the
day `ECA.ir4` was fetched. Both are written by the generator, so a refresh moves them
with the material rather than leaving them to a hand edit.

The generated DER ships beside the `.cbor` in `cas/prod/`, and
`conformance::check_generator_inputs` asserts it still matches what the store
carries — nothing `include_bytes!`es those files, so without that check they
would drift in silence. The anchors in `roots/prod/` *are* `include_bytes!`d, one
line per file in `src/roots_prod.rs`, which the generator writes with the directory, and `conformance::check_root_inputs` asserts the
directory and that list agree. The compiler checks only half of that: removing a
`.der` breaks the build, while adding one leaves a file that ships and reads as
an anchor without being in the trust set.

### The operational-test anchors are elsewhere

`ECA JITC Root CA 4` and `ECA JITC Root CA 5` are published in `JITC.ir4`, the
operational-test stream, alongside the DoD and NSS material that stream carries.
They are not in this crate: that stream publishes no ECA CAs at all, so a test
environment here would be two anchors and nothing beneath them. Add it if a
consumer needs to validate ECA test certificates — `certval_stores_fpki`'s
`fpki_legacy` is the precedent for an anchors-only entry.

## Using it

Load a store into a certval `PkiEnvironment` with `certval_stores_core`, naming the store by its
constant:

```rust
# #[cfg(feature = "eca")] {
use certval::{PkiEnvironment, TaSource};
use certval_stores_core::prepare_certval_environment;

let mut pe = PkiEnvironment::default();
pe.populate_5280_pki_environment();
let mut ta_store = TaSource::new();
prepare_certval_environment(
    &[certval_stores_eca::provider()],
    &mut pe,
    &mut ta_store,
    certval_stores_eca::ECA,
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

With an ordinary requirement such as `certval_stores_eca = "1.0"`, `cargo update` takes every
1.x release, including a minor release that adds or removes trust anchors. With
`certval_stores_eca = "~1.0"`, `cargo update` takes 1.0.1, 1.0.2 and so on, which change only
intermediate CA certificates, partial paths or dates, and does not take 1.1.0, so the trust anchors
stay those of 1.0 until the requirement is changed to `~1.1`. Each release's changes are listed in
`CHANGELOG.md`.

## Refreshing

A scheduled workflow does it: `.github/workflows/refresh.yml` asks the publisher for the stream,
regenerates `roots/`, `cas/` and `provenance/` when it moved, and opens a pull request. CI on that
pull request is expected to fail — the pinned counts below are what make a change in trust material
announce itself.

Locally it is two commands. `refresh` fetches the stream and replaces `inputs/ECA.ir4` when the
publisher's own date is newer; a stream published older than the committed one is refused as a
rollback rather than taken:

```sh
# certval-store-gen, a member of this workspace: cargo run -p certval-store-gen --
certval-store-gen refresh --url https://crl.gds.disa.mil/pke/config/ECA.ir4 \
    --into inputs/ECA.ir4 --population eca
```

Generation is a separate run, and is also how to take a stream downloaded by hand: replace the one
in `inputs/` and regenerate. Both `roots/prod/` and `cas/prod/` are output, so nothing there is
edited by hand:

```sh
# certval-store-gen, a member of this workspace: cargo run -p certval-store-gen --
certval-store-gen installroot --stream inputs/ECA.ir4 --population eca \
    --provider-dir . --env prod --dry-run   # read the diff first
certval-store-gen installroot --stream inputs/ECA.ir4 --population eca \
    --provider-dir . --env prod
```

`--dry-run` reports what would change by subject and serial and writes nothing,
which is the form to run first: a re-issued certificate keeps its subject and its
key, so a serial is what tells you it moved. Writing also rewrites
`src/roots_prod.rs`, the `include_bytes!` list that embeds the anchors — as DER
rather than read from the store, because `reqwest::Certificate::from_der` takes
only a bare `Certificate`.

`--population eca` is what selects this material. A stream can publish more than
one PKI: `JITC.ir4` carries DoD, NSS and ECA anchors together, and the generator
reports the populations it is not writing rather than dropping them silently.

Then update `EXPECTED_INTERMEDIATES` in `tests/tests.rs` if the count moved, and
re-run `cargo test -p certval_stores_eca --all-features`. That count exists to
make a change in trust material show up in review rather than arrive silently.

## Sanity check against pittv3

```sh
pittv3 -b cas/prod/prod.cbor -t roots/prod --list-partial-paths
```

Every certificate in the store should yield a path, each of one certificate: the
ECA intermediates are issued directly by the roots. A CA that appears in no path is unreachable to an offline
consumer however well-connected it looks.
