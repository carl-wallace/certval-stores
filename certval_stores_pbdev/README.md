# certval_stores_pbdev

Development trust store for certval — the Purebred development environment,
anchored at the DoD Engineering roots.

## What this crate carries

| Feature | Constant (id) | Anchors | CA store |
|---------|---------------|---------|----------|
| `dev` (default) | `PUREBRED_DEV` (`dod_purebred_dev`) | DoD ENG Root CA 6 | intermediates and partial paths |

With `dev` disabled the crate builds and its provider yields no entries.

The store is **flat**: all four CAs — `DOD PBDEV DERILITY CA-3`,
`DOD PBDEV EMAIL CA-71`, `DOD PBDEV ID CA-71`, `DOD PBDEV SW CA-75`, shipped as
`PB_*.der` — are issued directly by DoD ENG Root CA 6, so every serialized
partial path is a single certificate.

## The embedded material

The DER inputs the store was generated from ship beside the `.cbor` (`cas/dev/`),
and `conformance::check_generator_inputs` asserts they still match what the store
carries — nothing `include_bytes!`es those files, so without that check they
would drift in silence. Regenerating from them reproduced the committed
`dev.cbor` byte for byte (verified 2026-08-13), though that is not a property to
rely on: the generator folds certificates in the order the filesystem lists them,
so a regeneration elsewhere can reorder the buffers without changing the
material. The set is what matters, and `check_generator_inputs` is what asserts
it.

The anchors in `roots/dev/` *are* `include_bytes!`d, one line per file in
`src/roots_dev.rs`, which the generator writes with the directory, and `conformance::check_root_inputs` asserts the directory and that
list agree. The compiler checks only half of it: removing a `.der` breaks the
build, while adding one leaves a file that ships and reads as an anchor without
being in the trust set.

This is development material: it turns over when the dev environment is rebuilt,
which is more often than the production stores move, so the refresh path below
matters more here than the anchor count suggests. The ENG roots are not published
anywhere public, so unlike the production DoD roots there is no external source
to check them against — the conformance and validation tests are the check. For
the same reason the entry reports no publication date: there is no publisher to
state one. It gives a collection date only, and a refresh has to move it by hand,
since the `local` adapter below is handed a folder rather than a dated artifact.

## Using it

Load a store into a certval `PkiEnvironment` with `certval_stores_core`, naming the store by its
constant:

```rust
# #[cfg(feature = "dev")] {
use certval::PkiEnvironment;
use certval_stores_core::prepare_certval_environment;

let mut pe = PkiEnvironment::default();
pe.populate_5280_pki_environment();
prepare_certval_environment(
    &[certval_stores_pbdev::provider()],
    &mut pe,
    certval_stores_pbdev::PUREBRED_DEV,
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

With an ordinary requirement such as `certval_stores_pbdev = "1.0"`, `cargo update` takes every
1.x release, including a minor release that adds or removes trust anchors. With
`certval_stores_pbdev = "~1.0"`, `cargo update` takes 1.0.1, 1.0.2 and so on, which change only
intermediate CA certificates, partial paths or dates, and does not take 1.1.0, so the trust anchors
stay those of 1.0 until the requirement is changed to `~1.1`. Each release's changes are listed in
`CHANGELOG.md`.

## Refreshing

```sh
# certval-store-gen, a member of this workspace: cargo run -p certval-store-gen --
certval-store-gen --out-dir ./out local --tas roots/dev --cas cas/dev
cp out/ca.cbor cas/dev/dev.cbor
```

It reports how many trust anchors and intermediates it read. `--cas` may point at the folder
that already holds the `.cbor`; non-certificate files are ignored. The `ta.cbor`
it also writes is unused here — the anchors are embedded as DER, because
`reqwest::Certificate::from_der` takes only a bare `Certificate`.

Then update `EXPECTED_DEV_INTERMEDIATES` in `tests/tests.rs` if the count moved,
and re-run `cargo test -p certval_stores_pbdev --all-features`.

## Sanity check against pittv3

```sh
pittv3 -b cas/dev/dev.cbor -t roots/dev --list-partial-paths
```

Every certificate in the store should yield a path of one certificate, each
rooted at DoD ENG Root CA 6.
