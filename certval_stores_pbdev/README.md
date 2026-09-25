# certval_stores_pbdev

Development trust store for certval — the Purebred development environment,
anchored at the DoD Engineering roots.

## What this crate carries

| Feature | Env | Anchors | CA store |
|---------|-----|---------|----------|
| `dev` (default) | `DEV` | 2 — DoD ENG Root CA 3, DoD ENG Root CA 6 | 4 intermediates, 4 partial paths |

With `dev` disabled the crate builds and its provider yields no entries.

The store is **flat**: all four CAs — `DOD PBDEV DERILITY CA-3`,
`DOD PBDEV EMAIL CA-71`, `DOD PBDEV ID CA-71`, `DOD PBDEV SW CA-75`, shipped as
`PB_*.der` — are issued directly by DoD ENG Root CA 6, so every serialized
partial path is a single certificate.

**DoD ENG Root CA 3 expired on 2025-10-05** and issues none of the four CAs. It
is retained as an anchor for paths minted before it lapsed; the generator and
certval both log a "not valid at indicated time of interest" line for it, which
is expected rather than a defect. The conformance checks judge material on
structure with the time of interest disabled, so this reads as a store due for
a decision — keep the expired anchor or drop it — not as a broken one.

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
`src/lib.rs`, and `conformance::check_root_inputs` asserts the directory and that
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

## Refreshing

```sh
# certval-store-gen, a member of this workspace: cargo run -p certval-store-gen --
certval-store-gen --out-dir ./out local --tas roots/dev --cas cas/dev
cp out/ca.cbor cas/dev/dev.cbor
```

It reports `2 trust anchors, 4 intermediates`. `--cas` may point at the folder
that already holds the `.cbor`; non-certificate files are ignored. The `ta.cbor`
it also writes is unused here — the anchors are embedded as DER, because
`reqwest::Certificate::from_der` takes only a bare `Certificate`.

Then update `EXPECTED_DEV_INTERMEDIATES` in `tests/tests.rs` if the count moved,
and re-run `cargo test -p certval_stores_pbdev --all-features`.

## Sanity check against pittv3

```sh
pittv3 -b cas/dev/dev.cbor -t roots/dev --list-partial-paths
```

For the committed material this reports `4 certificates yielded: 4 paths with
1 certificate`, each rooted at DoD ENG Root CA 6.
