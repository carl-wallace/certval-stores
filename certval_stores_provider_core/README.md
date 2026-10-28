# certval_stores_provider_core

The contract between the `certval_stores_*` trust-store crates and the code that uses
them: `StoreEntry`, the trust material for one store, and `TrustStoreProvider`, the trait
a provider crate implements to hand its entries out.

This crate is for **providers**. It has no dependencies, so a provider that depends on it
alone links neither certval nor an HTTP client, and its version moves only when its own
material or this contract does.

**Consumers** depend on [`certval_stores_core`](https://crates.io/crates/certval_stores_core)
instead. It re-exports both types and turns a set of providers into a certval
`PkiEnvironment`, a serialized store or a configured `reqwest` client. Because the
re-export is the same trait, a provider built against this crate's 1.x fits any version
of `certval_stores_core` that depends on it.

## Building an entry

`StoreEntry` is `#[non_exhaustive]`, so fields can be added without a new major
version. Build one with `StoreEntry::new` and the `with_*` setters, all of which are
`const`:

```rust
use certval_stores_provider_core::{StoreEntry, TrustStoreProvider};

static ROOTS: &[&[u8]] = &[];

pub const EXAMPLE: &str = "example";

pub struct ExampleStores;

impl TrustStoreProvider for ExampleStores {
    fn entries(&self) -> Vec<StoreEntry> {
        vec![StoreEntry::new(EXAMPLE, "Example PKI", ROOTS)
            .with_published("2026-10-28")
            .with_collected("2026-10-28")]
    }
}
```

## Versioning

This crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). `StoreEntry` is
`#[non_exhaustive]`, so code outside this crate builds an entry with `StoreEntry::new` rather than
a struct literal, and a new field can be added in a minor release without breaking any provider. Each release's changes are listed
in `CHANGELOG.md`.
