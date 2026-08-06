# certval-stores

A family of **certval trust-store providers**. Each provider crate embeds the
trust anchors and CA stores (serialized certval `CertSource` CBOR — intermediate
CAs + partial certification paths) for one or more environments, and
[`certval_stores_core`] composes any set of providers into a certval
`PkiEnvironment` or a configured `reqwest` client.

This workspace replaces the former single `pb_pki` crate. It splits the trust
material by trust community so the sensitive members can live in separate
(private) repositories, while sharing one copy of the logic.

## Crates

| Crate | Repo | Environments (features) |
|-------|------|-------------------------|
| `certval_stores_core`  | public `carl-wallace/certval-stores` | — (the provider contract + plumbing) |
| `certval_stores_nipr`  | public `carl-wallace/certval-stores` | `om_nipr`, `nipr` (DoD PKI) |
| `certval_stores_pbdev` | public `carl-wallace/certval-stores` | `dev` (Purebred development) |
| `certval_stores_sipr`  | **private** `RedHoundSoftware/certval_store_sipr` | `om_sipr`, `sipr` (NSS PKI) |

New communities (e.g. FPKI, webpki) are added by writing another provider crate
that implements `TrustStoreProvider` — `certval_stores_core` needs no changes.

## The provider contract

```rust
pub struct StoreEntry {
    pub env: &'static str,                       // "NIPR", "OM_SIPR", "DEV", …
    pub roots: &'static [&'static [u8]],         // trust-anchor DERs
    pub cert_store_cbor: Option<&'static [u8]>,  // serialized certval CertSource (CBOR)
}

pub trait TrustStoreProvider {
    fn entries(&self) -> Vec<StoreEntry>;
}
```

Each provider crate exposes `provider() -> &'static dyn TrustStoreProvider`.
Providers *augment* the core functions by being passed in explicitly — the core
has no built-in knowledge of any environment.

`certval_stores_core` offers the same three entry points the old `pb_pki` did,
now taking a `&[&dyn TrustStoreProvider]`:

- `prepare_certval_environment(providers, pe, ta_store, env)` — env-selected;
  `Err(Error::Unrecognized)` if no provider serves `env`.
- `get_roots(providers)` — every trust-anchor DER across the providers.
- `get_reqwest_client{,_rustls,_native}(providers, …)` — a client trusting them.

## Consumer wiring (retaining the pbyk feature array)

The `dev` / `om_nipr` / `nipr` / `om_sipr` / `sipr` feature array is preserved
in the consumer (`pbykcorelib`), which maps each feature to the matching
provider and assembles the provider list:

```toml
# pbykcorelib/Cargo.toml
[dependencies]
certval_stores_core  = { git = "https://github.com/carl-wallace/certval-stores.git", branch = "main" }
certval_stores_nipr  = { git = "https://github.com/carl-wallace/certval-stores.git", branch = "main", optional = true }
certval_stores_pbdev = { git = "https://github.com/carl-wallace/certval-stores.git", branch = "main", optional = true }
certval_stores_sipr  = { git = "ssh://git@github.com/RedHoundSoftware/certval_store_sipr.git", branch = "main", optional = true }

[features]
dev     = ["certval_stores_pbdev/dev"]
om_nipr = ["certval_stores_nipr/om_nipr"]
nipr    = ["certval_stores_nipr/nipr"]
om_sipr = ["certval_stores_sipr/om_sipr"]
sipr    = ["certval_stores_sipr/sipr"]
```

(Enabling a dependency's feature — e.g. `certval_stores_nipr/nipr` — implicitly
enables the optional dependency, so no separate `dep:` entry is needed.)

```rust
// pbykcorelib: assemble the providers for whatever features are enabled.
use certval_stores_core::TrustStoreProvider;

pub fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    let mut v: Vec<&'static dyn TrustStoreProvider> = Vec::new();
    #[cfg(feature = "dev")]
    v.push(certval_stores_pbdev::provider());
    #[cfg(any(feature = "om_nipr", feature = "nipr"))]
    v.push(certval_stores_nipr::provider());
    #[cfg(any(feature = "om_sipr", feature = "sipr"))]
    v.push(certval_stores_sipr::provider());
    v
}
```

Call sites change from `pb_pki::prepare_certval_environment(pe, ta, env)` to
`certval_stores_core::prepare_certval_environment(&providers(), pe, ta, env)`.

The "at least one environment must be selected" guard (formerly a
`compile_error!` in `pb_pki`) belongs in the consumer, since environment
selection now lives there.

## Note on the private SIPR provider

`certval_stores_sipr` lives in a private repo. Because it is referenced as an
optional git dependency, a consumer's committed `Cargo.lock` will name that repo
(existence + URL only, never contents), and a bare `cargo update` — or building
the `sipr`/`om_sipr` features — requires read access to it. Plain NIPR/dev
builds from a committed lock need no such access.
