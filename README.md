# certval-stores

A family of **certval trust-store providers**. Each provider crate embeds the
trust anchors and CA stores (serialized certval `CertSource` CBOR — intermediate
CAs + partial certification paths) for one or more environments, and
`certval_stores_core` composes any set of providers into a certval
`PkiEnvironment` or a configured `reqwest` client.

This workspace replaces the former single `pb_pki` crate. It splits the trust
material by trust community so the sensitive members can live in separate
(private) repositories, while sharing one copy of the logic.

## Crates

| Crate | Repo | Environments (features) |
|-------|------|-------------------------|
| [`certval_stores_core`](certval_stores_core/README.md)  | public `carl-wallace/certval-stores` | — (the provider trait + plumbing) |
| [`certval_stores_eca`](certval_stores_eca/README.md)    | public `carl-wallace/certval-stores` | `eca` (DoD External Certification Authority) |
| [`certval_stores_fpki`](certval_stores_fpki/README.md)  | public `carl-wallace/certval-stores` | `fpki`, `fpki_legacy` (Federal PKI) |
| [`certval_stores_nipr`](certval_stores_nipr/README.md)  | public `carl-wallace/certval-stores` | `om_nipr`, `nipr` (DoD PKI) |
| [`certval_stores_pbdev`](certval_stores_pbdev/README.md) | public `carl-wallace/certval-stores` | `dev` (Purebred development) |
| [`certval_stores_wcf`](certval_stores_wcf/README.md)    | public `carl-wallace/certval-stores` | `wcf` (DoD WCF PKI) |
| `certval_stores_sipr`  | **private** `RedHoundSoftware/certval_store_sipr` | `om_sipr`, `sipr` (NSS PKI) |

Each provider crate's README records what material it carries, where that
material came from, and how to refresh it. `certval_stores_fpki` is the one whose
material is a dated snapshot rather than a constant: the FPKI mesh is republished
by the FPKI crawler whenever it changes.

`certval_stores_nipr`, `certval_stores_eca` and `certval_stores_wcf` keep the DoD
InstallRoot stream they are generated from, in `inputs/*.ir4` — one per published
stream: `DoD.ir4` and `JITC.ir4`, `ECA.ir4`, `WCF.ir4`. The stream is a set of signed RFC 5934
messages, so it records what DoD published rather than what someone collected, and
regenerating from it is how those crates are refreshed.

## Where the rest of the documentation lives

The provider API and the requirements a store has to meet are documented in the
core crate, so that `cargo doc` and docs.rs carry them — this file does not reach
either:

- **[The provider API](certval_stores_core/README.md#the-provider-api)** —
  `StoreEntry`, `TrustStoreProvider`, the three entry points, and the
  `reqwest-client` feature.
- **[What a trust store must satisfy](certval_stores_core/README.md#what-a-trust-store-must-satisfy)**
  — the expectations on embedded material, nearly all of which fail *quietly*
  when unmet, and the `conformance` harness that is their executable form.
- **[Adding a provider](certval_stores_core/README.md#adding-a-provider)** — the
  checklist for a new trust community. `certval_stores_core` needs no changes to
  accept one.

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
`certval_stores_core::prepare_certval_environment(&providers(), pe, ta, id)`,
where `id` names a store rather than a Purebred environment — `certval_stores_nipr::NIPR_PROD`
rather than `"NIPR"`. A consumer that has an environment to start from maps it to
a store id once, which is also what lets a store with no environment behind it
(the Mozilla sets, the Federal PKI) be named the same way as the rest.

The "at least one environment must be selected" guard (formerly a
`compile_error!` in `pb_pki`) belongs in the consumer, since environment
selection now lives there.

## Note on the private SIPR provider

`certval_stores_sipr` lives in a private repo. Because it is referenced as an
optional git dependency, a consumer's committed `Cargo.lock` will name that repo
(existence + URL only, never contents), and a bare `cargo update` — or building
the `sipr`/`om_sipr` features — requires read access to it. Plain NIPR/dev
builds from a committed lock need no such access.
