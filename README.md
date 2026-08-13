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
| `certval_stores_fpki`  | public `carl-wallace/certval-stores` | `fpki`, `fpki_legacy` (Federal PKI) |
| `certval_stores_nipr`  | public `carl-wallace/certval-stores` | `om_nipr`, `nipr` (DoD PKI) |
| `certval_stores_pbdev` | public `carl-wallace/certval-stores` | `dev` (Purebred development) |
| `certval_stores_sipr`  | **private** `RedHoundSoftware/certval_store_sipr` | `om_sipr`, `sipr` (NSS PKI) |

New communities (e.g. webpki/Mozilla roots) are added by writing another provider
crate that implements `TrustStoreProvider` — `certval_stores_core` needs no
changes. What such a crate owes its consumers is spelled out under
[What a trust store must satisfy](#what-a-trust-store-must-satisfy), and enforced
by the conformance harness described there.

`certval_stores_fpki` is the one provider whose material is a dated snapshot
rather than a constant: the FPKI mesh is republished by the FPKI crawler whenever
it changes, so that crate documents its own refresh procedure.

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
- `get_reqwest_client{,_rustls,_native}(providers, …)` — a client trusting them,
  behind the default-on `reqwest-client` feature.

### The `reqwest-client` feature

`reqwest` is about 60% of this crate's dependency graph — 169 crates become 77
without it, tokio, hyper and `url -> idna -> icu` among them — and the icu crates
impose a rustc 1.86 floor that certval itself (MSRV 1.85) does not. It is on by
default, because the consumers that exist use those constructors. Turn it off to
embed trust material without an HTTP client:

```toml
certval_stores_nipr = { git = "…", default-features = false, features = ["nipr"] }
```

**wasm consumers must turn it off**: reqwest's wasm backend is a thin `fetch()`
wrapper with no `Identity`, no `Certificate`, and no `timeout` or
`add_root_certificate` on its `ClientBuilder`, so the feature does not compile for
`wasm32-*` at all. Enabling it there fails with one explanatory `compile_error!`
rather than a cascade of missing methods. Each provider crate forwards the switch
(`reqwest-client = ["certval_stores_core/reqwest-client"]`) — without that
forwarding a consumer could not turn it off at all, features being additive.

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

## What a trust store must satisfy

A provider is not just a bag of certificates: certval, pittv3 and the `reqwest`
clients built here each place requirements on the embedded material, and most of
those requirements fail *quietly* when they are not met. certval logs and
continues past an anchor it cannot parse; `get_reqwest_client` does the same;
partial paths filed under the wrong key are simply never found. In every one of
those cases the store loads, the counts look right, and paths stop being built.

So the expectations below are the contract, and
`certval_stores_core::conformance` (behind the `test-util` feature) is the
executable form of it. Every provider — the ones here, the private SIPR one, and
any store contributed later — is expected to pass it. It lives in the core crate
so a check added once applies to every trust community, and so the private
providers get the coverage without a copy of the logic in a private repository.

**Trust anchors.**

- Each is a DER `Certificate`. RFC 5914 permits `[1] tbsCert` and `[2] taInfo`
  as well, and certval would parse them, but `reqwest::Certificate::from_der`
  accepts only a `Certificate` — so anything else builds paths normally while
  silently dropping out of every TLS client this crate configures.
- Each parses on *both* legs — as an x509-cert certificate and as a
  `reqwest::Certificate` — since a root that fails either is skipped with a log
  line rather than a build failure. The reqwest half of that check is compiled
  only under the `reqwest-client` feature; the expectation is not conditional, so
  run the suite with default features before publishing material.
- Each is one certval can actually use, not merely one it counted.
  `TaSource::initialize` skips a buffer that is not a usable `TrustAnchorChoice`,
  and `index_tas` leaves out anchors whose key identifier cannot be computed, so
  an installed anchor can still be unusable.
- No two anchors share a key identifier while carrying different public keys.
  certval poisons such a key identifier across every registered source and
  refuses to anchor on it, so a collision disables *both* anchors — including
  across providers a consumer happens to load together.
- No anchor is embedded twice, and every `env` label is usable verbatim as the
  match key `prepare_certval_environment` compares against.

**CA stores.** An entry may carry none (an anchors-only provider, e.g. a
webpki-style root list, or `certval_stores_fpki`'s retired G1 environment). One
that does carry a store must satisfy:

- it deserializes, initializes, is non-empty, and every buffer decodes;
- the partial paths serialized beside those buffers hold together: every CA
  appears in one, every path starts at a CA one of that entry's own anchors
  issued and is filed under its own leaf CA's key identifier (which is how
  `get_paths_for_target` finds it), every index names a buffer the store carries
  (certval indexes its parsed-certificate vector with these directly, so a stale
  index panics in the consumer), and row *i* holds paths of *i+1* certificates;
- certval can actually build a path for every CA in it, via the same
  `get_paths_for_target` call a consumer makes. Connectivity is not the bar. An
  offline consumer uses the serialized path set, so a CA in no path is
  unreachable however well-connected it looks, and a path rooted at an anchor
  that has since been purged still deserializes while leading nowhere;
- and at least one of those paths **validates** — signatures verified from the
  anchor down. Everything above reads the material; this asks certval whether it
  is cryptographically sound, which is what catches a CA re-keyed without
  regenerating the store, or a cross-certificate that no longer matches the
  issuer it names.

**Crypto is the provider's business, not the core's.** Validation is the one
expectation the harness cannot carry out on a provider's behalf, because it
cannot know what a community signs with. certval installs signature verifiers by
feature — RSA behind `rsa`, Ed25519 behind `eddsa`, ML-DSA/SLH-DSA/composite
behind `pqc`, **none of them on by default** — and a verifier that is not
compiled in returns `Unrecognized`, so a provider that omits the feature its own
material needs sees every CA reported as unvalidatable rather than a clear error
about the missing algorithm. So `check_paths_validate` takes the environment from
the caller: the provider crate enables the certval features its algorithms need
and passes an environment carrying them. The DoD stores here are RSA-signed,
which is why each provider crate's dev-dependency reads
`certval = { …, features = ["std", "rsa"] }`.

**Composition.** Providers are combined by the consumer, so each must also be
usable *beside* the others: no environment label claimed by two providers, and
no anchor key-identifier collision across the family. `check_providers_compose`
covers this, and `certval_stores_core/tests/composition.rs` runs it over every
public provider — add a new one to that list.

**Judged on structure, not on today's date.** Every check runs with the time of
interest disabled, so an expired-but-well-formed CA reads as a store due for
refresh rather than as a corrupt one, and CI does not turn red on a Tuesday.
Freshness is a separate question, answered by each store's refresh procedure.

### Adding a provider

1. Implement `TrustStoreProvider`, returning one `StoreEntry` per environment,
   and expose `provider() -> &'static dyn TrustStoreProvider`.
2. Add the harness and assert conformance:

   ```toml
   [dev-dependencies]
   certval_stores_core = { path = "…", features = ["test-util"] }
   ```

   ```rust
   #[test]
   fn provider_is_conformant() {
       conformance::assert_conformant(certval_stores_mine::provider());
   }
   ```

3. Validate the material, supplying the crypto yourself:

   ```toml
   [dev-dependencies]
   certval = { git = "…", features = ["std", "rsa"] }  # + eddsa / pqc as needed
   ```

   ```rust
   #[test]
   fn paths_validate_under_the_embedded_anchors() {
       conformance::assert_paths_validate(
           certval_stores_mine::provider(),
           conformance::default_environment,
           &conformance::structural_validation_settings(),
       );
   }
   ```

   `assert_conformant` deliberately does not include this — it has no environment
   to validate against — so a provider that skips this step is not covered by it.

4. Pin your own counts — anchors per environment, CAs per store — so material
   cannot be added or dropped silently. The shared checks confirm the material
   is *coherent*; only a count confirms it is the material you meant to ship.
5. If the store generator's `.der` inputs ship beside the `.cbor`, call
   `conformance::check_generator_inputs`. Nothing `include_bytes!`es those files,
   so without it they drift from the store in silence.
6. Forward the client switch, so a consumer can still turn the HTTP stack off:

   ```toml
   [dependencies]
   certval_stores_core = { path = "…", default-features = false }

   [features]
   default = ["…your environments…", "reqwest-client"]
   reqwest-client = ["certval_stores_core/reqwest-client"]
   ```

   Skipping this does not break your crate — it breaks everyone else's ability to
   opt out, since features are additive and your default re-enables the core's.
7. Add the provider to `certval_stores_core/tests/composition.rs`.
8. Document where the material came from and how to refresh it, as
   `certval_stores_fpki` does — a store nobody can regenerate is a store that
   expires.

Tests are gated only on the features they need, never on the *absence* of a
feature, so `cargo test --all-features` runs the whole suite for a crate.

## Note on the private SIPR provider

`certval_stores_sipr` lives in a private repo. Because it is referenced as an
optional git dependency, a consumer's committed `Cargo.lock` will name that repo
(existence + URL only, never contents), and a bare `cargo update` — or building
the `sipr`/`om_sipr` features — requires read access to it. Plain NIPR/dev
builds from a committed lock need no such access.
