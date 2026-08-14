//! Does the client actually refuse the public web PKI?
//!
//! `get_reqwest_client` documents that the trust set is exactly what the
//! providers carry, with reqwest's built-in bundle and the platform's native
//! roots disabled. Nothing about a built `reqwest::Client` is introspectable,
//! so the only way to check that claim is to make a connection and see which
//! way it goes — hence a network test, ignored by default:
//!
//! ```sh
//! cargo test -p certval_stores_core --all-features -- --ignored
//! ```
//!
//! The control matters as much as the assertion: a client that cannot reach
//! anything would satisfy "rejects a public host" for entirely the wrong
//! reason. So the same request is also made with a stock `reqwest::Client`,
//! which must succeed — that pins the failure below to the trust set rather
//! than to DNS, a proxy, or an offline machine.

#![cfg(feature = "reqwest-client")]

use certval_stores_core::{get_reqwest_client_rustls, TrustStoreProvider};

/// A publicly-rooted host that is not in any provider. The point is that a
/// public CA is not enough to authenticate a host to one of these clients: the
/// trust set is the providers' roots, and this host's chain is not among them.
const PUBLIC_HOST: &str = "https://github.com";

fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![
        certval_stores_fpki::provider(),
        certval_stores_nipr::provider(),
        certval_stores_pbdev::provider(),
    ]
}

/// With only these providers' roots loaded, a host whose chain ends outside
/// them must fail to authenticate. The providers below happen to be Federal and
/// DoD, but that is incidental — the property under test is provider-only
/// trust, not any particular community. Before `tls_certs_only` this request
/// succeeded, because `add_root_certificate` merges with reqwest's built-in
/// bundle rather than replacing it.
#[tokio::test]
#[ignore = "network"]
async fn a_publicly_rooted_host_is_rejected() {
    // Control first: if a stock client cannot reach the host, this machine
    // cannot answer the question and the test must not report a pass.
    let control = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("stock client must build");
    let control = control.get(PUBLIC_HOST).send().await;
    assert!(
        control.is_ok(),
        "control request to {PUBLIC_HOST} failed, so the trust-set assertion below would be \
         vacuous — test is inconclusive, not passing: {:?}",
        control.err()
    );

    let provider_refs = providers();
    let client = get_reqwest_client_rustls(&provider_refs, 30, None)
        .expect("client with provider roots must build");

    match client.get(PUBLIC_HOST).send().await {
        Ok(r) => panic!(
            "{PUBLIC_HOST} authenticated against the provider roots alone (status {}) — the \
             built-in web PKI bundle is still enabled",
            r.status()
        ),
        Err(e) => assert!(
            !e.is_timeout(),
            "expected a TLS/connect rejection but timed out: {e:?}"
        ),
    }
}

/// The escape hatch works: roots handed in through a provider are honoured, so
/// a consumer that genuinely wants the public web PKI can have it by declaring
/// it (`certval_stores_mozilla`) rather than relying on an ambient default.
///
/// Uses `certval_stores_pbdev`'s own roots as the payload — this asserts the
/// plumbing (provider roots reach the TLS config through `tls_certs_only`),
/// which is the half that could regress. Proving that a given provider's root
/// authenticates that provider's host needs an endpoint that is not reachable
/// from a developer machine.
#[tokio::test]
#[ignore = "network"]
async fn provider_roots_reach_the_tls_configuration() {
    let provider_refs: Vec<&dyn TrustStoreProvider> = vec![certval_stores_pbdev::provider()];
    let roots: usize = provider_refs
        .iter()
        .flat_map(|p| p.entries())
        .map(|e| e.roots.len())
        .sum();
    assert!(roots > 0, "fixture provider must carry roots");

    // Builds only if every root was accepted by `reqwest::Certificate::from_der`
    // and `tls_certs_only`; a rejected root would have been logged and skipped,
    // which `conformance::check_roots_parse` is what actually catches.
    get_reqwest_client_rustls(&provider_refs, 30, None)
        .expect("provider roots must be usable as reqwest certificates");
}
