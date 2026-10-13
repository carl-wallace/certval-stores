# Keeping the stores current

How trust material enters these crates, what keeps it from going stale, and what CI guarantees
about it. This is the maintainer's view; what a *consumer* needs is in each crate's own README, and
the provider API is in [`certval_stores_core`](certval_stores_core/README.md).

Two repositories and one private one hold the family: `carl-wallace/certval-stores` (this
workspace), `carl-wallace/certval-stores-mozilla`, and `RedHoundSoftware/certval_store_sipr`. They
do not share a refresh mechanism; each is driven by what its publisher offers, which is set out
below.

## How trust anchors and intermediate CA certificates are obtained

Every provider crate commits its trust anchors and CA certificates rather than fetching them, and
**nothing in a consumer's build reaches the network**. That is the invariant the rest of this
follows from: a consumer of a published crate compiles certificates, not a downloader. Refreshing
therefore lives outside the build, in the generator and the workflows that drive it.

Five sources, distinguished by what authenticates the material:

| Source | Crates | What signs it |
|---|---|---|
| DoD InstallRoot stream (`.ir4`) | `nipr`, `eca`, `wcf` | RFC 5934 messages, signed by DoD; the stream is committed under `inputs/` |
| Microsoft trust list | `msft` | CMS signature over the list, checked against a pinned anchor |
| TPM cabinet (`TrustedTpm.cab`) | `tpm` | Authenticode signature on the cabinet |
| Published PKCS#7 bundle | `fpki` | Nothing — the FPKI crawler republishes an unsigned bundle |
| A crates.io dependency | `webpki_root_certs` | Whatever `webpki-root-certs` carries; nothing is vendored here |

The stream-sourced crates keep the signed artifact they were generated from. That is what makes
them checkable later: `*_store_is_what_the_committed_stream_generates` regenerates from the
committed `.ir4` and compares certificate sets, so a store that drifted from its own input fails
even when the pinned counts still line up. `fpki` commits its bundle for the same reason, and
`the_store_is_what_the_committed_bundle_generates` does the same with it.

`certval_stores_msft` is the only crate with a build script, and it refreshes nothing. Every file in
`roots/` must hash to its own name, which is the same comparison that admitted it — Microsoft's list
is signed and the certificates it names are not, so the SHA-1 the list gave is what binds them. It
costs one build dependency.

## What keeps it current

### The scheduled refresh (`refresh.yml`)

Weekly, Mondays at 06:00 UTC, plus `workflow_dispatch`. Two jobs, for five crates:

- **`refresh`** — `msft` (from the trust list) and `tpm` (from the cabinet), each a
  `certval-store-gen` run against the publisher.
- **`refresh-streams`** — `nipr`, `eca` and `wcf`. Two steps rather than one, because several
  environments read the same stream: `DoD.ir4` produces the production store *and* both
  interoperability stores, so the publisher is asked once per stream and the generator run once per
  environment. Regeneration is skipped entirely when no stream moved.

Either job acts only when the material actually changed, and then **opens a pull request** from a
branch named for the crate (`refresh/<crate>`, `.github/scripts/refresh-pr.sh`). The pull request
is the notice: GitHub emails its creation, so a waiting refresh no longer depends on someone
noticing a branch. While it is open, later runs push nothing to it, since the reviewer may have
pushed the updated constants there; if the material moved again they comment on it once, and the
run after the merge opens a new one. Opening it needs the repository setting that lets Actions
create pull requests, which also lets them approve one; with no approvals required by the rulesets,
that half unlocks nothing. The review guidance is the pull request's description and the commit
message. So is what moved: for every CBOR store a refresh rewrote, it carries `certval-store-gen diff` of the committed store against the new one, naming the
certificates added and removed and counting the partial paths that changed
(`.github/scripts/store-diff.sh`). A provider that commits certificates rather than a store, such as
the Microsoft one, shows its changes in the file list instead.

**A refresh is expected to arrive red, and that is the mechanism rather than a defect.** Each crate
pins both the counts and a **digest over the certificate set** its material had when a person last
reviewed it. When a publisher moves, the tests fail and name what changed; someone reads the
certificate diff, updates the constants, and merges. The failure *is* the acknowledgement gate.
A pull request opened by the workflow starts no CI by itself, so the first run is the one the
reviewer's push of the updated constants starts (or, for a refresh that moves nothing pinned, a
close and reopen).

Every pinned constant is checked with `certval_stores_core::pin!`, so updating them is one command
on the refresh branch:

```sh
UPDATE_PINS=1 cargo test --workspace --all-features
cargo fmt
cargo test --workspace --all-features
git diff -- '*/tests/*'
```

With `UPDATE_PINS` set, each `pin!` rewrites its constant's declaration to the value the material
gives instead of failing, so that run passes every pin by construction, against binaries compiled
with the old values. The plain run after it is the one that checks the new constants, as CI will.
The diff is what to read beside the certificate diff before committing. The values come from the code that checks them, so the updater cannot drift from the
gate. A constant checked against two different values in one run (the roots the TPM crate embeds
and the roots its committed cabinet regenerates, say) still fails: that is the material disagreeing
with itself, which no value settles. The refresh job deliberately does not run this itself: the
constants exist so that a person looks before the material merges.

The digest is there because a count cannot see substitution, and that is not hypothetical: on
2026-09-25 a Mozilla refresh removed 19 intermediates and added 19 others, every pinned count was
unchanged, and 38 changed certificates passed a gate whose only purpose is to make someone look.
A count measures size where the question is membership. `conformance::set_digest` digests each
certificate, sorts the digests and digests the sorted list, so order does not matter and any
addition, removal or swap moves the value.

The rollback guard sits in the generator, not the workflow: a stream published older than the
committed one is refused rather than taken.

### The Federal PKI (`refresh-fpki.yml`)

Daily, in its own workflow because the cadence differs: the mesh is republished whenever any
participant's cross-certificates change, and a cross-certificate appearing is how a participant
becomes reachable. The bundle is fetched, re-encoded as DER (the publisher has served it both PEM-wrapped and as
DER) and **committed
under `inputs/`**; the store is regenerated from it only if it moved.

The bundle is the one source here with no signature to check before taking it. Committing it is the
compensation: it gives this crate the property the InstallRoot providers have, a source artifact
the store can be regenerated from and compared against.

### Drift detection (`certval-stores-mozilla`)

Daily at 06:17 UTC. The scheduled run skips every ordinary job and runs one that does not run on
pull requests at all: `tools/verify_against_nss.py`, comparing the committed store against what
Firefox ships. It is the only networked job in that repo, kept off pull requests so a CCADB or
GitHub outage cannot block one.

It **detects**; it does not act. Acting is a separate weekly workflow in that repository, which
runs `tools/refresh.py` and `tools/refresh_cas.py` and opens a pull request the same way this
workspace does. The two are kept apart on purpose: drift is cheap and runs daily, while a refresh
fetches the whole CCADB report and every disclosed intermediate.

### By hand

`pbdev` carries a development environment and does not track a publisher, so nothing schedules it.

Every other provider can be refreshed by hand with the same command its workflow runs: each crate's
README carries the invocation, and a `workflow_dispatch` does the same thing and opens a pull
request to review.

`webpki_root_certs` moves when its dependency moves, and Dependabot is what moves it — weekly,
with `webpki-root-certs` deliberately excluded from every group, so a change to which roots the
crate serves is never buried in a lockfile pull request.

## What CI guarantees

`ci.yml` in this workspace, on every pull request and every push to `main`:

- **`cargo hack --each-feature`**, build and test. Each provider builds with every environment
  individually *and with none* — a crate whose material is behind a feature must still compile
  without it.
- **`--all-features`** separately, because `--each-feature` never combines: `nipr`+`om_nipr` in one
  build is where an anchor or partial-path collision between two environments would surface, and
  the core crate's composition test asks whether every public provider can share one
  `PkiEnvironment`.
- **wasm32, without the HTTP client** — the shape `pittv3-wasm` builds, and the one that cannot
  fall back, since reqwest's wasm backend has no `Certificate` or `add_root_certificate`.
- **MSRV 1.85 on two no-client builds** — `nipr`, the multi-environment shape, and `msft`, the
  only crate with a build script. 1.85 is certval's own floor and what every provider
  declares. `certval-store-gen` is excluded and declares 1.88, which it needs: it takes certval's
  `remote` feature, so reqwest carries `icu 2.3` into its graph.
- **`rustfmt`, and `clippy` twice** — default features and `--all-features`, because
  `--all-features` cannot catch a warning that exists only when a feature is *absent*.
- **Ten generator feature shapes**, each with warnings fatal, `fail-fast: false`. This is the job
  that catches dead code in the combinations between "nothing" and "everything" — a provider's
  build script asks for a subset, and that is where an ungated unused function hid.
- **`inputs-verified`** — every committed `.ir4` must verify. This is the gate that lets the
  build-side check stay tolerant: a stream reaching `main` has been checked here, so a consumer's
  build never has to decide what to do about one that has not. It needs egress to
  `ocsp.sectigo.com` for the timestamp authority, which nothing staples.

## Versioning

Nothing in the family is published yet, and versions do not move until it is: every crate stays at
`0.1.0`, and consumers take the providers as git dependencies on `branch = "main"`, so a refresh
reaches them on their next `cargo update` with no version signal. The test constants are the signal
in the meantime; changing one is the acknowledgement that someone read the diff.

The providers publish at `1.0.0`, because the rule below needs three levels and Cargo gives a 0.x
version only two. From then on a bump follows what changed:

- **Patch**, when only intermediate CA certificates or partial paths change. What is trusted is
  unchanged; only which paths can be built without fetching anything is different. A refresh that
  drops expired or withdrawn cross-certificates is a patch, as one that adds new ones is.
- **Minor**, when trust anchors change, or the API gains something compatibly. A root change is the
  larger event, so it is marked as one, but it stays Cargo-compatible and still arrives with
  `cargo update`.
- **Major**, when the API changes incompatibly.

## Accepted costs

An accepted cost rather than a gap, recorded so it is not rediscovered: `inputs-verified` reaches
`ocsp.sectigo.com` on every pull request, so a responder outage blocks the repository. The workflow
states this is the intended reading, since it is here, rather than in a consumer's build, that a
revocation status must be determined.
