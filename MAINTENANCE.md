# Keeping the stores current

How trust material enters these crates, what keeps it from going stale, and what CI guarantees
about it. This is the maintainer's view; what a *consumer* needs is in each crate's own README, and
the provider API is in [`certval_stores_core`](certval_stores_core/README.md).

Two repositories and one private one hold the family: `carl-wallace/certval-stores` (this
workspace), `carl-wallace/certval-stores-mozilla`, and `RedHoundSoftware/certval_stores_sipr`. They
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
| The mesh, walked from its committed anchor | `fpki` | Nothing per bundle: the walk starts at a committed anchor and the store keeps only what validates back to it |
| A crates.io dependency | `webpki_root_certs` | Whatever `webpki-root-certs` carries; nothing is vendored here |

The stream-sourced crates keep the signed artifact they were generated from. That is what makes
them checkable later: `*_store_is_what_the_committed_stream_generates` regenerates from the
committed `.ir4` and compares certificate sets, so a store that drifted from its own input fails
even when the pinned counts still line up. `fpki` commits every bundle its walk read, under
`inputs/crawl/`, for the same reason, and `the_store_is_what_the_committed_walk_generates` does the
same with them, pruned at the walk date recorded in `provenance/fpki/collected.txt`.

Every provider the generator writes embeds its anchors through a list it writes with them:
`src/roots_<env>.rs` in `nipr`, `eca`, `wcf`, `tpm` and `pbdev`, and `src/env_*.rs` in `msft`.
Each crate's tests check that list against `roots/`, both as generated text and as the anchors the
crate yields, so a refresh that changes a publisher's roots changes what the crate embeds in the
same commit. `fpki`'s two fixed anchors are listed in its `lib.rs`, since its refresh writes no
roots.

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
the Microsoft one, shows its changes in the file list instead. Trust anchors get a section of their
own (`.github/scripts/roots-diff.sh`): each root the refresh added, removed or replaced, by file and
subject, since a change of roots is the larger event the versioning below marks as a minor bump.

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

Daily, in its own workflow because the cadence differs: the mesh changes whenever any
participant's cross-certificates change, and a cross-certificate appearing is how a participant
becomes reachable. `certval-store-gen fpki-crawl` walks the mesh from Federal Common Policy CA G2,
following both the SIA `caRepository` and AIA `caIssuers` bundles each certificate names, and
**commits every bundle as served under
`inputs/crawl/<host>/<path>`**, the walk date in `provenance/fpki/collected.txt`, and the store,
validated at that date; what it leaves out is listed in `provenance/fpki/dropped.txt`. A walk that
reads exactly the committed bundles writes nothing.

The FPKI's repositories are not reliably up, so one host failing must not cost the refresh. A
repository that gives no answer after the walk's retries is read from its committed bundle
instead, and the walk continues through it; anything in that copy that has expired since is
pruned at the walk date. A repository with no committed copy is skipped, since the store held
nothing from it before either. The workflow raises a warning for either, so a host that stays
down is seen rather than silently aging its copy. A repository answering that it has nothing (a
4xx) is not an outage: the mesh has at least one such URI permanently.

The bundles are the one source here with no signature to check before taking them. Committing them
is the compensation: it gives this crate the property the InstallRoot providers have, a source
artifact the store can be regenerated from and compared against. Until 2026-10-27 the source was
GSA's FPKI crawler bundle, which lagged the mesh and left out two Northrop Grumman CAs whose
repository serves BER.

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

`webpki_root_certs` moves when its dependency moves, and Dependabot is what moves it — monthly,
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
- **MSRV 1.88 on two no-client builds** — `nipr`, the multi-environment shape, and `msft`, the
  only crate with a build script. 1.88 is certval's own floor and what every crate here declares.
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

The providers publish at `1.0.0` and follow the rule each crate's README states: a **patch**
release changes intermediate CA certificates, partial paths, or a store's dates or label; a
**minor** release adds or removes trust anchors in a store, adds a store, or adds to the API
without breaking code that uses it; a **major** release breaks code that uses the API, for example
by removing a store along with its feature and constant. Publishing at 1.0 is what gives the
providers all three kinds of release: below 1.0, Cargo treats a patch release as compatible and
every other release as breaking, so there would be no way to mark a trust-anchor change apart
from an intermediate CA change.

A trust-anchor change counts whether or not a file under `roots/` moved. A root that leaves one store
and stays in another, as when Microsoft withdraws a purpose or Mozilla changes a trust bit, changes
the anchors of the store it left. `.github/scripts/suggested-bump.sh` applies this rule to each
refresh and puts the suggested bump first in the pull request's description.

Three crates sit outside the rule:

- `certval_stores_provider_core` (1.x) contains `StoreEntry` and `TrustStoreProvider` and nothing
  else, and follows ordinary semver. `StoreEntry` is `#[non_exhaustive]`, so a field arrives in a
  minor release.
- `certval_stores_core` (0.x) has certval and reqwest types in its API, so a breaking release of
  certval or reqwest is a breaking release of core. The providers depend on
  `certval_stores_provider_core` alone, so a new release of core does not require new releases of
  the providers.
- `certval_stores_webpki_root_certs` takes its trust anchors from the `webpki-root-certs` crate,
  which it requires as a minimum version. When a merged Dependabot pull request moves
  `webpki-root-certs` to a release that changes the roots, raise the minimum in its `Cargo.toml`
  to that release and publish a minor release. A user's `cargo update` can bring the newer roots
  before then. The requirement is never exact, because an exact one would conflict with other
  crates that depend on `webpki-root-certs`, such as `ureq`.

Each published crate has a `CHANGELOG.md`, packaged with it.

## Releasing

Releases are batched: publish when a merged refresh has changed a store's trust anchors, or a month
after the last release, whichever comes first. Until then a merged refresh reaches only consumers
taking the crates from git; a crates.io user sees nothing.

For each crate with changes merged since its last release:

1. Take the largest suggested bump among the refresh pull requests merged since that release, so a
   single minor makes the release minor, or larger if code changed.
2. Set the version and date on the crate's `CHANGELOG.md` entry and list what changed. The refresh
   pull requests' descriptions name the roots and intermediates that moved.
3. Bump `version` in the crate's `Cargo.toml`, and the `version =` requirement of any crate here
   that depends on it. For `certval_stores_webpki_root_certs`, also raise its `webpki-root-certs`
   minimum to the release in `Cargo.lock`.
4. Check: `cargo test --workspace --all-features`; one pass with the `[patch.crates-io]` table
   removed, since that is the dependency graph a crates.io user resolves; `cargo package -p
   <crate>`; and the MSRV build.
5. Publish in dependency order: `certval_stores_provider_core`, `certval_stores_core`, the
   providers, then `certval_stores_mozilla` from its own repository.
6. Tag each published crate as `<crate>-v<version>`.

The first release differs:

- certval and pkiprocmacros must be on crates.io before anything here.
- The dependency lines that pair `git` with `version` (core on certval; mozilla on
  `certval_stores_provider_core` and core) switch to registry versions, so the repository builds
  what users get. Work against an unreleased certval with a temporary `[patch.crates-io]` instead.
- Publishing eleven new crate names in one sitting meets crates.io's limit on new crates. A refused
  publish partway through is that limit, not a failure, and the rest go up after a wait.
- `certval_stores_sipr`, which is private and not published, moves to the registry
  `certval_stores_provider_core` and `certval_stores_core` at the same time. A git-sourced core
  beside registry providers gives two different `TrustStoreProvider` traits.

## Accepted costs

An accepted cost rather than a gap, recorded so it is not rediscovered: `inputs-verified` reaches
`ocsp.sectigo.com` on every pull request, so a responder outage blocks the repository. The workflow
states this is the intended reading, since it is here, rather than in a consumer's build, that a
revocation status must be determined.
