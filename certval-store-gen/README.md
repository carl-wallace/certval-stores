# certval-store-gen

Offline generator for [certval](https://github.com/carl-wallace/rust-pki) CBOR stores.
It produces a `ta.cbor` / `ca.cbor` pair that **pittv3** (desktop and wasm) load directly
as fetched stores — the same format the pittv3 store fetch path already consumes, via
`TaSource::new_from_cbor` and `CertSource::new_from_cbor`.

## What it does

One shared generation core, four input adapters. Every adapter normalizes its source into
a set of self-signed **trust anchors** and a set of **intermediate CA** certificates; the
core then:

- serializes the trust anchors to `ta.cbor` (buffers only, no partial paths), and
- builds every partial certification path among the intermediates and serializes that to
  `ca.cbor`.

Both steps reuse certval's own `find_all_partial_paths` + `BuffersAndPaths` CBOR
serialization (the same path `pittv3 --generate` drives), so outputs are byte-format
compatible with the pittv3 consumers by construction.

## Adapters

| Command       | Source                                             | Status  |
| ------------- | -------------------------------------------------- | ------- |
| `local`       | a folder of trust anchors + a folder of CA certs   | working |
| `webpki`      | Mozilla roots (webpki-roots) + CCADB intermediates | working |
| `fpki`        | oversized PKCS#7 certs-only bundle (Federal PKI)   | working |
| `installroot` | a DoD InstallRoot `.ir4` stream (RFC 5934 TAMP)    | working |
| `recode`      | existing stores, rewritten in the current encoding | working |

`installroot` reads one population out of a stream — `--population dod|nss|eca|wcf`, since one
stream publishes more than one PKI and they belong to different store crates. Every member
of a stream is verified before any of its material is read, and one bad member refuses the
whole stream: the signature over the TAMP message, the RFC 3161 timestamp on that signature,
the signer's chain under the code-signing EKU to a DoD root pinned in `anchors/`, and the
revocation status of every certificate in that chain — all as of the time the timestamp
establishes, so a stream signed last year still verifies while one signed with an
already-expired certificate does not. `verify --stream <file>...` runs exactly those checks and
nothing else, which is what makes it the right gate for a repository: it answers "may this file
be committed", not "can this environment be built".

**The stapled revocation data is read, and it is required.** A stream carries OCSP responses for
its own signing chain — DISA produces them within days of signing — so the status of every
position can be determined with no network, and only as of the timestamp: those responses are
days old when the stream is published and years stale afterwards. Requiring a determined status
is what makes them load-bearing; a member that staples none, or staples CRLs instead, is refused
rather than validated without the check.

**The timestamp authority's chain is settled by asking a responder**, because nothing staples it:
DISA has its streams timestamped by Sectigo, and that chain is validated as of *today*, revocation
included. certval does the asking — this crate takes certval's `remote` feature and calls
`check_revocation`, so the ladder is the one certval ships rather than a second one assembled
beside it. Who may ask is a policy, `verify::Revocation`: `verify --stream`, generation, and a
source checkout refreshing its inputs all ask; the regeneration check a provider crate runs in its
own tests does not, because a test that depends on a responder being up is a test nobody trusts, and
the gate that asks runs upstream in CI on those same committed bytes.

Taking `remote` is why this crate's floor is rustc 1.86 rather than certval's 1.85 — reqwest's
graph carries icu 2.2.0. A provider crate inherits that floor where it takes this crate: at build
time for the two that keep a build script, and at test time for the InstallRoot providers, which
take it as a dev-dependency. Building those needs only certval's 1.85.

The timestamp is verified too, not merely read — it is what the signer is validated at, and
it arrives outside the signature where anyone handing over the file could edit it. That means
a second pinned anchor: DISA has its streams timestamped by Sectigo, so `anchors/` holds
`Sectigo Public Time Stamping Root R46` beside the four DoD roots, and the timestamp
authority is required to carry `id-kp-timeStamping` across its whole path.

## Usage

```sh
# Local folders: a folder of trust anchors + a folder of intermediate CA certs
certval-store-gen --out-dir ./out local --tas ./roots --cas ./intermediates

# Local folders: roots only (ta.cbor, no ca.cbor)
certval-store-gen --out-dir ./out local --tas ./roots

# Web PKI: Mozilla roots only
certval-store-gen --out-dir ./web webpki

# Web PKI: roots + a folder of CCADB intermediates (DER/PEM)
certval-store-gen --out-dir ./web webpki --ccadb ./ccadb-intermediates

# Federal PKI: split a PKCS#7 bundle into roots + intermediates
certval-store-gen --out-dir ./fpki fpki --p7 ./fpki-bundle.p7b

# DoD: one population of an InstallRoot stream, written into a provider crate
certval-store-gen installroot --stream ./DoD.ir4 --population dod \
    --provider-dir ../certval-stores/certval_stores_nipr --env prod --collected 2026-09-11

# The same, reporting what would change and writing nothing
certval-store-gen installroot --stream ./DoD.ir4 --population dod \
    --provider-dir ../certval-stores/certval_stores_nipr --env prod --dry-run

# A stream plus material it cannot carry: a cross-certified root published by no
# repository, and the bundle that root publishes at its own SIA
certval-store-gen installroot --stream ./DoD.ir4 --population dod \
    --extra-roots ./DoD_Interoperability_Root_CA_2.der \
    --extra-cas ./DODINTEROPERABILITYROOTCA2_IB.p7c \
    --provider-dir ../certval-stores/certval_stores_nipr --env interop --collected 2026-09-21
```

Writes `ta.cbor` (and `ca.cbor` when intermediates are present) into `--out-dir`
(default `.`); override individual paths with `--ta-out` / `--ca-out`.

## Composing a provider

`--provider-dir` is how a `certval_stores_*` crate's material is made, not only how this
repository's own is refreshed. Pointed at a crate laid out like the ones beside this one, it
writes `roots/<env>/*.der`, `cas/<env>/*.der`, `cas/<env>/<env>.cbor` and
`provenance/<env>/{published,collected}.txt`, and always reports the diff by certificate
first — added, removed, unchanged — whether or not it then writes. `--dry-run` reports and
writes nothing.

Certificates are named from their own subject, so material merged in from a file lands
beside stream material under names of the same shape, and a supplied file's name never
reaches the repository.

`--extra-roots` and `--extra-cas` exist for material a published stream cannot carry. DoD
Interoperability Root CA 2 appears in no `.ir4` message and in no `issuedby` bundle, so an
interoperability environment has to be handed it, together with the bundle that root
publishes at its own SIA. Supplied files may be DER, PEM, or a certs-only PKCS#7 container,
which is expanded before anything is parsed — a `.p7c` handed to a DER-only parse looks like
one unreadable certificate rather than the five it holds. A self-issued certificate given to
`--extra-cas` is rejected rather than filed as an intermediate.

## Checking a provider at build time

The same generation core is a library, so a provider crate can check on every build that
what it committed is still what its inputs produce:

```rust
// build.rs
fn main() {
    certval_store_gen::build_log::init(log::LevelFilter::Warn).ok();
    certval_store_gen::build_check::assert_tamp_store(
        "inputs/DoD.ir4", "dod", "cas/prod/prod.cbor",
    );
}
```

Take the crate with `default-features = false` and the CLI's dependencies stay out of the
build graph.

The comparison is on **content, not bytes**: both stores are decoded and their certificate
sets compared. A byte comparison would conflate the material drifting with certval changing
how it encodes a store — a real thing, which `recode` exists to handle — and would fail a
build for a reason having nothing to do with trust material. Comparing decoded certificates
is invariant under an encoding change and still catches a store that gained, lost or altered
one, which is what makes failing the build on a mismatch honest.

`build_log::init` routes the library's `log` output to `cargo::warning=`, since cargo
surfaces nothing else from a build script without `-vv`.

For composing rather than checking, `ingest::read_cert_file`, `ingest::reject_self_issued`
and `ingest::merge_extras` are the same functions the CLI uses.

## Design notes

- **Roots vs. intermediates split** (FPKI): decided by *self-signature verification*, not a
  bare issuer==subject comparison, so self-issued rollover certs are not misfiled as roots.
- **Validity**: certs are included regardless of their validity window — expiry is a
  validation-time concern for the consumer, not a reason to omit a cert from the store.
- **Web PKI intermediates** are an optimization: preloading lets a chain build without a
  just-in-time AIA fetch and covers servers that omit AIA. Once the pittv3 fetch proxy
  lands, AIA becomes the fallback for anything not preloaded here.
- **Deterministic output**: each cert's `filename` label is reduced to its basename before
  serialization, so no absolute source path (build-machine username / directory layout)
  ends up in the store. The label is only surfaced in consumer logs/reports — path building
  indexes by SKID/name and `CertFile` equality ignores it — so a basename keeps a useful
  label while making generation reproducible (byte-identical across machines).
- **Two dates, and only one of them is this tool's opinion.** A provider crate reports how
  current its material is, and the generator writes both halves of that:
  `provenance/<env>/published.txt` is read out of the source — for `installroot`, the
  `genTime` of the RFC 3161 timestamp DoD attaches to each message, since its own
  `SignerInfo` carries no `signingTime` — while `collected.txt` is `--collected`, the day
  the artifact was downloaded, defaulting to today. Adapters handed a folder or an undated
  bundle write no publication date rather than inventing one. Files rather than lines in
  `lib.rs` so that a refresh carries the dates with the material: the gap between them is
  the useful part, `JITC.ir4` having been published **2025-02-03** and collected
  **2026-09-11**, and a consumer shown only the second would read nineteen months of DoD
  anchor changes as freshness.
- **Compression is a transport concern, not this tool's job**: the CBOR (`BuffersAndPaths`)
  is the format the pittv3 consumers already load, so it is emitted uncompressed and
  unchanged. It gzips to ~40–55% of raw; serve it with `Content-Encoding` at the fetch
  layer rather than pre-compressing here. The store's non-DER weight is the precomputed
  partial-path graph, which is the point of the store, not bloat.

## Building

A member of the `certval-stores` workspace, and it takes `certval` from the same git source
every other member does. That is required rather than tidy: cargo treats a path dependency
and a git dependency as different crates, so mixing them would put two certvals in one graph
and the `x509-cert` types would stop matching across the boundary. The workspace root's
`[patch.crates-io]` covers the patches certval needs.

The CLI is behind the default `cli` feature. `default-features = false` gives the library
alone, which is what a `[build-dependencies]` entry wants.
