# certval_stores_wcf

WCF trust store for certval — the DoD sub-PKI that DISA publishes as `WCF.ir4`,
whose certificates all sit under `OU=WCF PKI,OU=DoD`.

## What this crate carries

| Feature | Env | Anchors | CA store |
|---------|-----|---------|----------|
| `wcf` | `WCF` | 1 — DoD WCF Root CA 1 | 11 intermediates, 11 partial paths |

`wcf` is on by default, along with `reqwest-client`. This crate has one
environment, so there is nothing for a consumer to choose between — unlike
`certval_stores_nipr`, where neither environment is default and the consumer
says which it wants.

| Anchor | Key | Expires | CAs beneath it |
|--------|-----|---------|----------------|
| DoD WCF Root CA 1 | RSA 2048, sha256 | 2030-12-30 | 11 |

**The store is two deep, and it is the only one in the family that is.** Both
`certval_stores_nipr` and `certval_stores_eca` are flat — every CA issued
directly by a root, so every serialized partial path is a single certificate.
Here the root issues one intermediate, `DoD WCF Intermediate CA 2`, and that
intermediate issues all ten signing CAs:

```text
DoD WCF Root CA 1                       (anchor, expires 2030-12-30)
└── DoD WCF Intermediate CA 2           (expires 2030-12-29)
    └── DoD WCF Signing CA 1 … 10       (expire June 2027)
```

So the store carries 11 buffers and 11 paths: one of a single certificate and
ten of two. `Intermediate CA 1` is not published and neither is `Signing CA`
anything above 10 — what the stream carries is what is here.

The signing CAs expire within a year of each other in June 2027, which is worth
knowing before a refresh: a consumer that pins this crate and does not update it
loses the whole working layer at once while the anchor stays valid for three more
years.

## Where the material comes from

`inputs/WCF.ir4` is the artifact of record. It is a DoD InstallRoot stream — an
RFC 4073 collection of separately signed RFC 5934 TAMP updates, published at
`https://crl.gds.disa.mil/pke/config/` — and everything in `roots/` and `cas/` is
generated from it.

Only the `Root` and `CA` messages are read, and only their `add` entries: the
stream is used here as a trust store rather than applied as an update, so there
is no prior state for `remove` and `change` to act on. The
`RemoveCertificateHintList` message is skipped for that reason and one sharper
one — its entries are structurally `add`, but each shares a public key with a
`remove` elsewhere in the same file, so reading it would install exactly the
certificates being withdrawn.

**The stream is verified at generation**, where the anchors are already in hand:
the member signatures, the RFC 3161 timestamps over them, the signer's chain to a
pinned DoD root under the code-signing EKU, and the revocation status of that chain
from the OCSP responses the stream staples — all at the time those timestamps
establish, which is when those responses were current. One bad member refuses the whole
stream. Your build fetches nothing; the timestamp authority's own status is asked of a
responder by `verify --stream`, which CI runs on these committed bytes. `WCF.ir4` is signed by the
same DISA code-signing certificate as `DoD.ir4` and `ECA.ir4`
(`CN=CS.DISA.ID21.08-0040`, chaining to DoD Root CA 3), which is why the anchors a
stream is verified against are pinned in the generator rather than taken from the
crate being generated.

`provenance/prod/published.txt` and `provenance/prod/collected.txt` carry the dates
the entry reports — the verified timestamp on the InstallRoot messages read, and the
day `WCF.ir4` was fetched. Both are written by the generator, so a refresh moves them
with the material rather than leaving them to a hand edit.

The generated DER ships beside the `.cbor` in `cas/prod/`, and
`conformance::check_generator_inputs` asserts it still matches what the store
carries — nothing `include_bytes!`es those files, so without that check they
would drift in silence. The anchor in `roots/prod/` *is* `include_bytes!`d in
`src/lib.rs`, and `conformance::check_root_inputs` asserts the directory and that
list agree. The compiler checks only half of that: removing a `.der` breaks the
build, while adding one leaves a file that ships and reads as an anchor without
being in the trust set.

### There is no operational-test environment

`JITC.ir4`, the operational-test stream, publishes DoD, NSS and ECA anchors and
no WCF ones — so unlike the DoD material next door in `certval_stores_nipr`,
there is no test counterpart to carry. `certval_stores_fpki`'s `fpki_legacy` is
the precedent for an anchors-only entry if DISA ever publishes one.

## Refreshing

`build.rs` does it on a plain `cargo build`, but only when `refresh-inputs` is present beside
`Cargo.toml`. That file is gitignored and never committed — a git dependency is a checkout of
this repository, so a committed sentinel would put every consumer's build on the refresh path —
so create it once in a fresh clone:

```sh
touch refresh-inputs
```

With it there, a build re-fetches the stream, replaces `inputs/WCF.ir4` when the
publisher's own date is newer, regenerates `roots/`, `cas/` and `provenance/`, and reports what
moved as `cargo::warning=`. What it leaves behind is an ordinary source change to review and
commit. Delete the file to build from the committed material without touching the network.

To do it by hand instead, replace the stream in `inputs/` with a freshly downloaded one and
regenerate. Both `roots/prod/` and `cas/prod/` are output, so nothing there is edited by hand:

```sh
certval-store-gen installroot --stream inputs/WCF.ir4 --population wcf \
    --provider-dir . --env prod --dry-run   # read the diff first
certval-store-gen installroot --stream inputs/WCF.ir4 --population wcf \
    --provider-dir . --env prod
```

`--dry-run` reports what would change by subject and serial and writes nothing,
which is the form to run first: a re-issued certificate keeps its subject and its
key, so a serial is what tells you it moved. Writing also prints the
`include_bytes!` list, which goes into `src/lib.rs` — the anchors are embedded as
DER rather than read from the store, because `reqwest::Certificate::from_der`
takes only a bare `Certificate`.

`--population wcf` is what selects this material. WCF anchors sit under `OU=DoD`
and would otherwise classify as DoD material: naming the population is what keeps
this store and `certval_stores_nipr` from being able to take each other's anchors
if DISA ever publishes both in one stream.

Then update `EXPECTED_INTERMEDIATES` in `tests/tests.rs` if the count moved, and
re-run `cargo test -p certval_stores_wcf --all-features`. That count exists to
make a change in trust material show up in review rather than arrive silently.

## Sanity check against pittv3

```sh
pittv3 -b cas/prod/prod.cbor -t roots/prod --list-partial-paths
```

For the committed material this reports `11 certificates yielded: 1 paths with
1 certificate; 10 paths with 2 certificates`. A CA that appears in no path is
unreachable to an offline consumer however well-connected it looks.
