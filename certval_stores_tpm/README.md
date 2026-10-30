# certval_stores_tpm

![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

The TPM vendor trust material Microsoft redistributes as `TrustedTpm.cab`, as a certval trust
store.

These are the roots and intermediate CAs of every TPM vendor whose attestation keys Windows will
accept. What they are *for* is verifying that an attestation key lives in a real TPM made by a real
vendor — the check behind a Purebred pre-enrollment or a SCEP request from a TPM-backed virtual
smart card — rather than validating certificates issued to people.

## Where it comes from, and what makes it trustworthy

One Authenticode-signed cabinet, fetched from
`https://go.microsoft.com/fwlink/?linkid=2097925` and committed at `inputs/TrustedTpm.cab`.

**The cabinet vouches for its members**, which is the whole of the trust argument: it carries
`flags 0x0004`, so its reserved area holds a signature covering everything inside, and none of its
members is signed on its own. That is the opposite of the Microsoft root program's
`authrootstl.cab`, which is unsigned packaging around a signed list — the two routes
`certval-store-gen`'s `cab` module offers, and the reason it offers two.

The publisher's own folder names say what each member is, and nothing here second-guesses them:

```text
<vendor>\RootCA\<name>          the anchors
<vendor>\IntermediateCA\<name>  the CAs beneath them
version.txt setup.cmd setup.ps1 packaging
```

Splitting by self-signature — what the PKCS#7 adapters do — would be wrong twice here: a vendor
root certval cannot verify would be filed as an intermediate, and a self-signed *intermediate*
would be promoted to an anchor.

Vendors also share certificates -- `Microsoft Pluton Root CA 2021` ships under `AMD\RootCA` as
well as Microsoft's, and `Microsoft TPM Root Certificate Authority 2014` under `QC\RootCA` -- so
the same bytes arrive under two names and are collapsed to one.

## One environment

`tpm`, on by default. Ten vendors appear inside (Microsoft, Infineon, AMD, Intel, NationZ,
STMicro, Nuvoton, Atmel, QC), but they are one trust set rather than a menu: an attestation key
chains to whichever vendor made the part, and a relying party cannot know which in advance. The
vendor survives only in each certificate's label.

**A few dozen roots and over two thousand intermediate CAs**, in a CA store of several megabytes,
which is roughly what enabling `tpm` adds to a binary.

**The intermediates live only in that store**, unlike every other provider here, which also commits
each one as loose DER for review. At over two thousand certificates that would be megabytes of the
same material twice over, in a diff nobody reads. What replaces the review is
`the_store_is_what_the_committed_cabinet_generates`, which rebuilds the store from the committed
cabinet and compares -- a stronger check than reading DER, and one CI runs on every change. The
roots stay loose, because `src/roots_tpm.rs`, which a refresh writes with them, embeds them
individually and a test compares that list against the directory.

## What is not carried

**Intermediates that reach no root in the cabinet.** They are listed by name in
`provenance/tpm/dropped.txt`, and that list is the thing to watch — shorter when a publisher fixes
one, longer when a vendor's root stops being carried.

Most are AMD fTPM CAs whose issuers the cabinet does not include and whose AIA URIs serve a
self-signed certificate rather than the issuer. Those CAs are real; this material simply cannot
root them. Carrying them anyway would ship a store that fails its own conformance checks, since
`check_partial_paths` requires every CA in a store to appear in some path — and relaxing that check
would give up the property that catches a genuinely broken generation.

## Encodings, which are not uniform

The cabinet mixes DER and PEM **within a single vendor folder** — several hundred `.crt` and `.cer`
members begin `0x2d`, the `-` of a `-----BEGIN CERTIFICATE-----` line. A reader that assumes DER
loses a whole vendor's intermediates and reports it as a parse failure. Some PEM members hold more
than one certificate, which is why the cabinet yields more intermediates than it has members. There is also a
`readme.txt` inside `AMD\IntermediateCA\`.

## Using it

Load a store into a certval `PkiEnvironment` with `certval_stores_core`, naming the store by its
constant:

```rust
# #[cfg(feature = "tpm")] {
use certval::PkiEnvironment;
use certval_stores_core::prepare_certval_environment;

let mut pe = PkiEnvironment::default();
pe.populate_5280_pki_environment();
prepare_certval_environment(
    &[certval_stores_tpm::provider()],
    &mut pe,
    certval_stores_tpm::TPM,
)?;
# }
# Ok::<(), certval::Error>(())
```

Loading decodes and indexes the whole CA store, which takes a few tens of milliseconds and holds
roughly 25 MB of memory, several times the store's size in the binary. Build the environment once
per process and reuse it rather than building one per request.

The trust material is embedded as it was committed, and nothing in this package lets you re-check
where it came from: using it means trusting this crate's publisher, and the review each refresh
received before it was merged. How the material is obtained and authenticated is described in this
README and in the repository's
[MAINTENANCE.md](https://github.com/carl-wallace/certval-stores/blob/main/MAINTENANCE.md).

## Versioning

This crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html), and the version
number also says what changed in the trust material:

- A **patch** release (1.0.0 to 1.0.1) changes intermediate CA certificates, partial paths, or a
  store's dates or label. No store's trust anchors change.
- A **minor** release (1.0.x to 1.1.0) adds or removes trust anchors in a store, adds a store, or
  adds to the API without breaking code that uses it.
- A **major** release (1.x to 2.0.0) changes the API in a way that breaks code that uses it, for
  example by removing a store along with its feature and constant.

With an ordinary requirement such as `certval_stores_tpm = "1.0"`, `cargo update` takes every
1.x release, including a minor release that adds or removes trust anchors. With
`certval_stores_tpm = "~1.0"`, `cargo update` takes 1.0.1, 1.0.2 and so on, which change only
intermediate CA certificates, partial paths or dates, and does not take 1.1.0, so the trust anchors
stay those of 1.0 until the requirement is changed to `~1.1`. Each release's changes are listed in
`CHANGELOG.md`.

## Refreshing

Refreshing is a tool, not a build script — this crate has no build script at all:

```text
cargo run -p certval-store-gen --features cli,authroot,tpm -- tpm
```

It fetches the cabinet, verifies its Authenticode signature, and regenerates `roots/tpm`,
`cas/tpm` and `provenance/tpm` wholesale. Refreshing needs `tpm_cab_verify`, the `authenticode`
fork and a pre-release ASN.1 stack, whose patch-table entries do not travel with a git dependency —
so keeping it out of the build means a consumer embedding this store resolves none of it.

**What keeps it current** is `.github/workflows/refresh.yml`, weekly, opening a pull request when
the cabinet changes. It arrives with failing tests by design: the tests pin the counts and a digest
of the certificate set (see `MAINTENANCE.md`), so a change names itself and a person reads the diff
before it lands.

**The rollback guard**: `version.txt` states when the contents last changed, and a cabinet dated
earlier than the committed one is refused as a stale mirror rather than accepted as an update.

**The guarantee that the shipped store is the validated output of the committed cabinet** is a
test, not a build-script check — `the_store_is_what_the_committed_cabinet_generates`. Establishing
it means classifying over two thousand members and building a path graph over as many
intermediates, which is far too much to put on every consumer's build; CI runs the tests on every change, which is where a
mismatch has to be caught.

[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.88+-blue.svg
