# certval_stores_tpm

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
`flags 0x0004`, so its reserved area holds a signature covering everything inside, and none of the
2,209 members is signed on its own. That is the opposite of the Microsoft root program's
`authrootstl.cab`, which is unsigned packaging around a signed list — the two routes
`certval-store-gen`'s `cab` module offers, and the reason it offers two.

The publisher's own folder names say what each member is, and nothing here second-guesses them:

```text
<vendor>\RootCA\<name>          48 members, 47 distinct anchors
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

Measured against the cabinet published 2026-07-09: **47 roots, 2,480 intermediate CAs**, a 4.2 MB
CA store.

**The intermediates live only in that store**, unlike every other provider here, which also commits
each one as loose DER for review. At 2,480 certificates that would be ten megabytes of the same
material twice over, in a diff nobody reads. What replaces the review is
`the_store_is_what_the_committed_cabinet_generates`, which rebuilds the store from the committed
cabinet and compares -- a stronger check than reading DER, and one CI runs on every change. The 47
roots stay loose, because `lib.rs` embeds them individually and a test compares that list against
the directory.

## What is not carried

**42 intermediates that reach no root in the cabinet.** They are listed by name in
`provenance/tpm/dropped.txt`, and the count is the thing to watch — down when a publisher fixes
one, up when a vendor's root stops being carried.

Most are AMD fTPM CAs whose issuers the cabinet does not include and whose AIA URIs serve a
self-signed certificate rather than the issuer. Those CAs are real; this material simply cannot
root them. Carrying them anyway would ship a store that fails its own conformance checks, since
`check_partial_paths` requires every CA in a store to appear in some path — and relaxing that check
would give up the property that catches a genuinely broken generation.

## Encodings, which are not uniform

The cabinet mixes DER and PEM **within a single vendor folder** — several hundred `.crt` and `.cer`
members begin `0x2d`, the `-` of a `-----BEGIN CERTIFICATE-----` line. A reader that assumes DER
loses a whole vendor's intermediates and reports it as a parse failure. Some PEM members hold more
than one certificate, which is why 2,209 members yield 2,480 intermediates. There is also a
`readme.txt` inside `AMD\IntermediateCA\`.

## Refreshing

`build.rs` refreshes only in a working tree carrying a `refresh-inputs` sentinel, gitignored and
never committed, so no consumer's build fetches anything. A refresh fetches the cabinet, verifies
its signature, and regenerates `roots/tpm`, `cas/tpm` and `provenance/tpm` wholesale.

**The rollback guard**: `version.txt` states when the contents last changed, and a cabinet dated
earlier than the committed one is refused as a stale mirror rather than accepted as an update.

**The guarantee that the shipped store is the validated output of the committed cabinet** is a
test, not a build-script check — `the_store_is_what_the_committed_cabinet_generates`. Establishing
it means classifying 2,209 members and building a path graph over 2,480 intermediates, which is far
too much to put on every consumer's build; CI runs the tests on every change, which is where a
mismatch has to be caught.
