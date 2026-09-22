# certval_stores_msft

The Microsoft root program as certval trust stores, split by the purposes the program grants.

Microsoft publishes its root program as a **certificate trust list** rather than as a bundle:
`authrootstl.cab` is an Authenticode-signed cabinet holding one file, `authroot.stl`, which lists
SHA-1 thumbprints and per-root metadata and carries no certificates at all. Each certificate is
served separately, at a URL named after its own thumbprint. This crate carries the result of
following that, and `certval-store-gen`'s `authroot` adapter is what follows it.

## What binds a certificate to the program

The list is signed; the individual certificates are not, and they are served over plain HTTP. What
makes a certificate here trust material is that its SHA-1 digest equals the entry that asked for
it — so the file names in `roots/` **are** those digests, and a test asserts that each file hashes
to its own name. Anything substituted in transit fails that comparison, which is why the unsigned
transfer does not matter.

## Environments

Six, all views over the same list, and the certificate itself is stored once in `roots/`
regardless of how many grant it. Measured against the list published 2026-08-25:

| feature | id | roots |
|---|---|---|
| `msft_all` | `msft_all` | 357 |
| `msft_client_auth` | `msft_client_auth` | 267 |
| `msft_tls` | `msft_tls` | 234 |
| `msft_email` | `msft_email` | 215 |
| `msft_timestamping` | `msft_timestamping` | 162 |
| `msft_code_signing` | `msft_code_signing` | 143 |

No environment carries a CA store. Microsoft publishes roots and nothing else, so there are no
intermediates and no precomputed partial paths — a chain validated against one of these needs its
intermediates supplied or retrieved.

## What is carried, and what is not

The published list holds **562** entries; this crate carries **357**. Three rules account for the
difference, and the first two are about not accumulating trust nobody intends:

- **Expired roots are dropped** — 98 of them. Microsoft keeps them listed; `CDD4EEAE…`,
  `CN=Microsoft Root Certificate Authority`, has been expired since 2021 and is still published.
- **Restricted roots are dropped** — 107 of the remainder. A root can stay in the list while
  Microsoft distrusts it from a given date, carried as property `1.3.6.1.4.1.311.10.11.104`. The
  2016-04-19 cohort is the SHA-1 deprecation; `DigiCert Baltimore Root` and
  `GeoTrust Universal CA` were restricted on 2026-09-15. Keeping them would mean shipping a root
  as trusted after the program stopped trusting it.
- **Roots certval cannot verify are dropped** — MD2, MD4 and MD5 signatures. certval's RSA support
  begins at SHA-1 and no feature adds those, so such a root could anchor nothing. The list holds
  ten (two MD2, eight MD5) and all ten are already excluded by the two rules above, so this one
  removes nothing today; a test asserts the invariant rather than trusting that to stay true.

None of the three is a decision the list makes for us, and the first two could be revisited: a
consumer verifying an *old* Authenticode signature legitimately needs a root that was restricted
after that signature was timestamped. `msft_code_signing` cannot do that today. Ask if you need it.

## Things in this material worth knowing

- **Seven roots are ML-DSA-87** (`2.16.840.1.101.3.4.3.19`) — pilot roots from DigiCert, HARICA,
  IdenTrust, Sectigo, SSL.com, UniTrust and ComSign. certval can verify their self-signatures;
  most tooling cannot.
- **41 of the 357 carried roots are SHA-1 signed**, so reading this crate's material needs
  certval's `sha1_sig`. That, with the MD2 and MD5 roots the program also lists, is why the
  generator takes the signed list as the authority on what is a root rather than deciding by
  self-signature the way the PKCS#7 adapters do: an algorithm nobody can verify would file a root
  as an intermediate.
- **Twenty roots carry a serial number of zero or a negative value**, against RFC 5280. x509-cert
  enforces the length limit and not positivity, so they decode; one, `SZAFIR ROOT CA`, has a
  21-byte serial and survives only because that limit is enforced as 21 on decode.
- **Microsoft's own product roots grant nothing.** Six entries carry no purposes, and they are
  `Microsoft Root Certificate Authority` 1997/2010/2011 and the ECC product roots. Windows trusts
  them intrinsically rather than through the program — so no store built from this list can verify
  Microsoft's own signed artifacts, including the trust list itself.

## Refreshing

`build.rs` refreshes only in a working tree carrying a `refresh-inputs` sentinel, which is
gitignored and never committed, so no consumer's build fetches anything. A refresh is a
conditional `GET` of the cabinet — 304 on all but roughly one day a month, since the list changes
about monthly — and on a change it re-fetches every listed certificate, verifies each thumbprint,
then rewrites `roots/` and the generated `src/env_*.rs` indexes wholesale. Nothing is written and
nothing is deleted unless every entry is satisfied, so a failed fetch leaves what is committed.

`provenance/` records what the copy is: `published.txt` (the list's own `thisUpdate`),
`collected.txt`, `sequence_number.txt` and `last_modified.txt` — the last two so a refresh can
tell "the CDN re-served the same list" from "the program changed".
