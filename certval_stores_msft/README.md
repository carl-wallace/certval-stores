# certval_stores_msft

The Microsoft root program as certval trust stores, split by the purposes the program grants.

Microsoft publishes its root program as a **certificate trust list** rather than as a bundle:
`authrootstl.cab` is a cabinet holding one file, `authroot.stl`, a list signed with CMS that gives
SHA-1 thumbprints and per-root metadata and contains no certificates at all. Each certificate is
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

Each environment other than `msft_all` contains a root when the list grants that environment's
purpose (property `…10.11.9`) and does not withdraw it (property `…10.11.122`). Microsoft adds a
withdrawal on top of the original grant rather than editing it, so a root can list a purpose in
both; it is left out of that environment and stays in `msft_all`.

**Microsoft's NotBefore restrictions are not applied.** Properties `…10.11.126` and `…10.11.127`
say that certificates issued after a date are not trusted for the listed purposes, while those
issued before it still are. That depends on the issued certificate, not on the root, and has no
equivalent in RFC 5280 path validation, so the environments contain these roots as the list grants
them and the validity of the certificates themselves is what applies. On the list published
2026-10-23, 50 roots in `msft_tls` feature such a date for serverAuth, among them the Entrust,
AffirmTrust and Trustwave roots.

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

## Versioning

This crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html), and the version
number also says what changed in the trust material:

- A **patch** release (1.0.0 to 1.0.1) changes intermediate CA certificates, partial paths, or a
  store's dates or label. No store's trust anchors change.
- A **minor** release (1.0.x to 1.1.0) adds or removes trust anchors in a store, adds a store, or
  adds to the API without breaking code that uses it.
- A **major** release (1.x to 2.0.0) changes the API in a way that breaks code that uses it, for
  example by removing a store along with its feature and constant.

With an ordinary requirement such as `certval_stores_msft = "1.0"`, `cargo update` takes every
1.x release, including a minor release that adds or removes trust anchors. With
`certval_stores_msft = "~1.0"`, `cargo update` takes 1.0.1, 1.0.2 and so on, which change only
intermediate CA certificates, partial paths or dates, and does not take 1.1.0, so the trust anchors
stay those of 1.0 until the requirement is changed to `~1.1`. Each release's changes are listed in
`CHANGELOG.md`.

## Refreshing

Refreshing is a tool, not a build script:

```text
cargo run -p certval-store-gen --features cli,authroot,tpm -- authroot
```

It is a conditional `GET` of the cabinet — 304 on all but roughly one day a month, since the list
changes about monthly — and on a change it re-fetches every listed certificate, verifies each
thumbprint, then rewrites `roots/` and the generated `src/env_*.rs` indexes wholesale. Nothing is
written and nothing deleted unless every entry is satisfied, so a failed fetch leaves what is
committed.

**Why not a build script.** Refreshing needs `tpm_cab_verify`, the `authenticode` fork and a
pre-release ASN.1 stack; their patch-table entries do not travel with a git dependency, so a build
script able to refresh would make every consumer resolve all of it to embed a store it never
refreshes. This crate's only build dependency is `sha1`, for the thumbprint check it runs on every
build.

**What keeps it current** is `.github/workflows/refresh.yml`, which runs the command weekly and
opens a pull request when the publisher has moved. That pull request arrives with failing tests by
design: the counts below are pinned, so a change names itself and a person reads the certificate
diff before it lands.

`certval-store-gen authroot --check-only` verifies the committed material and fetches nothing.

`inputs/authrootstl.cab` is the cabinet the committed store was generated from, exactly as it was
fetched. A refresh compares the list it fetches with the list inside that cabinet, and refuses one
with a lower sequence number or an earlier `thisUpdate`, writing nothing: an older list is validly
signed as of its own date, so its signature alone does not rule it out. Expired and disallowed
roots are judged as of the list's `thisUpdate`, not the day the refresh runs.

`provenance/` records what the copy is: `published.txt` (the list's own `thisUpdate`),
`collected.txt`, `sequence_number.txt` and `last_modified.txt` — the last two so a refresh can
tell "the CDN re-served the same list" from "the program changed".
