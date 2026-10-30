# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.
See the README's "Versioning" section for what each level means for the trust material.

## [1.0.0-rc.2] - 2026-10-30

### Changed
- The Entrust NFI Medium Assurance SSP CA certificate for the CA's newer key (issued 2021, serial
  `4AA96994`) is back in the store, so paths to certificates that CA signs with that key can be found.
  One of the servers behind Entrust's SIA URL serves a copy of the bundle last modified in 2020, without
  this certificate; the 2026-10-29 refresh, which 1.0.0-rc.1 shipped, happened to be answered by that one.

## [1.0.0-rc.1] - 2026-10-29

Initial release, with a store behind each of the `fpki` and `fpki_legacy` features.
