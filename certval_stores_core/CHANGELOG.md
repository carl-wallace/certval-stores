# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## [0.1.0] - unreleased

Initial release: composes `certval_stores_*` providers into a certval `PkiEnvironment`
(`prepare_certval_environment`), serialized stores (`serialize_environment`), trust anchors
(`get_roots`) and `reqwest` clients (`reqwest-client` feature), with conformance checks for
provider crates (`test-util` feature).
