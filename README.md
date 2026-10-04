# DIV and DEWP, version 1.0.0

This repository publishes the full [DIV](DIV.md) and [DEWP](DEWP.md)
specifications, their JSON Schemas and conformance vectors. This release is
pinned by the [v1.0.0 tag](https://github.com/intyga-dev/specifications/tree/v1.0.0).
The signed payloads use protocol version 1.0; the repository release version
identifies the complete specification, schema and vector snapshot.

DIV defines signed action approvals and their offline verification. DEWP
defines tamper-evident audit commitments and offline evidence verification.
Neither a valid approval signature nor an audit commitment proves that an
action executed or that a recorded description matches a real-world event.

Paths in the specifications beginning with `docs/schemas/dewp/` refer to
`schemas/dewp/` here; `packages/mcp-schemas/vectors/` refers to `vectors/`.
Other implementation paths are informative. Use the schemas in this release
when validating it; `$id` values are schema identifiers. Resolve their
cross-references from this directory, not from an unpinned remote alias.

`CHECKSUMS.sha256` pins the specifications and companion files. Run
`sha256sum --check CHECKSUMS.sha256` from this directory.
`SOURCE-MANIFEST.json` records the original source hashes. The publication
process removes internal revision notes, normalizes blank lines, updates the version label and brand
spelling, replaces an internal rollout link with prose, uses a reserved example
domain, and replaces the abstracts with scoped descriptions. It preserves
the technical requirements and code examples from the recorded source files.

DEWP anchors bind seven fields, including `seqStart`, `seqEnd` and `chainHash`.
An anchor over only the earlier four-field preimage does not satisfy this
release's verification requirements.

Copyright 2026 Janbjer Technologies AB. Licensed under Apache License 2.0;
see [LICENSE](LICENSE). Published releases are immutable; subsequent
corrections must use a new release and versioned path.
