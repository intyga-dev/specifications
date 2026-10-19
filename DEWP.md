# Deterministic Evidence & Witness Protocol (DEWP) Specification

**A Stateless Protocol Primitive for Asynchronous Witness Audit, Merkle Inclusion Proofs, and Gapless Completeness in Irreversible Infrastructure.**

*Open Specification · DEWP 1.1.0 · Edition 1.2.0 · 19 October 2026*

---

## Abstract

This document specifies the Deterministic Evidence and Witness Protocol (DEWP), a format for tamper-evident audit commitments and offline evidence verification. It defines canonical event preimages, domain-separated hashing, two-tier Merkle inclusion proofs, per-tenant sequence checks, checkpoint continuity, and independently verifiable anchor evidence. Verifiers report content, commitment, embedded-signature, and anchor verification separately. Completeness checks cover committed events within the evaluated range; they cannot prove that an event was never withheld before commitment or that a committed description accurately records a real-world action. Version 1.1 adds execution evidence: a record that an approved action was dispatched, statements signed by independent evidence sources about whether it took effect, and a status a verifier derives under its own trust; that status reports what a trusted source observed, not what physically happened. The specification also defines a streaming format that the reference implementations do not yet implement.

---

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

---

# 1. Scope & Explicit Non-Goals

DEWP narrowly defines the cryptographic structures and verification algorithms required for post-execution tamper-evidence and audit completeness.

## 1.1 Scope

DEWP specifies exclusively:

1. The canonical event preimage schema and deterministic serialization rules using JSON Canonicalization Scheme (JCS) [RFC8785].
2. Domain-separated hashing rules (`0x00` leaf tag, `0x01` node tag, `0x02` empty root tag, `0x03` anchor tag, `0x04` checkpoint-chain tag) to prevent cross-domain signature and second-preimage attacks.
3. The two-tier Merkle log tree hierarchy (Tier 1 Block Roots and Tier 2 Daily Checkpoint Roots).
4. The schema for portable single-event (`dewp.audit.inclusion-proof`), multi-event (`dewp.audit.evidence-bundle`), and streaming (`dewp.audit.evidence-stream`) proof containers.
5. Content-Verified, Commitment-Only (Privacy Redacted), Signature-Verified, and Fully-Verified validation levels.
6. The offline inclusion and gapless completeness verification procedure executed by a Relying Party or auditor.
7. Execution evidence records, the Execution Evidence Statement, and the Execution Status a verifier derives from them (§4.7).

## 1.2 Out-of-Scope (Explicit Non-Goals)

DEWP explicitly does **NOT** define:

* **Pre-Execution Intent Authorization:** Synchronous step-up approvals and intent binding are governed by companion specifications such as DIV [docs/DIV.md].
* **Storage Engine & Database Schemas:** Physical table storage, indexing, and database engine choice are implementation details.
* **Public Anchor Transports:** Specific block-anchoring transports (e.g., Git repositories, public transparency logs, distributed ledgers) are external integration choices.
* **Physical Execution:** §4.7 records what a caller-trusted evidence source reported about an action's effect. Whether that report is true of the physical world, and how a source measures it, are outside this specification (Appendix A is guidance only).

## 1.3 Relationship to DIV

DEWP and DIV are independent but complementary protocol primitives.

DIV ([docs/DIV.md]) provides pre-execution authorization evidence by cryptographically binding approval to an intended execution payload.

DEWP provides post-execution evidence by cryptographically committing completed events into an append-only audit structure.

A compliant implementation MAY combine DIV Intent Proofs with DEWP Witness Events by embedding the verified DIV payload, digest hash (`divIntentHash`), and signature metadata into the DEWP Canonical Preimage (array indices 8, 9, 10).

The presence of a DEWP Witness Event MUST NOT be interpreted as proof that DIV authorization occurred unless the associated DIV proof material is independently verified.

DIV's reserved `evidence` field (DIV §4.3.4) is a different thing: external facts an authorization may be conditioned on *before* execution, inside the signed approval. Whether the approved action then took effect is recorded *after* execution, in DEWP (§4.7), and never alters the approval.

Nothing in the preimage or its verification ties these slots to DIV specifically: indices 6..10 carry generic signer, payload and signature material, and verification per §4.6.1 checks the signature over the payload bytes without ever interpreting the payload's schema. Any pre-execution protocol whose proof is a signature over a canonical byte string can occupy them under the same rules; DIV is the companion specification this document uses as its worked example.

---

# 2. Terminology & Core Definitions

* **Witness Event:** A canonical record representing a completed state-mutating operation, approval event, or security state transition.
* **Canonical Preimage:** The exact, deterministic byte sequence constructed from an event's attributes that forms the input to the leaf hash function.
* **Leaf Hash:** The domain-separated SHA-256 digest computed over a Canonical Preimage (`hashLeaf(CanonicalPreimage)`).
* **Block Root (Tier 1):** The Merkle root computed over a short-cycle batch of Leaf Hashes.
* **Checkpoint Root / Daily Root (Tier 2):** The Merkle root computed over a sequential sequence of `hashLeaf(BlockRoot)` values, committed to an external public anchor.
* **Proof Step:** An element in a Merkle path carrying the **sibling's** hash (`siblingHash`) and the sibling's position relative to the current node (`siblingPosition`: `"LEFT"` or `"RIGHT"`), ordered strictly from **leaf to root**.
* **Inclusion Proof:** A two-hop Merkle proof comprising a `blockProof` (leaf to Block Root) and a `checkpointProof` (`hashLeaf(BlockRoot)` to Daily Root), each accompanied by the bounds (`leafIndex`/`blockLeafCount`, `checkpointLeafIndex`/`checkpointLeafCount`) that make it a proof of membership rather than a proof that some path exists.
* **Verification Properties:** Four independent boolean properties a verifier evaluates — `commitmentVerified`, `contentVerified`, `signatureVerified`, and `anchorVerified` (see §7.1). These are orthogonal: anchor verification is NOT a strict superset of signature verification.
* **Verification Level:** A summary classification derived from the four properties: `INVALID`, `COMMITMENT_VERIFIED`, `CONTENT_VERIFIED`, `SIGNATURE_VERIFIED`, or `FULLY_VERIFIED`.
* **Content-Verified Entry:** A proof entry where the full Canonical Preimage is present, enabling offline verification of both tree inclusion and exact event parameter binding.
* **Commitment-Only Entry:** A privacy-redacted proof entry where event content has been purged under data retention rules, enabling offline verification of historical commitment without exposing sensitive event text.
* **Tenant Sequence (`tenantSeq`):** A strictly monotonic, gapless 64-bit integer assigned sequentially to a tenant's committed audit events.
* **Global Sequence (`seq`):** A strictly monotonic numeric ordering counter (stringified 64-bit integer). Distinct from the event **identifier** `id`.
* **Evidence Source:** A party independent of the one that sent a command, which observes the command's effect and signs an Execution Evidence Statement about it (§4.7.2).
* **Execution Evidence Statement:** The canonical object of type `dewp-execution-evidence` an evidence source signs, binding a verdict and an observation to one approval's nonce and payload hash (§4.7.2).
* **Execution Status:** The per-approval result a verifier derives from Approval, Dispatch and Evidence Records under its own evidence-source trust: `confirmed`, `contradicted`, `unconfirmed`, `pending` or `not_reported`, reported together with the §4.7.4 findings (dispatch conflict, late contradiction, untrusted contradiction, window capped, source continuity).
* **Event Identifier (`id`):** An opaque unique event ID (RECOMMENDED RFC 9562 UUIDv7 for time-ordered sortability). It is an identity value, not an arithmetic ordering counter; verifiers MUST NOT perform `+1` continuity arithmetic on `id`.

---

# 3. Protocol Invariants

A compliant DEWP implementation MUST satisfy the following structural invariants:

1. **Domain-Separated Cryptographic Hashing**

   To prevent an interior-node hash (or an empty-root, anchor, or chain preimage) from being reinterpreted as a valid leaf preimage, hashing MUST employ distinct one-byte domain-separation prefixes. This applies the Merkle audit-path domain-separation technique of RFC 6962 §2.1 (leaf tag vs node tag), extended here with empty-root, anchor, and chain tags:
   - Leaf Hash: `SHA-256(byte(0x00) || UTF8(CanonicalPreimageBytes))`
   - Node Hash: `SHA-256(byte(0x01) || hexDecode(LeftChildHash) || hexDecode(RightChildHash))`
   - Empty Tree Root: `SHA-256(byte(0x02))`
   - Anchor Signature Preimage: `SHA-256(byte(0x03) || UTF8(JCS(AnchorPreimageArray)))`
   - Checkpoint Chain Hash: `SHA-256(byte(0x04) || UTF8(JCS(ChainPreimageArray)))` (§5.4)

2. **Deterministic Preimage Binding**

   For unredacted entries, the Relying Party MUST verify that the Leaf Hash in an Inclusion Proof equals `leafHash(CanonicalPreimage)`.

3. **Two-Hop Hierarchy Binding & Leaf-to-Root Proof Ordering**

   A valid inclusion proof MUST satisfy two distinct Merkle path verification steps ordered strictly from **leaf to root**, and each step MUST be bounded by the leaf's position and its tree's leaf count (§11.1):
   - Step 1 (Event Leaf): `verifyMerkleProof(leaf, blockProof, blockRoot, {index: leafIndex, leafCount: blockLeafCount}) == true`
   - Step 2 (Block Root): `verifyMerkleProof(hashLeaf(blockRoot), checkpointProof, dailyRoot, {index: checkpointLeafIndex, leafCount: checkpointLeafCount}) == true`

   The bounds are REQUIRED, not advisory. Because this tree self-pairs an unpaired trailing node, an unbounded path check accepts a proof for a leaf that was never in the tree — see §11.1.

4. **Gapless Tenant Completeness (of Committed Events)**

   Every committed tenant event MUST carry a strictly monotonic `tenantSeq` integer counter (`tenantSeq_N+1 == tenantSeq_N + 1`).

   Auditors verifying an Evidence Bundle MUST reject any sequence containing gaps, duplicates, or out-of-order `tenantSeq` values.

   **Which copy of the counter is read is normative.** An Evidence Bundle carries `tenantSeq` in more than one place and only one of them is covered by the Merkle commitment. The check MUST read the leaf-bound counter — the final element of the Canonical Preimage (§4.1) — for every entry that carries a preimage; the sibling `event.tenantSeq` is a display copy that nothing signs, so a check run over it is satisfied by renumbering it. §7.2 gives the full source-precedence, disclosure and range cross-check rules.

   **Scope of the guarantee:** This detects **modification or deletion of already-committed events** — a producer cannot silently drop, reorder, or alter an event that was assigned a `tenantSeq` and committed under a published anchor without leaving a gap or a broken leaf hash. It does **NOT** prove that a producer never withheld an event from commitment in the first place: an event that was never assigned a `tenantSeq` leaves no hole to detect. Completeness claims MUST be scoped to the committed, anchored history, not to all real-world events.

5. **Global Sequence Monotonicity**

   The numeric global sequence `seq` MUST satisfy `seq(N+1) > seq(N)`. `seq` is an arithmetic ordering counter and MUST be numeric; it MUST NOT be a UUID. Time-ordered event **identifiers** (`id`), when used, are a separate field (RECOMMENDED RFC 9562 UUIDv7) and MUST NOT be used for `+1` continuity arithmetic.

6. **Offline Inclusion Verification**

   Verification of an Inclusion Proof MUST run locally in the auditor's process by checking that `blockProof` and `checkpointProof`, each bounded per §11.1, recompute to the trusted Checkpoint Root. Verification MUST NOT require network calls or proprietary API keys.

   The Daily Root that carries a **trust** verdict MUST be one the auditor obtained independently of the artifact under verification — a root it recorded earlier, or one from the published roots file (§5.4.1) whose chain it has checked. An external anchor cannot supply it: a Rekor entry stores a hash of the §5.2 anchor digest and an RFC 3161 token the digest itself, and neither reveals the root; what the anchors provide is a check on a root the auditor already holds (§5.3). A root carried inside the artifact — `proof.checkpointRoot`, or the `dailyRoot` inside a bundle-carried anchor — MUST NOT be treated as that trusted value, MUST NOT be reported as anchored, and MUST NOT support a non-repudiation claim: a bundle that supplies its own root vouches for itself.

   This forbids *trusting* a self-supplied root, not *computing against* one. Recomputing the two hops against a bundle-carried root, and reporting the outcome as an internal-consistency property explicitly labelled self-asserted, is permitted — that property is §7.1's `commitmentVerified`, and §7.1 is where the two readings reconcile: `commitmentVerified` says an entry recomputes to the root in hand, and only `anchorVerified` says that root is anyone else's.

   A verifier cannot tell where a root handed to it came from. It MUST NOT report a caller-supplied root as "independent": a root the caller copied out of the very bundle under verification is indistinguishable, to the verifier, from one recorded a year earlier. The reference implementations report `rootSource: "caller-supplied"`, and the independence of that root is the caller's claim to make, not the verifier's.

7. **Independent Anchor Verification (Quorum)**

   `anchorVerified` (and therefore `FULLY_VERIFIED`) is satisfied if and only if the Checkpoint Root is verified against an **anchor quorum** as defined by the verifier's anchor policy (§5.3): at least `requiredAnchors` distinct anchors, each signed by an issuer in `trustedIssuers`, MUST present a valid signature over the **same** `dailyRoot` — binding the checkpoint's position, and for an external witness authenticated within the §5.3 time bound of the checkpoint's claimed time. A single anchor provider is a single point of compromise; `requiredAnchors` SHOULD be ≥ 2 for high-assurance non-repudiation. If two trusted anchors that the verifier obtained itself for the same checkpoint (out of band or through discovery) sign **different** roots, the verifier MUST treat the result as `INVALID` (anchor divergence) rather than pick one. A bundle-carried anchor set MUST NOT be treated as able to establish divergence (§6.3): the producer chooses what a bundle carries, so the bundle is no evidence that nothing conflicting exists. Self-asserted roots within unanchored bundles MUST NOT be treated as authoritative proof of non-repudiation.

---

# 4. Canonical Preimage and Cryptographic Definitions

## 4.1 Canonical Array Preimage Representation (DEWP Core)

The DEWP Core Canonical Preimage MUST be represented as an ordered JSON array serialized using RFC 8785 JSON Canonicalization Scheme (JCS). It is defined by a single canonical rule:

- **Fixed core fields:** indices `0..10` (`seq` .. `sigAlg`) MUST appear in the order defined in §4.2 and MUST NOT be reordered.
- **`tenantSeq` is always the final element** of the array (`array[array.length - 1]`).
- **Bare Core:** with no Application Profile, the array has exactly **12** elements — fixed fields `0..10` followed by `tenantSeq` at index `11`.
- **Profiles (§4.5):** an Application Profile MAY insert profile fields at indices `11..N-1`; `tenantSeq` is then relocated to the final index `N`. It is never at a fixed numeric index other than "last".

Vendor- or application-specific attributes MUST NOT be inserted among the fixed core fields `0..10`; they MUST be carried in `metadata` (index 5) or appended as profile fields per §4.5.

```json
[
  "1048576",
  "2026-07-24T12:00:00.000Z",
  "ACTION_APPROVED",
  "SUCCESS",
  "Database drop approved",
  "{\"target\":\"users\"}",
  "did:example:human:alice",
  "base64-spki-public-key",
  "{\"actionType\":\"db:dropTable\",\"type\":\"div-intent-verification\",\"v\":1}",
  "base64-signature",
  "ES256",
  "42"
]
```

## 4.2 Array Element Definitions (DEWP Core)

| Index | Field | Type | Requirement | Description |
|:---:|---|---|---|---|
| 0 | `seq` | string | REQUIRED | Global numeric ordering counter (stringified 64-bit integer). MUST NOT be a UUID. The opaque event identifier (`id`, RECOMMENDED UUIDv7) is a separate bundle-level field, not a Core preimage element in v1. |
| 1 | `createdAt` | string | REQUIRED | ISO 8601 UTC timestamp (`YYYY-MM-DDTHH:mm:ss.sssZ`, zero offset). |
| 2 | `event` | string | REQUIRED | Event **type** / name (e.g. `ACTION_APPROVED`), not a per-event unique id. |
| 3 | `outcome` | string | REQUIRED | Outcome status. The registered values are `SUCCESS`, `FAILURE` and `PENDING`. `PENDING` is load-bearing rather than transitional: an event that RECORDS A REQUEST — a challenge raised, a signature received, a document submitted for signing — is committed to the ledger when it happens, and its outcome is not yet known. Suppressing those events until they resolve would leave the request itself unwitnessed, which is the opposite of what the log is for. A verifier MUST NOT treat `PENDING` as a failure, and MUST NOT assume a later event resolving it appears in the same bundle. Earlier drafts of this table listed `DENIED`; no producer emits it (a refusal is carried by the event type, e.g. `AUTHZ_DENIED`, with its own outcome), and it is not a registered value. |
| 4 | `detail` | string \| null | REQUIRED | Human-readable detail string (max 4,096 bytes; informational unless signed). |
| 5 | `metadata` | string | REQUIRED | Compact **JCS** string of metadata (max 65,536 bytes; `jcs(metadata ?? null)` — i.e. RFC 8785 with keys sorted recursively by **UTF-16 code units** (§3.2.3 — a surrogate-pair key sorts before U+FFFD; pinned by the `metadata-utf16-key-order` golden vector), **not** `JSON.stringify`, which preserves insertion order and would make the leaf depend on how the producer happened to build the object). |
| 6 | `signerDid` | string \| null | REQUIRED | DID of the signing party (if applicable). |
| 7 | `signerPublicKey` | string \| null | REQUIRED | Base64-encoded public key (SPKI or COSE). |
| 8 | `signedPayload` | string \| null | REQUIRED | Exact canonical payload string signed (embedded intent-proof material, §4.6). |
| 9 | `signature` | string \| null | REQUIRED | Base64-encoded signature (embedded intent-proof material, §4.6). |
| 10 | `sigAlg` | string \| null | REQUIRED | Signature algorithm identifier (`ES256`, `WEBAUTHN`, `AUTO_APPROVED`). |
| 11 | `tenantSeq` | string \| null | REQUIRED | Per-tenant monotonic sequence counter (stringified 64-bit integer). |

## 4.3 Canonical Null, Timestamp, and Size Bound Rules

- **Canonical Null Rules:** A bare DEWP Core array MUST contain exactly 12 elements (a profile array contains `12 + (number of profile fields)` elements, with `tenantSeq` always last). Missing fields MUST NOT be omitted; they MUST be represented as explicit `null`. An empty string `""` MUST NOT be treated as `null`.
- **Timestamp Rules:** Timestamps MUST be formatted as ISO 8601 UTC strings (`YYYY-MM-DDTHH:mm:ss.sssZ`) with millisecond precision and a literal `'Z'` zero timezone offset. Implementations SHOULD attach RFC 3161 Timestamp Authority (TSA) tokens for high-assurance timestamp non-repudiation.
- **Size Bounds:** The `detail` field SHOULD NOT exceed 4,096 bytes. The `metadata` field SHOULD NOT exceed 65,536 bytes (64 KB). The total Canonical Preimage JCS byte string SHOULD NOT exceed 131,072 bytes (128 KB). *(These were stated as MUST in an earlier revision. No producer or verifier in the reference implementation enforces them, and a verifier that started rejecting oversized leaves would fail to verify history it had already anchored. They are downgraded to SHOULD to match reality; a future revision may enforce them at the producer only.)*
- **ID Monotonicity:** Event identifiers SHOULD be RFC 9562 UUIDv7 strings to guarantee time-ordered sortability across distributed systems.

### 4.3.1 Portable Number Range

RFC 8785 defines a serialization for every finite double, but independent implementations disagree in practice: each language's number formatter switches to exponent notation at its own threshold, and `-0` has no single spelling. Because the `metadata` element (§4.2 index 5) is hashed as text, two verifiers that format one number differently compute different leaf hashes for the same row — which presents as tampering, the most damaging way for evidence to fail.

A number appearing anywhere in `metadata` is **portable** when it is finite, is not `-0`, and satisfies one of:

- it is an integer with `|x| < 1e16`; or
- it is `0`; or
- it is a non-integer with `1e-4 <= |x| < 1e16`.

**Producers MUST NOT commit a leaf whose `metadata` contains a non-portable number.** A value outside the range MUST be carried as a string, as an integer in smaller units, or not at all. This is a producer obligation because it is the only place the problem can be solved once: after commitment the leaf hash is fixed and every verifier must live with it.

**Verifiers MAY** either refuse to canonicalize a non-portable number (reporting the leaf as unverifiable) **or** serialize it on a best-effort basis and report an ordinary content mismatch. Both are conformant; a non-conformant producer is what puts a verifier in that position. The best-effort path has a limit worth stating plainly: a verifier whose number formatter happens to match the producer's reproduces the committed bytes exactly and reports the leaf as content-verified. That verdict attests inclusion of the committed bytes — it does not attest that the content is portable, and the same leaf will fail content verification in every port whose formatter differs. A leaf that verifies only under one language's number formatting is precisely the interoperability failure the producer MUST above exists to prevent; the producer rule, not the verifier, is the load-bearing control here. *(Normative change in this revision: an earlier draft added "a verifier MUST NOT report such a leaf as verified" — a requirement the best-effort path cannot satisfy when the verifier's formatter matches the producer's, and which every best-effort reference implementation therefore violated. That sentence is withdrawn; the two verifier options above are the complete conformance surface.)*

**Shortest round-trip formatting applies here too.** Inside the portable range a number in `metadata` MUST serialize as the shortest decimal string that round-trips to the same double, per **DIV §4.1.1.1** — which also records why a language's built-in formatter may not be conformant (notably Java's `Double.toString` before JDK 19). Because `metadata` is hashed as text, an implementation that emits extra digits computes a different leaf hash for the same row and reports it as tampering. DIV §4.1.1's caveat on integers above `2^53` applies to `metadata` identically: an arbitrary-precision runtime preserves such an integer's exact digits where a double-based one rounds them, so the same row hashes differently across ports — keep integers within `±2^53` or carry them as strings.

*(Reference implementations: the producer refuses at ingestion; `verify-go` refuses to canonicalize; `verify`, `verify-rust` and `sdk-python` best-effort match the TypeScript reference. `verify-java` refuses, with one exception it cannot see: its JSON parser normalizes an integer-form `-0` to `0` before the check runs, so that single value is best-effort — like `verify-rust`. The DIV signing path applies the identical range at signing time — see DIV §4.1.1.)*

## 4.4 Cryptographic Hash Definitions

All cryptographic digests in DEWP MUST use **SHA-256** as defined by FIPS 180-4.

Digest values MUST be encoded as 64-character lowercase ASCII hexadecimal strings (e.g. `d4e5f6a1b2c3...`).

The normative hash functions are:

- `sha256Hex(dataBytes)`: Computes `SHA-256(dataBytes)` and returns a 64-character lowercase hex string.
- `hashLeaf(preimageStr)`: Computes `sha256Hex(byte(0x00) || UTF8Bytes(preimageStr))`.
- `hashPair(leftHex, rightHex)`: Computes `sha256Hex(byte(0x01) || hexDecode(leftHex) || hexDecode(rightHex))`. The two child digests are **hex-decoded to their raw 32 bytes** before hashing (they are NOT concatenated as hex strings). Order encodes position (`left` then `right`) and MUST NOT be sorted.

## 4.5 Application Profiles & Extension Arrays

Applications requiring additional domain-specific or platform-specific attributes MUST carry them inside element 5 (`metadata`) or define an explicit **Application Profile**.

### Profile Extension Array Rules:
1. Core fields `0..10` (`seq` .. `sigAlg`) MUST remain fixed in position and semantic.
2. Extension profile fields MUST be inserted at indices `11..N-1` — **after** core field 10 and **before** the final `tenantSeq`. They MUST NOT displace `tenantSeq` from the last position.
3. `tenantSeq` MUST ALWAYS occupy the **final element** of the canonical array (`array[array.length - 1]`). This is the single, unambiguous rule for `tenantSeq`'s location in both Core and profiles.
4. Profile naming MUST follow reverse-DNS format: `vendor.profileName.vVersion` (e.g. `org.example.audit.v1`).

### Informative Example: Extended Application Profile (`profile: "org.example.audit.v1"`)

| Index | Field | Scope | Description |
|:---:|---|---|---|
| 0..10 | `seq` .. `sigAlg` | DEWP Core | Universal event attributes |
| 11 | `isBillable` | `example.v1` Profile | Application billing classification flag |
| 12 | `tenantId` | `example.v1` Profile | Organization / tenant ID |
| 13 | `actorNodeId` | `example.v1` Profile | Actor node identifier |
| 14 | `subjectNodeId` | `example.v1` Profile | Subject node identifier |
| 15 | `edgeId` | `example.v1` Profile | Relationship edge identifier |
| 16 | `challengeId` | `example.v1` Profile | Approval challenge identifier |
| 17 | `tenantSeq` | DEWP Core (Final Element) | Per-tenant monotonic sequence counter |

### Registered Profiles

| Profile | Layout |
|---|---|
| *(none)* | Bare DEWP Core — 12 elements, `tenantSeq` at index 11. |
| `trust.intyga.audit.v1` | Core `0..10`, then `isBillable`, `tenantId`, `actorNodeId`, `subjectNodeId`, `edgeId`, `challengeId`, then `tenantSeq` at index 17 — the layout tabulated above. |

A bundle SHOULD declare its profile in a top-level `profile` field. A verifier encountering a profile it
does not implement MUST NOT attempt content verification against it: recomputing the leaf under a
different field order yields a mismatch indistinguishable from tampering. It MUST instead report
`contentVerified: false` and continue to evaluate `commitmentVerified`, which is profile-independent.
Reporting `contentVerified: false` does not make the artifact pass: the profile is a producer-supplied
field, so a verifier MUST NOT return an overall pass for a proof (§6.2) or an Evidence Bundle entry (§6.3)
that ships a preimage it could not bind. An entry with no preimage (a `COMMITMENT_ONLY` redaction) has
nothing to bind and still verifies as commitment-only.

---

## 4.6 Event Signature Scope

The event-level signature material carried in the preimage (`signerDid`, `signerPublicKey`, `signedPayload`, `signature`, `sigAlg` — indices 6..10) is **embedded intent-proof material**, reproduced by reference from a pre-execution authorization protocol — in this document's examples, DIV (`docs/DIV.md`) — **or an Execution Evidence Statement** signed by an evidence source (§4.7). The scope rules below apply to both; §4.7.5 says which trust a verifier applies to which. Its scope MUST be understood precisely to avoid over-claiming:

- **`signedPayload` is the exact, verbatim canonical byte string the signer's key signed** — for a DIV approval, the DIV Intent Payload (`{"actionType":...,"type":"div-intent-verification","v":1}`). It is reproduced byte-for-byte; DEWP does not re-serialize it.
- **`signature` covers ONLY the bytes of `signedPayload`.** It does NOT cover any DEWP field — not `seq`, not `tenantSeq`, not `createdAt`, not the surrounding preimage array. A verifier MUST NOT infer that the signer attested to the DEWP sequence numbers, timestamps, or Merkle position.
- **What binds the DEWP fields is the Merkle commitment, not the event signature.** Integrity of `seq`/`tenantSeq`/`createdAt`/etc. derives from `leafHash(CanonicalPreimage)` being committed under an anchored root (§3 Invariants 2 and 3), a property independent of whether any event signature is present.
- Consequently, a `SIGNATURE_VERIFIED` result asserts *"a named key signed exactly `signedPayload`"* and nothing about the DEWP envelope; a `CONTENT_VERIFIED` result asserts the envelope was committed. Both are required to conclude *"this signed action was recorded at this position."*

### 4.6.1 Verifiability of each `sigAlg` from the leaf alone

The Core preimage carries only `signerPublicKey`, `signedPayload`, `signature` and `sigAlg`. That is
sufficient for a raw signature but not for every registered algorithm:

| `sigAlg` | Verifiable from the Core preimage? |
|---|---|
| `ES256` | **Yes.** `signature` over `signedPayload` under `signerPublicKey` (SPKI, P-256). |
| `WEBAUTHN` | **No.** A WebAuthn assertion signs `authenticatorData ‖ SHA-256(clientDataJSON)`, and neither component has a Core slot. A verifier MUST report `signatureVerified: false` for such an event rather than guess, so a passkey-approved event tops out at `CONTENT_VERIFIED` unless a profile carries the two components. |
| `AUTO_APPROVED` | **No signature exists.** A policy pre-approval carries no human attestation; `signatureVerified` is false and MUST NOT be read as a failure. |

An implementation needing offline signature verification of passkey approvals MUST define an
Application Profile carrying `authenticatorData` and `clientDataJSON`; verifying such an assertion also
requires the expected `origin` and RP ID, which are deployment configuration and not evidence, so they
MUST be supplied by the verifier rather than read from the bundle.

The `trust.intyga.audit.v1` Application Profile uses the existing committed `metadata` element:
`metadata.webauthn.authenticatorData` and `metadata.webauthn.clientDataJSON` carry the browser's
base64/base64url assertion components. These fields are already covered by the canonical metadata
serialization; no preimage field ordering or hashing changes. Their absence in older exports means
WebAuthn is not checkable. Verification MUST bind the assertion challenge to the exact `signedPayload`,
pin the expected origin and RP ID from caller configuration, require UP and UV, and refuse cross-origin
ceremonies. The reference ports accept caller-provisioned COSE P-256 keys mapped to signer DID.
The embedded key alone MUST NOT establish trusted signer identity.

The reference APIs report signature status (`verified`, `invalid`, `not_checked`, `not_applicable`),
a reason and a separate `trusted` flag. An absent algorithm with remaining signature material is
`not_checked`, not an unsigned event. Diagnostic mode preserves independent commitment/content
verdicts even for an invalid signature. Caller-selected `requireSignatures` additionally requires a
verified, caller-trusted signature on every selected entry; absent trust, unknown algorithms,
redacted/unsigned entries and invalid signatures fail that gate. This does not verify the enclosing
DIV approval policy, quorum, expiry, expected operation, hardware attestation or execution.



## 4.7 Execution Evidence

A pre-execution approval (DIV) establishes that a human approved exact bytes. A committed DEWP event
establishes that a record was not altered after commitment. Neither says whether the approved action
then took effect. This section defines how a producer records that question and its answer, and how a
verifier evaluates them, without changing the Canonical Preimage, the leaf hash, any Application
Profile layout, or the bundle `version` (`"1.0"`). Every record defined here is an ordinary leaf, so a
verifier that does not implement this section still verifies its commitment and content.

The answer is only as good as the party that observed it. §4.7 records **what a caller-trusted evidence
source reported**, signed by that source. It does not prove what physically happened, and a verifier
MUST NOT present an execution status as more than that (§4.7.6).

### 4.7.1 Records

Four event types are defined. Each is identified by the `event` element (§4.2 index 2); a producer
writes the outcome and signature slots shown. Verifiers identify a Dispatch Record by its `event`,
`metadata` and `createdAt` alone, and an Evidence Record as §4.7.3 says; the outcome of a Dispatch or
Unconfirmed Record is a producer convention that §4.7.3–§4.7.4 do not read. The approval a record refers
to is identified by the DIV `nonce` (DIV §4.3), which is unique per approval. In this revision an
**Approval Record** is a leaf carrying an ordinary DIV Intent Payload (`type` `div-intent-verification`,
located as §4.7.3 step 5 says). Offline approvals (DIV §5a), delegations, agent-authority seals and
platform intents (DIV §5c) are not Approval Records: an action approved through them cannot be
dispatched or confirmed under §4.7, and a statement naming one reads `unbound`.

| `event` | `outcome` | Signature slots (indices 6..10) | `metadata` (index 5) |
|---|---|---|---|
| `EXECUTION_DISPATCHED` | `PENDING` | all `null` | object containing `nonce`, `payloadSha256`, `evidenceDeadline` |
| `EXECUTION_CONFIRMED` | `SUCCESS` | Execution Evidence Statement, `ES256` | any |
| `EXECUTION_CONTRADICTED` | `FAILURE` | Execution Evidence Statement, `ES256` | any |
| `EXECUTION_UNCONFIRMED` | `FAILURE` | all `null` | any |

- A **Dispatch Record** states that the executing party sent the approved action to its target and
  expects evidence by `evidenceDeadline`. Its `metadata` MUST be an object whose `nonce` is the approval's
  DIV nonce, whose `payloadSha256` is the lowercase hex SHA-256 of the UTF-8 bytes of the approved DIV
  Intent Payload, and whose `evidenceDeadline` follows the §4.3 timestamp rule. Other members are
  permitted and are ignored by §4.7.3–§4.7.4; a leaf of this event type whose `metadata` does not
  satisfy these rules, or whose `createdAt` does not, is not a Dispatch Record. A Dispatch Record is
  written by or on behalf of the party
  that executes, which is the party least able to attest that execution succeeded; it is therefore never
  evidence of success. Several Dispatch Records MAY name one nonce (a retry, a re-dispatch). Because the
  executing party writes them, a verifier never lets one of them decide which statements bind (§4.7.3
  step 5), bounds the window they open (§4.7.3 step 6), and reports records for one nonce that disagree
  on `payloadSha256` as a dispatch conflict (§4.7.4). A later record never reopens or extends the
  window: the lowest-seq matching record governs it, so a re-dispatch after the first window closed is
  recorded but cannot be confirmed — otherwise re-dispatching would keep a nonce `pending` at will.
- An **Evidence Record** carries one Execution Evidence Statement (§4.7.2) in its signature slots:
  `signerDid` is the statement's `source`, `signerPublicKey` the base64 SPKI of the P-256 key that
  signed it, `signedPayload` the statement bytes, `signature` the base64 ECDSA P-256 / SHA-256 signature
  over those bytes (IEEE P1363 or DER, as for `ES256` in §4.6.1), and `sigAlg` `ES256`. Its `event` and
  `outcome` MUST match the signed `verdict` as tabulated. A producer relays a statement; it cannot author
  one, because it does not hold the source's key.
- An **Unconfirmed Record** is the producer's own, unsigned note that `evidenceDeadline` passed without
  qualifying evidence. It is an alarm, not evidence: verifiers derive `unconfirmed` themselves (§4.7.4)
  and MUST NOT require or rely on this record. A negative statement needs no trusted signer, so this is the
  only §4.7 record a producer writes on its own authority.

All four are appended, never updated. Evidence that arrives after an Unconfirmed Record is still
committed; the history keeps both.

### 4.7.2 Execution Evidence Statement

The statement is the object an **Evidence Source** signs: a party independent of the one that sent the
command — for example a protection relay reporting breaker position, or a measured-boot attestation
reporting the digest of the firmware that actually booted.

```json
{
  "approval": {
    "nonce": "4f6c1c9e-1b8a-4e2f-9d3a-7c2b5e8f0a1d",
    "payloadSha256": "5d1f…(64 lowercase hex)…"
  },
  "observation": { "breaker": "open", "currentA": 0, "previousCurrentA": 412 },
  "observedAt": "2026-10-05T14:02:11.000Z",
  "sampledAt": "2026-10-05T14:02:09.500Z",
  "sequence": 418,
  "source": "did:example:relay-7",
  "type": "dewp-execution-evidence",
  "v": 1,
  "verdict": "confirmed"
}
```

Normative rules:

1. The statement MUST be a JSON object with exactly the nine members shown, and `approval` MUST have
   exactly the two members shown.
2. `type` MUST be the string `dewp-execution-evidence` and `v` the integer `1`. The type is distinct from
   every DIV payload `type`, so a statement can never verify as an approval and an approval can never
   verify as a statement; DIV approval verifiers MUST refuse it.
3. `approval.nonce` MUST be a non-empty string: the DIV nonce of the approval the evidence is about.
   `approval.payloadSha256` MUST be 64 lowercase hexadecimal characters: the SHA-256 of the UTF-8 bytes
   of that approval's DIV Intent Payload. The hash binds the evidence to the exact approved bytes, so a
   statement cannot be moved to another approval.
4. `source` MUST be a non-empty string naming the evidence source, and MUST equal the Evidence Record's
   `signerDid`.
5. `verdict` MUST be `confirmed` (the source observed the approved effect) or `contradicted` (the source
   observed that it did not take effect, or took a different effect). A source that cannot decide MUST NOT
   sign; the absence of qualifying evidence is what produces `unconfirmed`.
6. `observedAt` MUST follow the §4.3 timestamp rule. It is the source's claim of when it produced the
   statement; when the measurement behind it was taken is `sampledAt` (rule 11).
7. `observation` MUST be a JSON object and MAY be empty. Its content is domain-specific, covered by the
   signature, and not interpreted by §4.7.3–§4.7.4. Appendix A gives non-normative guidance on what it
   should establish.
8. Every number anywhere in the statement MUST be portable (§4.3.1) and MUST have a magnitude of at
   most 2^53 − 1 (9007199254740991), no string in it may contain an unpaired surrogate (DIV §4.1), and it
   MUST NOT nest arrays and objects more than 64 levels deep (the statement object itself is level 1).
   The integer bound is tighter than §4.3.1's because some parsers read every number as a double: above
   2^53 they would read a different integer from the same digits, and the same bytes would be a
   different statement in different verifiers.
9. The statement bytes MUST be the RFC 8785 serialization of the statement's own parsed value. A verifier
   MUST parse the bytes as described in §4.7.7, re-serialize them under RFC 8785 and compare, and MUST
   treat a parse failure or a mismatch as malformed. This makes duplicate member names, insignificant whitespace and non-canonical number or
   string spellings malformed, so every conformant parser reads the same statement from the same bytes.
10. The statement bytes MUST NOT exceed 16,384 bytes.
11. `sampledAt` MUST follow the §4.3 timestamp rule and MUST NOT be later than `observedAt`. It is the
    source's claim of when the measurement behind `observation` was taken. The evidence window (§4.7.3
    step 6) is evaluated on `sampledAt`, so a statement produced inside the window over a measurement
    taken outside it is `stale`; a source that reports a measurement it took earlier says so by signing
    the earlier time.
12. `sequence` MUST be an integer from 1 to 2^53 − 1: the source's own count of statements it has signed
    for this producer's log, incremented by exactly one per statement and never reused. The log is the
    unit an Evidence Bundle is exported for — on a multi-tenant producer, one tenant's log. A source
    that signs for several logs keeps a counter per log; one counter shared across logs shows as gaps in
    each. The counter is what lets a verifier see a statement that is missing from the bundle (§4.7.3,
    Source continuity).

### 4.7.3 Statement Check

A verifier reads only content-verified entries (§7.1): a redacted entry, or a preimage that is not
bound to its leaf, is not read as any §4.7 record, as §7.2 already requires of every other field.

For each Evidence Record — a content-verified leaf whose `event` is `EXECUTION_CONFIRMED` or
`EXECUTION_CONTRADICTED`, or whose `signedPayload` parses (§4.7.7) as a JSON object with `type` equal to
`dewp-execution-evidence`; either suffices, so a record cannot avoid evidence-source trust by
mislabelling one side — a verifier MUST report a check with a `status`, a `reason` and a `trusted` flag,
applying these steps in order. The first step that decides the status ends the check, except that
`trusted` set in step 4 is retained by steps 5 and 6.

1. `sigAlg` is not `ES256`, or `signature`, `signerPublicKey` or `signedPayload` is missing: `invalid`.
2. The statement violates any rule of §4.7.2 other than rule 4: `invalid`.
3. `source` differs from `signerDid`, or `event`/`outcome` do not match `verdict` (§4.7.1): `invalid`.
4. Signature:
   - Without an evidence-source trust policy, the signature is checked under the embedded
     `signerPublicKey`: `invalid` if it does not verify, otherwise `trusted` is false and the check
     continues. As in §4.6.1, an embedded key MUST NOT establish who the source is.
   - With a policy, the caller-provisioned keys for `source` are tried in turn. None provisioned:
     `not_checked`. None verifies: `invalid`. One verifies: the check continues, and `trusted` is true
     unless that key carries a validity interval (§4.7.5) and the record's anchored time is unknown or
     lies outside it; then `trusted` is false and the reason says so. An unbounded key needs no
     anchored time.
   - Evidence-source trust is separate from approver trust. A verifier MUST NOT accept an approver's key
     as an evidence source's, or the reverse (§4.7.5).
5. Binding, evaluated over the content-verified entries of the same bundle:
   - the **matching Dispatch Records** for `approval.nonce` are those whose `metadata.payloadSha256`
     equals the statement's; there is none: `unbound`. The **governing Dispatch Record** is the matching
     one with the lowest `seq`. A Dispatch Record carrying another hash never decides this step: the
     executing party writes Dispatch Records, and letting its earliest one govern would let it unbind
     every genuine statement by committing one wrong record first;
   - no **Approval Record** exists — a leaf whose `signedPayload` parses (§4.7.7) as a JSON object with `type`
     `div-intent-verification` and `nonce` equal to `approval.nonce`, and whose `signedPayload` bytes hash
     to `approval.payloadSha256`: `unbound`.
6. Window. The **effective deadline** is the earlier of the governing Dispatch Record's `evidenceDeadline`
   and its `createdAt` plus the verifier's maximum evidence window: the window is bounded by the
   verifier, never by the dispatch alone, or an executing party could keep a nonce `pending` forever.
   `sampledAt` earlier than the governing record's `createdAt` minus the skew allowance: `stale`
   (reason `early`); later than the effective deadline: `stale` (reason `late`). The skew allowance
   covers clock error between the source and the producer and nothing else — it also admits a
   measurement taken just before dispatch, which for an action with no visible change confirms a no-op —
   so it is small: this profile's default is 30 seconds. The maximum evidence window defaults to 86 400
   seconds. Both are caller-overridable per verification and MAY be given other defaults by an
   Application Profile; a slow process is accommodated by raising them for that verification, never by
   leaving them loose.
7. Otherwise: `verified`.

**Source continuity.** Over the Evidence Records whose check passed step 4 (the statement parsed, its
`source` matches, and its signature verified under the embedded or a provisioned key), a verifier MUST
also report, per `source`: the smallest and largest `sequence` seen, every integer strictly between them
that no record carries (a **gap**), and every value carried by two records whose statement bytes differ
(a **divergence**). A gap means a statement the source signed is absent from the bundle, whether withheld
from commitment or outside the exported range; a divergence means the source, or someone holding its
key, signed two statements under one counter value. Neither changes a statement's own check or an
Execution Status; both are findings (§4.7.4). Only the range inside the bundle can be checked: a source
that stops signing, or whose later statements were all withheld, leaves no gap. A gap closes when the
missing statement is committed later: refusal commits nothing, so a statement lost in transit, or
refused for a cause the relaying party can fix, can be relayed again. A statement the producer can
never accept — malformed, or signed under a key it will never register — leaves a permanent gap, and a
caller applying the require-all policy (§4.7.4) must expect it. A producer that refuses a statement it
could parse SHOULD record the refusal where its operators can see it, naming the `source` and the
`sequence`, so a gap can be explained from the log.

A single Inclusion Proof carries one leaf, so only steps 1–4 can be evaluated for it; a verifier MUST NOT
report a single proof's statement as `verified`, and reports `unbound` with that reason.

A check other than `verified` MUST be reported and MUST NOT by itself invalidate the entry's commitment,
content or signature verification: the statement is committed evidence that does not support the claim,
not evidence that the bundle was altered.

### 4.7.4 Execution Status

For every DIV nonce named by a content-verified Approval Record, Dispatch Record or Evidence Record in an
Evidence Bundle, a verifier implementing this section MUST report an **Execution Status**. Approval
Records are enumerated so that an approval with no dispatch and no evidence is reported rather than
passed over: silence is the case a caller requiring confirmation most needs to see.

| Status | Condition, evaluated in this order |
|---|---|
| `contradicted` | Some statement for the nonce is `verified`, `trusted`, with verdict `contradicted`. |
| `confirmed` | Some statement for the nonce is `verified`, `trusted`, with verdict `confirmed`. |
| `not_reported` | There is no Dispatch Record for the nonce. |
| `unconfirmed` | The governing Dispatch Record's effective deadline (§4.7.3 step 6) is earlier than the evaluation time. |
| `pending` | Otherwise. |

Where no statement for the nonce reached §4.7.3 step 6, the governing Dispatch Record is the one with
the lowest `seq` among those naming the nonce. `contradicted` takes precedence over `confirmed`: one
trusted source that saw the action fail outweighs another that saw it succeed, and the disagreement is
itself the finding. Untrusted, `unbound` and `stale` statements never decide a status; late evidence
leaves a nonce `unconfirmed`.

Beside the status, a verifier MUST report these **findings** for the nonce. None changes a status:

- **Dispatch conflict** — Dispatch Records for the nonce that disagree on `payloadSha256`. The executing
  party wrote two accounts of what it dispatched; which statements bind is decided by §4.7.3 step 5, and
  the disagreement itself is reported.
- **Late contradiction** — a statement for the nonce that is `trusted`, bound (§4.7.3 step 5 passed)
  and `contradicted`, but `stale` because `sampledAt` is later than the effective deadline. The window
  rule stands, so the status is not `contradicted`; but a trusted source saying the action did not take
  effect is the case that most needs escalation, and it MUST be reported as its own alert rather than
  folded into `unconfirmed`.
- **Window capped** — the governing Dispatch Record's own `evidenceDeadline` lay beyond the verifier's
  maximum evidence window, so the effective deadline is earlier than the record claims.
- **Untrusted contradiction** — a `contradicted` statement for the nonce that is bound and sampled
  at or after the window's start (including its clock-skew allowance), whether inside the window or
  late, and whose signature verified under a caller-provisioned key, but which did not establish trust
  because that key's validity could not be placed in time or the record lay outside it (§4.7.5). It
  cannot decide the status, but a registered source's key signed a contradiction, and silence about it
  would let an unbounded source's `confirmed` stand unchallenged. A late statement still produces this
  finding when it meets those conditions; lateness and missing key trust MUST NOT cancel each other
  out. Early or unbound statements, and statements verified only under an embedded key rather than a
  caller-provisioned key, do not produce this finding.
- **Source continuity** — the per-source gaps and divergences of §4.7.3, reported per source.

`unconfirmed` and `contradicted` are both "not confirmed", but they call for different responses and an
implementation should keep them distinguishable to its operators. `unconfirmed` means the outcome cannot
be told — often benign, such as a lost or stale sensor — and calls for investigation. `contradicted`
means a trusted source observed that the approved effect did not take place, and calls for escalation.
Reporting both the same way would blunt the alarm in the case that matters.

The evaluation time is the caller's to choose and defaults to the current time. It MUST be an input
rather than a hidden clock so a status can be reproduced; a status computed at one time can change from
`pending` to `unconfirmed` later, and a later export can change any status by adding evidence. An
Unconfirmed Record does not change the status (§4.7.1).

Execution Status is reported alongside the four §7.1 properties and does not affect them or the derived
Verification Level. A caller MAY require every reported nonce to be `confirmed` as an acceptance policy.
Under it a bundle that reports no nonce MUST fail rather than pass vacuously, and a dispatch conflict,
a gap, a divergence, a late contradiction or an untrusted contradiction MUST fail it as well: the
first three mean the bundle does not carry the whole account, and the last two mean a registered
source signed a contradiction that the status could not count — an executing party that chose a
short window, or a bundle handed over without the anchors that place a key in time, must not clear a
policy that requires confirmation. An
approval that was never dispatched — never consumed, or a ceremony the producer applies itself — is
`not_reported` and fails that policy too; a caller applying it to a bundle containing such approvals
must expect that.

### 4.7.5 Trust

A verifier MUST take evidence-source trust from the caller, as a mapping from `source` to one or more
base64 SPKI P-256 keys, separate from the approver trust of §4.6.1. The separation is load-bearing: the
party that approved an action is not an independent observer of its effect, and a source key accepted as
an approver key would let an observation device approve.

Each key MAY carry a validity interval: `notBefore` and `notAfter`, each a §4.3 timestamp, either one
optional, both inclusive. A key entry is either the bare key or an object with exactly the members
`key`, `notBefore` and `notAfter` (the last two optional); an entry with any other member, or with a
bound that is present but is not a §4.3 timestamp, verifies a signature but establishes no trust — a
misspelt or mistyped bound must fail closed, never read as "no bound". A key with an interval
establishes trust in a statement only when the Evidence Record's **anchored time** lies within it. The
anchored time is the earliest external witness time (§5.3: Rekor `integratedTime`, TSA `genTime`)
among the anchors that counted toward quorum for the checkpoint the record's own inclusion proof names,
and only if the record's `seq` lies within the `seqStart`..`seqEnd` those anchors were held to; it is
the latest the record can have been committed, and a witness cannot be backdated. A verifier MUST NOT
take the anchored time from any other checkpoint — one listing an over-wide range would backdate
every record under it — and MUST refuse a bundle that lists one root twice with differing fields.
`observedAt` and `sampledAt` are the source's own claims — a compromised key could place a statement
inside a period when the key was still valid — and a verifier MUST NOT use them for this. A record no
counting anchor covers has no anchored time, and a bounded key then does not establish trust; the
reason is reported, and a contradiction so refused is still a finding (§4.7.4). An unbounded key is
unaffected. The same anchored time governs the §4.6.1 signature check of an Evidence Record, so the two
reports agree. Because the anchored time is an upper bound on the commit time, the two bounds are not
symmetric: `notAfter` is conservative — a record committed inside the interval but anchored after it is
refused — while `notBefore` admits a record committed before it and anchored after it, by up to one
checkpoint period. DEWP gives a verifier no lower bound on when a record was committed, so a caller for
whom the start of a key's validity matters relies on the producer's registry having refused the key
before that time, not on `notBefore` alone.

For an Evidence Record, the §4.6.1 signature check (and any caller policy requiring trusted signatures)
MUST therefore use evidence-source trust: when the caller supplies approver trust but no evidence-source
trust, an Evidence Record's signature is not checked. A leaf of any other kind is never checked against
evidence-source trust. When the caller supplies no trust at all, §4.6.1's embedded-key behaviour is
unchanged.

A producer MAY maintain its own registry of evidence sources and refuse statements from unregistered or
revoked ones before committing them; that registry is producer policy and does not substitute for the
verifier's own trust. Revoking a source's key does not invalidate statements already committed under
it: a caller expresses the revocation as the key's `notAfter`. Because trust is decided at the anchored
time, a `notAfter` equal to the revocation instant refuses every statement in the same checkpoint
period, those committed before the revocation included. A caller that wants them to keep their trust
sets `notAfter` to the earliest witness time of the first checkpoint anchored after the revocation —
the latest any of them can have been committed. That bound also admits a statement committed between
the revocation and that anchor; on a producer that refuses revoked sources at ingest there is none.

### 4.7.6 What Execution Status Does Not Establish

- **Physical truth.** `confirmed` means a source the caller trusts signed an in-window statement saying
  the approved effect was observed. A compromised, misconfigured or mis-wired source produces a genuine
  signature over a false observation. Where that matters, the caller should trust only sources whose
  observations are independent physical measurements, and claim no more than they support.
- **Completeness, beyond the counter.** The per-source `sequence` exposes a statement missing from
  inside the range a bundle covers; it does not expose a source that stopped signing, or statements
  after the last one committed (§4.7.3, Source continuity). Within that limit a withheld `contradicted`
  is a gap, not a `confirmed`; beyond it the ledger still leaves no gap to detect (§3 Invariant 4).
- **Content that was redacted.** §4.7 reads content-verified entries only (§4.7.3). Once a Dispatch or
  Approval Record is redacted to commitment-only under retention (§7.1), the statements it bound read
  `unbound`; once an Evidence Record is, its statement no longer counts. A status computed after a
  redaction can therefore differ from one computed before it, exactly as a later export can change a
  status by adding evidence; a caller that needs the status as it stood keeps the earlier bundle.
- **Approval validity.** The Approval Record is located by its payload type, nonce and hash only.
  Whether it carries a valid, trusted approval under the caller's DIV policy is decided by §4.6.1 and DIV,
  not by this section.
- **Who executed.** A Dispatch Record is the executing party's own statement.

### 4.7.7 Parsing Signed Payloads

Every place §4.7 says a `signedPayload` or a statement "parses", a verifier MUST apply this one
procedure, so that no two conformant verifiers classify the same bytes differently:

1. The whole string is one RFC 8259 JSON text: no trailing content after the value (whitespace aside),
   and no non-standard literals such as `NaN` or `Infinity`.
2. Arrays and objects nest at most 64 levels deep, the outermost value counting as level 1. A deeper
   text does not parse. (Parsers differ in their built-in depth limits; this bound is below all of them.)
3. When a member name repeats, the last occurrence wins, as in the reference parsers. For a statement
   this is moot: §4.7.2 rule 9 refuses any repeated name, because re-serialization cannot reproduce it.
4. Every number is finite when read as an IEEE 754 double: `1e400`, or an integer too long for any
   double, does not parse (some parsers refuse it, others would read infinity or an exact big integer).
5. Timestamps (§4.3) consist of ASCII digits only, and year `0000` is a valid year.

A payload that does not parse is neither an Execution Evidence Statement nor an Approval Record. Its
leaf is still an Evidence Record when its `event` says so (§4.7.3), and is then reported `invalid`.

---

# 5. Two-Tier Merkle Log Tree & Anchor Specification

DEWP structures audit logs into a two-tier Merkle tree hierarchy:

```
                  [ Daily Checkpoint Root (Tier 2 Anchor) ]
                                 /        \
          checkpointProof       /          \       checkpointProof
                               /            \
                   [ Block Root 1 ]      [ Block Root 2 ]
                       /      \              /      \
        blockProof    /        \            /        \    blockProof
                     /          \          /          \
                [ Leaf 1 ]   [ Leaf 2 ] [ Leaf 3 ]  [ Leaf 4 ]
```

## 5.1 Tree Construction & Balancing Rules

Each rule below is referenced elsewhere as **§5.1.N**.

1. **§5.1.1 — Empty Tree:** An empty Merkle tree has `merkleRoot([]) == sha256Hex(byte(0x02))`.
2. **§5.1.2 — Single Leaf Tree:** A tree with 1 leaf has `merkleRoot([L1]) == L1`.
3. **§5.1.3 — Odd Node Duplication:** When an odd number of nodes exists at any level during pairwise iteration, the final node MUST be duplicated (`nextParent = hashPair(level[i], level[i])`). This rule is why inclusion proofs require bounds — see §11.1.
4. **§5.1.4 — Tier 1 (Block Merkle Tree):** Witness events occurring within a short time window are hashed into Leaf Hashes (`hashLeaf(preimage)`) and balanced into a Tier 1 Block Merkle Tree.
5. **§5.1.5 — Tier 2 (Daily Checkpoint Tree):** Block Roots are re-hashed with the leaf tag (`hashLeaf(blockRoot)`) and aggregated into a Tier 2 Daily Checkpoint Tree, yielding a final single **Daily Checkpoint Root**.
6. **§5.1.6 — Leaf-to-Root Ordering & Sibling-Relative Naming:** All proof step arrays (`blockProof` and `checkpointProof`) MUST be ordered strictly from **leaf to root** (bottom to top). Each step MUST contain `siblingHash` (the digest of the sibling node) and `siblingPosition` (`"LEFT"` or `"RIGHT"` — the side on which the **sibling** sits relative to the running node). The running node is combined as `hashPair(siblingHash, running)` when `siblingPosition == "LEFT"`, else `hashPair(running, siblingHash)`.

## 5.2 Signed Anchor Preimage Specification (`0x03` Domain Tag)

To anchor a Daily Checkpoint Root, an anchor provider MUST publish a signed anchor object.

The **Canonical Anchor Preimage** MUST be serialized as an ordered 7-element JSON array of strings formatted according to RFC 8785 (JCS):

```json
[
  "e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8",
  "2026-07-24T23:59:00.000Z",
  "https://transparency.example.org",
  "ES256",
  "1048576",
  "1049600",
  "6ae54abac75d273317f9f369306f2fbe85f2fafc9dd30685dc4f8a375257ef2b"
]
```

| Index | Field | Description |
|:---:|---|---|
| 0 | `dailyRoot` | 64-character lowercase hex Daily Checkpoint Root string. |
| 1 | `timestamp` | The checkpoint's own claimed commit time — the same instant as its `anchoredAt` and the one its §5.4 chain hash commits to — ISO 8601 UTC in exactly the §4.3 form (`YYYY-MM-DDTHH:mm:ss.sssZ`). Every anchor over one checkpoint, from any issuer, carries this same value; a witness's own time lives in its evidence (§5.3). |
| 2 | `issuer` | HTTPS URI or DID of the anchor provider. |
| 3 | `algorithm` | Signature algorithm (`ES256`, `Ed25519`, `RSA-PSS`). |
| 4 | `seqStart` | First global `seq` the checkpoint commits (stringified integer). |
| 5 | `seqEnd` | Last global `seq` the checkpoint commits (stringified integer). |
| 6 | `chainHash` | The checkpoint's §5.4 continuity chain hash (64-character lowercase hex). |

The anchor signing input is the raw domain-separated digest:

`anchorDigest = SHA-256(byte(0x03) || UTF8Bytes(JCS([dailyRoot, timestamp, issuer, algorithm, seqStart, seqEnd, chainHash])))`

**Why the position is bound.** A root alone says nothing about where in the log it sits or when it existed. An anchor over the root alone lets a party able to rewrite the log recompute a root and have it witnessed at any later time, with nothing tying the witness to the checkpoint it is offered for. Binding `seqStart`/`seqEnd` names the range; binding `chainHash` — which commits to the checkpoint's root, range, entry count, commit time and its predecessor's chain hash (§5.4) — makes every anchor re-attest the entire sequence of roots before it, so an edit to any earlier checkpoint invalidates the anchors of every later one. An anchor object lacking any of the seven fields, or carrying one in another shape, MUST NOT verify. In particular `algorithm` MUST be one of `ES256`, `Ed25519` and `RSA-PSS` for every anchor `kind` — external anchors carry the producer's own anchor algorithm — and a verifier MUST NOT fall back to some default scheme for any other label.

The signature MUST be computed over the **raw 32-byte `anchorDigest` value**, NOT over its 64-character lowercase-hex string encoding. (For algorithms that apply their own message hash — e.g. ECDSA-P256/SHA-256, RSA-PSS/SHA-256 — the `anchorDigest` bytes are the message input; verifiers MUST pass the 32 raw bytes, never the hex text.) A verifier that hex-encodes the digest before signature verification MUST be considered non-conformant, as it will interoperate with neither compliant signers nor the reference vectors.

**RSA-PSS profile.** An `RSA-PSS` anchor is RSASSA-PSS [RFC8017] with SHA-256 as the message hash,
MGF1 with SHA-256 as the mask generation function, and a salt length of exactly 32 bytes (the hash
length), over the raw 32-byte `anchorDigest` like every other algorithm. The key's modulus MUST be at
least 2048 bits. A verifier MUST NOT recover the salt length from the signature or accept any other
salt length, and MUST refuse a smaller key: both are properties of the signature scheme, and a
verifier that auto-detects them verifies anchors that another conformant verifier refuses. Note that
common signing APIs default to the MAXIMUM salt length (Node.js, OpenSSL); a producer MUST set the
salt length explicitly.

**ECDSA signature encoding.** Producers MUST emit ES256 anchor signatures in ASN.1/DER, the encoding the reference producer emits and the golden vectors pin. Verifiers MUST accept **both** ASN.1/DER and raw IEEE-P1363 (`r ‖ s`, 64 bytes for P-256). Do NOT infer the encoding from length: a DER signature whose `r` and `s` both happen to be short is also 64 bytes, so a length switch mis-rejects valid DER. Attempt both encodings and accept if either verifies. Accepting only DER is non-conformant: §5.3 exists to admit anchors from issuers the producer does not control, and a WebCrypto-based issuer can emit only P1363 — refusing those makes a genuine third-party anchor read as an invalid signature in one implementation while counting toward quorum in another. Both encodings are pinned by the `signedAnchor` vectors.

### 5.2.1 External Anchor Representation

The published JSON Schema (`docs/schemas/dewp/anchor.schema.json`) governs the anchor object's wire
shape. Its `kind` registry is `SELF`, `REKOR`, `RFC3161`, and `WEBHOOK`; an absent `kind` MUST be
treated as the legacy DEWP-signed form (`SELF`). A `SELF` anchor carries a non-empty §5.2
`signature`, which is its evidence.

External `REKOR` and `RFC3161` anchors carry `signature: ""`; their `evidence` field contains the
third party's own self-contained attestation. Their trust does not derive from a DEWP signature by
the producer, but from verification of that attestation under trust material selected by the
verifier. A `WEBHOOK` receipt is deployment-specific and MUST NOT count unless the deployment has
an explicit verifier for its evidence.

For `REKOR`, a verifier checks the Signed Entry Timestamp (SET) over Rekor's canonical entry under a
caller-pinned Rekor log key, and confirms that the logged `hashedrekord` SHA-256 value is the expected
hash of the §5.2 `anchorDigest`. The log key comes from the verifier's own trust configuration
(normally Sigstore TUF), never from the bundle. Both checks are required: a valid SET for an
unrelated public entry is not evidence for this checkpoint. The caller MUST bind the pinned log key
to a particular issuer; the producer-controlled issuer string inside a submitted digest does not
establish which witness signed it. The reference implementations use `rekorIssuer` alongside the
log key. A legacy unscoped key is accepted only under a policy with exactly one trusted issuer;
otherwise it cannot count or establish divergence. This prevents one log from satisfying a
multi-issuer quorum under several producer-chosen names.

For `RFC3161`, `evidence` is the base64-encoded DER TimeStampToken. Its SHA-256 message imprint
MUST equal the raw §5.2 `anchorDigest` recomputed from the exported anchor's own seven signed
fields; hashing that digest a second time is incorrect. These fields
MUST remain exactly as submitted. In particular, a producer MUST NOT replace the bound timestamp
with a receipt time or replace the bound issuer with another identity after obtaining evidence.
The token's authenticated `genTime` establishes existence by the TSA time, not occurrence of the
underlying business action at the anchor's producer-supplied timestamp — which is why §5.3 bounds the
distance between the two.

A verifier MAY count this evidence only after validating the token signature, message imprint,
TSA signer identity, timestamping certificate purpose, certificate path and its caller-selected
time and revocation policy. Embedded certificates MUST NOT establish trust. Trust roots and a TSA
signer identity binding MUST be selected by the caller for that issuer. A producer checking a fresh
response MUST also verify the request nonce. A minimal verifier without the necessary backend or
trust MUST report the token as present but unverified and MUST NOT count it. The JSON Schema remains
authoritative where this prose and the object shape differ.

## 5.3 Anchor Trust, Quorum & Key Discovery

A verifier evaluates anchors against a local **anchor policy**:

```json
{
  "requiredAnchors": 2,
  "trustedIssuers": ["https://transparency.example.org", "https://anchor.example.net"],
  "quorum": "ALL_MUST_AGREE"
}
```

| Field | Requirement | Description |
|---|---|---|
| `requiredAnchors` | REQUIRED | Minimum count of distinct, independently-issued valid anchors over the same `dailyRoot`. SHOULD be ≥ 2 for high-assurance non-repudiation. |
| `trustedIssuers` | REQUIRED | Allowed anchor issuer identifiers; an anchor whose `issuer` is not listed does not count toward quorum. |
| `quorum` | REQUIRED | `ALL_MUST_AGREE` (every trusted anchor present MUST sign the same root) or `N_OF_M` (at least `requiredAnchors` agree). |
| `maxAnchorLagSeconds` | OPTIONAL | The time bound below. Absent ⇒ 86400 (one day). |

`anchorVerified` is true only if the policy is satisfied.

**Time bound.** An external anchor proves only that its witness saw the digest at the witness's own
authenticated time — Rekor's `integratedTime`, an RFC 3161 token's `genTime`. An anchor first witnessed
long after the checkpoint claims to exist says nothing about whether the checkpoint existed then, and it
is exactly what re-anchoring a rewritten old root produces. A verifier MUST therefore compare each
external witness time with the anchor's signed `timestamp` (the checkpoint's claimed time) and MUST NOT
count an anchor witnessed more than `maxAnchorLagSeconds` after it, or more than a small clock-skew
tolerance before it (the reference implementations allow 300 seconds). The verdict MUST say why such
an anchor did not count, and SHOULD expose each issuer's witness time whether or not it counted. `SELF`
anchors carry no independent time and are not subject to the bound. A producer SHOULD obtain external
anchors promptly after committing a checkpoint; one whose anchoring stalled beyond the bound stays
verifiable only to a relying party that deliberately widens it.

The bound is only as good as the checkpoint time it is measured against, and the anchor's own
`timestamp` is chosen by the producer. A verifier MUST therefore take that time from the checkpoint the
anchor is counted for (below), and MUST NOT count an external witness for a checkpoint whose claimed
time it does not know: a checkpoint that states no `anchoredAt` or `chainHash` MUST NOT be reported as
anchored (divergence is still evaluated), and a single inclusion proof, which carries no checkpoint
(§6.2), MUST NOT count an external anchor unless the caller supplies the checkpoint's record.

**Position.** Where the verifier knows the checkpoint an anchor is counted for — an evidence bundle's
`checkpoints[]` entry, §6.3, or a caller-trusted checkpoint record — it MUST NOT count an anchor whose
signed `seqStart`, `seqEnd`, `chainHash` or `timestamp` differs from that checkpoint's `seqStart`,
`seqEnd`, `chainHash` or `anchoredAt`, and it MUST NOT read such an anchor as divergence: it names
another checkpoint. (The chain hash and claimed time are the exception for divergence. Both commit
to the root, so a checkpoint rewritten with a different root necessarily states a different chain
hash and usually a different time; a caller-obtained anchor for the same seq range that differs in
them is exactly the conflicting evidence divergence exists to expose, and a verifier MUST NOT
discard it for that difference alone.) **A caller-trusted checkpoint record** — normally the chain-verified line of the
roots file (§5.4.1) for the checkpoint's root — takes precedence over the bundle's copy: a verifier
given one MUST hold anchors to the record's fields where it states them, and MUST fail a bundle whose
checkpoint states a different `seqStart`, `seqEnd`, `entryCount`, `anchoredAt` or `chainHash` for the
same root. A bundle alone can re-date a checkpoint with a self-consistent chain hash over an invented
predecessor; only a record the verifier already holds exposes that.

**Rekor submitter.** Rekor logs a `hashedrekord` under whatever key submits it, and the anchor digest
is computed from public fields, so anyone can have any digest logged. A verifier that knows the
producer's anchor key (§5.3 key discovery) SHOULD pin it and count a Rekor entry only when its
`publicKey` is that key and its signature over the anchor digest verifies. The time bound, not the
pin, is what defeats back-dated re-anchoring; the pin removes third parties from the picture.

**What this does and does not establish.** With the time bound and position binding, an anchored
checkpoint cannot be rewritten after the bound has passed without every later anchor failing, because
each binds the chain hash that commits to it. A party able to rewrite the log AND re-date every
checkpoint from the edited one onward to "now" can still produce a self-consistent export; what exposes
it is a roots file or earlier export retained by anyone (§5.4.1), whose chain hashes the rewrite cannot
reproduce, and the months-long gap between the re-dated checkpoints and the leaf-committed `createdAt`
of the events under them. In either quorum mode, fatal divergence can
be established only from anchors the verifier obtained itself per checkpoint (out of band or through
discovery), never from a bundle-carried set; valid same-root bundle anchors may still count toward
quorum under verifier-trusted keys (§6.3). Divergence evidence MUST also satisfy the rules an anchor
must satisfy to count toward quorum: its signed seq range MUST be the checkpoint's, an external
witness time MUST lie within the time bound above of the anchor's own signed `timestamp`, and a
`REKOR` entry MUST NOT establish divergence unless the verifier pinned the producer's submission key
(the Rekor submitter rule above) — without it, anyone can have a digest over a different root logged
under a trusted issuer's name and raise a false alarm. A `SELF` anchor carries no witness time; its
signature under the issuer's trusted key is the evidence. If two such trusted issuers sign **different** roots for
the same checkpoint, the verdict is `INVALID` (divergence), never a silent pick. A single self-hosted
anchor (`requiredAnchors: 1` from the platform's own issuer) provides tamper-evidence but NOT
independent non-repudiation, and the verifier SHOULD surface that distinction.

**RFC 3161 reference implementation.** All five ports provide an optional OpenSSL 3 adapter.
The adapter accepts SHA-256, SHA-384 or SHA-512 CMS signer digests and requires the single declared
CMS digest algorithm to match the single SignerInfo digest; SHA-1 and MD5 are refused.
Its caller-owned trust configuration pins the DER signer certificate's SHA-256 fingerprint to an
issuer, supplies trusted CA certificates, and explicitly chooses offline CRL checking or unchecked
revocation. CRL mode requires fresh, valid CRLs for the certificate chain at the caller's evaluation
time. Unchecked mode makes no revocation assertion. Both modes verify certificate validity at that
evaluation time and at the signed `genTime`; a future `genTime` is refused. Evaluation defaults to
current time rounded up by less than one second. A caller can supply an explicit historical
Unix-second evaluation time and retained CRLs; the adapter does not choose historical trust from
the token itself. No network trust discovery, OCSP fetching or archival evidence renewal occurs.
Unavailable OpenSSL, absent trust, or failed checks contribute zero issuers and produce a diagnostic
note. Only caller-attributed evidence can establish divergence, including RFC 3161 evidence.

These adapters have no additional language-package dependencies but require the OpenSSL 3 executable.
Their positive and negative cases are shared in `rfc3161-vectors.json`. They do not imply the complete
Extended Profile: NDJSON evidence streaming remains outside the current implementation.

Verifiers MUST discover trusted anchor public keys via:
1. Static SPKI / JWKS public key configuration supplied to the verifier, OR
2. HTTPS Well-Known discovery endpoint at `{issuer}/.well-known/dewp-anchors.json`.

Anchor objects MUST carry a `keyId` referencing the active SPKI public key.

## 5.4 Checkpoint Continuity Chain (`0x04` Domain Tag)

An inclusion proof binds an event to **one** daily root. It says nothing about whether the *sequence*
of daily roots was rewritten: a published roots file with one day silently replaced or removed is
internally consistent and verifies fine. Producers therefore SHOULD link each checkpoint to its
predecessor.

The canonical chain preimage is the RFC 8785 JCS serialization of a **6-element array of strings**:

```
[prevChainHash, root, seqStart, seqEnd, entryCount, anchoredAt]
```

`chainHash = sha256Hex(byte(0x04) || UTF8Bytes(chainPreimage))`.

Rules:

- Every element MUST be a JSON **string**, including `seqStart`, `seqEnd` and `entryCount`. For an
  array of strings JCS reduces to plain `JSON.stringify`, so no implementation has to reproduce
  RFC 8785 number canonicalization — the part of JCS where independent verifiers most often drift.
  §5.2 makes the same trade for the same reason.
- `prevChainHash` for the first checkpoint MUST be the empty string `""`. No real chain hash can
  collide with it, since those are always 64 hex characters, so a verifier that reaches a `""`
  predecessor knows it is at the genuine start of the log and not at a truncation point.
- `anchoredAt` MUST be the same instant recorded on the checkpoint, ISO 8601 UTC with millisecond
  precision and a literal `Z` (§4.3).
- Verifiers MUST check both that each entry's `chainHash` recomputes **and** that its `prevChainHash`
  equals its predecessor's `chainHash`. Recomputation alone does not detect a deleted entry.

**Transport of the chain.** The chain is verifiable only over a source that carries `chainHash` and
`prevChainHash` per checkpoint — normally the published roots file (§5.4.1). The Evidence Bundle of
§6.3 carries both, with `entryCount`, for each checkpoint it includes, so a bundle-only verifier can
recompute each checkpoint's chain hash and hold its anchors to it (§5.3). It cannot check that the
sequence of daily roots is unbroken: a bundle carries only the checkpoints its entries fall under,
which are rarely consecutive. For continuity, an auditor MUST obtain the chain from the roots file.

### 5.4.1 Published Roots File (`roots.jsonl`)

The RECOMMENDED chain transport is an append-only JSON-Lines file of published daily roots, one
object per line, ordered by `seqEnd` (the reference implementation's publication point is
`ledger/roots/roots.jsonl` — not yet publishing at the time of writing — and its exporter is
`packages/db/src/scripts/export-roots.ts`):

```json
{"seqStart":"1","seqEnd":"10000","entryCount":10000,"root":"<64-hex>","anchorRef":"<publication receipt>","anchoredAt":"2026-07-15T00:00:00.000Z","prevChainHash":"","chainHash":"<64-hex>"}
```

| field           | meaning |
|---|---|
| `seqStart` / `seqEnd` | Global `seq` range the daily root commits (stringified integers). |
| `entryCount`    | Number of committed events under the root (JSON number; the chain preimage stringifies it, §5.4). |
| `root`          | The Daily Checkpoint Root, lowercase hex. |
| `anchorRef`     | The producer's publication receipt — self-identifying, NOT an independence claim. |
| `anchoredAt`    | The checkpoint's commit instant (ISO 8601 UTC, ms precision) — part of the chain preimage. |
| `prevChainHash` | The previous line's `chainHash`; `""` marks the genuine start of the log. |
| `chainHash`     | `SHA-256(0x04 ‖ JCS([prevChainHash, root, seqStart, seqEnd, String(entryCount), anchoredAt]))`, hex. |

Rules:

- A verifier consuming the file MUST run the §5.4 continuity checks over the WHOLE file before
  trusting any root in it. A file that mixes chained and unchained lines MUST be refused. A file
  with no chain fields at all cannot be continuity-checked — a verifier MAY proceed with it (a
  hand-built minimal root list is a legitimate workflow) but MUST surface that continuity was not
  checked; the published file is always chained.
- Publication MUST be **prefix-only**: a line may be appended only when every earlier checkpoint is
  already in the file. A checkpoint whose anchor quorum lags therefore DELAYS later roots rather
  than being skipped — a skipped predecessor would leave a `prevChainHash` pointing at an entry not
  in the file, and back-filling it later would break the append-only ordering. A line already
  published never blocks appending after it, whatever its live anchor set looks like.
- A producer MUST refuse to append when a published line's `root` — or, same root, its
  `chainHash` — differs from its own record: a published root (or its chain identity) that changed
  is the precise event the file exists to make detectable.

**Scope of the guarantee — this is NOT an RFC 6962 consistency proof.** On its own the chain is only
internally consistent: a producer that rewrites history can recompute every chain hash from the edit
onward, and the rewritten file verifies. What the chain adds is that any two copies of the file can be
compared at a single point — the chain hash of the latest line both contain commits to every root
before it. So against a copy retained or published earlier (a relying party's saved file, the
publication repository's history), the chain shows that no root up to that copy's last line was
edited, reordered or removed; it says nothing about lines after it, or about any history nobody kept.
Nor does it prove that the leaves committed under an earlier root are unchanged: that comes from each
root being externally anchored, within the §5.3 time bound, under a preimage that binds its chain hash
(§5.2). Neither mechanism is sufficient alone, and implementations MUST NOT describe the chain as a
consistency proof or as tamper-proof.

**Global sequence continuity.** Verifiers MUST NOT require `seqStart(N+1) == seqEnd(N) + 1` across
checkpoints. Global `seq` is an ordering counter (§4 rule 5) and is commonly allocated from a
non-transactional database sequence, where a rolled-back write burns its value permanently — gaps are
therefore normal in a healthy log, and a strict check would raise false alarms that train operators to
ignore the signal. Verifiers MUST instead require that ranges advance without overlapping
(`seqStart(N+1) > seqEnd(N)`). Gapless completeness is carried by the transactionally allocated
per-tenant `tenantSeq` (§4 rule 4), not by global `seq`.

**Sealing a closed prefix (producer requirement).** The gap tolerance above covers values that were
never committed, such as those burned by a rolled-back write. It does not cover a value that commits
*after* a block over its range was sealed. A producer MUST NOT seal a block over `[seqStart, seqEnd]`
while any entry that could still commit with a `seq` in that range is uncommitted. Where `seq` is
allocated at insert but becomes visible at commit, the two orders differ. A sealer that simply seals
every row it can see will then close blocks over transactions still in flight. The late row either
invalidates its block's stored root, or falls between two blocks and is never sealed; an evidence
export then presents it as a per-tenant omission.

*Implementation note (non-normative).* The reference producer enforces this with a commit barrier. Every insert takes a shared lock and draws its `seq` only while holding it. The sealer takes the same lock exclusively, so it waits for in-flight writers to finish, and no `seq` can be drawn while it holds the lock. The sealer's wait is bounded: on timeout it seals nothing that pass and retries on the next.

---

# 6. Proof Bundle Schemas

Normative machine-readable JSON Schemas (Draft 2020-12) for the containers in this section are published alongside this document and are authoritative for structural validation:

* `docs/schemas/dewp/inclusion-proof.schema.json` — `dewp.audit.inclusion-proof`
* `docs/schemas/dewp/evidence-bundle.schema.json` — `dewp.audit.evidence-bundle`
* `docs/schemas/dewp/anchor.schema.json` — signed anchor object (§5.2)
* `docs/schemas/dewp/execution-evidence-statement.schema.json` — Execution Evidence Statement (§4.7.2)

The JSON examples below are illustrative; where an example and a schema disagree, the schema governs. Each container schema accepts only the canonical `dewp.audit.*` `kind` (§6.5); the statement schema describes a signed object, not a container, and has no `kind`.

## 6.1 Algorithm Registry Object

All DEWP proof containers SHOULD carry an `algorithmRegistry` metadata block:

```json
{
  "hashAlgorithm": "SHA-256",
  "serialization": "RFC8785-JCS",
  "merkleVersion": 1,
  "signatureAlgorithms": ["ES256", "WEBAUTHN", "AUTO_APPROVED"]
}
```

## 6.2 Single Inclusion Proof Bundle Schema (`dewp.audit.inclusion-proof`)

The `event.canonical` object carries the raw JSON values exported by the producer. In particular,
`metadata` is the parsed JSON value (or `null` when absent), not a pre-serialized JCS string. When
rebuilding the ordered preimage, the verifier converts that raw value into the compact JCS string
required at §4.2 index 5.

The example uses the registered `trust.intyga.audit.v1` profile and therefore carries its six
extension fields before the final `tenantSeq`, for an 18-element preimage.

```json
{
  "protocol": "DEWP",
  "version": "1.0",
  "kind": "dewp.audit.inclusion-proof",
  "profile": "trust.intyga.audit.v1",
  "exportedAt": "2026-07-24T12:30:00.000Z",
  "verificationLevel": "CONTENT_VERIFIED",
  "algorithmRegistry": {
    "hashAlgorithm": "SHA-256",
    "serialization": "RFC8785-JCS",
    "merkleVersion": 1
  },
  "event": {
    "seq": "1048576",
    "id": "0190e3f2-1a2b-7c3d-8e4f-5a6b7c8d9e0f",
    "createdAt": "2026-07-24T12:00:00.000Z",
    "type": "ACTION_APPROVED",
    "outcome": "SUCCESS",
    "detail": "Database drop approved",
    "actorDid": "did:example:human:alice",
    "subjectDid": null,
    "signerDid": "did:example:human:alice",
    "signature": "base64-sig",
    "sigAlg": "ES256",
    "canonical": {
      "seq": "1048576",
      "createdAt": "2026-07-24T12:00:00.000Z",
      "event": "ACTION_APPROVED",
      "outcome": "SUCCESS",
      "detail": "Database drop approved",
      "metadata": { "target": "users" },
      "signerDid": "did:example:human:alice",
      "signerPublicKey": "base64-spki",
      "signedPayload": "{\"actionType\":\"db:dropTable\",\"display\":\"...\",\"type\":\"div-intent-verification\",\"v\":1}",
      "signature": "base64-sig",
      "sigAlg": "ES256",
      "isBillable": true,
      "tenantId": "tenant-uuid-01",
      "actorNodeId": "node-uuid-alice",
      "subjectNodeId": null,
      "edgeId": null,
      "challengeId": "challenge-uuid-01",
      "tenantSeq": "42"
    }
  },
  "proof": {
    "seq": "1048576",
    "leaf": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
    "blockIndex": "0",
    "blockRoot": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "blockProof": [
      { "siblingHash": "f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2", "siblingPosition": "RIGHT" }
    ],
    "leafIndex": 0,
    "blockLeafCount": 2,
    "checkpointId": "cp-uuid-01",
    "checkpointRoot": "e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8",
    "checkpointProof": [
      { "siblingHash": "c4b3a2f1e5d6c4b3a2f1e5d6c4b3a2f1e5d6c4b3a2f1e5d6c4b3a2f1e5d6c4b3", "siblingPosition": "LEFT" }
    ],
    "checkpointLeafIndex": 1,
    "checkpointLeafCount": 2,
    "anchorRef": "https://transparency.example.org/roots/2026-07-24.json",
    "anchored": true,
    "externallyAnchored": true,
    "externallyAnchoredRequired": 2
  },
  "anchor": {
    "dailyRoot": "e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8",
    "timestamp": "2026-07-24T23:59:00.000Z",
    "issuer": "https://transparency.example.org",
    "keyId": "key-2026-01",
    "algorithm": "ES256",
    "seqStart": "1048576",
    "seqEnd": "1049600",
    "chainHash": "6ae54abac75d273317f9f369306f2fbe85f2fafc9dd30685dc4f8a375257ef2b",
    "signature": "base64-anchor-signature",
    "anchorRef": "https://transparency.example.org/roots/2026-07-24.json",
    "anchored": true
  },
  "anchors": [
    {
      "dailyRoot": "e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8",
      "timestamp": "2026-07-24T23:59:00.000Z",
      "issuer": "https://transparency.example.org",
      "keyId": "key-2026-01",
      "algorithm": "ES256",
      "seqStart": "1048576",
      "seqEnd": "1049600",
      "chainHash": "6ae54abac75d273317f9f369306f2fbe85f2fafc9dd30685dc4f8a375257ef2b",
      "signature": "base64-anchor-signature"
    }
  ]
}
```

Two anchoring flags appear in a proof, and they mean different things — both are **producer
claims** a verifier reports for display and never treats as proof (the §5.3 quorum over the signed
anchors is the check):

- `anchored` — a publication receipt (`anchorRef`) exists. The reference producer writes one for
  every checkpoint at commit time, so this is COMMITMENT only and structurally always true for a
  checkpointed proof; it MUST NOT be read as independence.
- `externallyAnchored` — the producer claims a §5.3 external anchor quorum exists for this root:
  at least `externallyAnchoredRequired` DISTINCT INDEPENDENT issuers hold an anchor over it.
  Distinct **issuers**, not anchor rows — re-anchoring under a rotated key is one opinion.
  "Independent" excludes both the producer's own `SELF` anchor and any `WEBHOOK` receipt, because a
  webhook endpoint is operated by the producer and is therefore not a second opinion.
- `externallyAnchoredRequired` — the quorum size the claim above was evaluated against. Producers
  SHOULD emit it whenever they emit `externallyAnchored`, and verifiers SHOULD surface it wherever
  they surface the flag: without it the boolean cannot be read, since a deployment requiring one
  issuer and a deployment requiring three publish the same `true`. Counting the `anchors` array is
  not a substitute — the array may be absent, and its length is the count ACHIEVED rather than the
  count REQUIRED. Both fields remain producer claims; `anchorVerified` (§7.1) is the check.

The single `anchor` field alongside the `anchors` array is a legacy convenience (the first entry of
the set); the array is what the §5.3 quorum rule is evaluated over, and the published JSON Schema
governs where this example and the schema disagree (§6).

A single proof carries no checkpoint record, so it gives the verifier no position or claimed time to
hold an anchor to. An external (`REKOR`, `RFC3161`) anchor therefore counts toward `anchorVerified` only
when the caller supplies the proof's checkpoint record — the roots-file line for its root (§5.4.1) — and
the anchor is then held to that record's range, chain hash and `anchoredAt` (§5.3). A record naming a
different root than the caller's `trustedRoot` MUST fail the proof. Where the record carries
`entryCount`, the proof's leaf counts MUST be consistent with it (§17.3).

## 6.3 Multi-Entry Evidence Bundle Schema (`dewp.audit.evidence-bundle`)

```json
{
  "protocol": "DEWP",
  "version": "1.0",
  "kind": "dewp.audit.evidence-bundle",
  "exportedAt": "2026-07-24T12:30:00.000Z",
  "tenant": { "id": "tenant-uuid-01", "name": "Acme Corp" },
  "range": { "from": "2026-07-01T00:00:00.000Z", "to": "2026-07-24T23:59:59.000Z" },
  "tenantSequenceCommitment": {
    "tenantId": "tenant-uuid-01",
    "firstTenantSeq": "1",
    "lastTenantSeq": "42"
  },
  "entries": [
    {
      "event": {
        "seq": "1048576",
        "createdAt": "2026-07-24T12:00:00.000Z",
        "type": "ACTION_APPROVED",
        "outcome": "SUCCESS",
        "redaction": { "mode": "NONE" },
        "signerDid": "did:example:human:alice",
        "sigAlg": "ES256",
        "canonical": { "seq": "1048576", "tenantSeq": "42" }
      },
      "proof": { "seq": "1048576", "leaf": "d4e5f6...", "blockRoot": "...", "checkpointRoot": "..." }
    },
    {
      "event": {
        "seq": "1048577",
        "createdAt": "2026-07-24T12:05:00.000Z",
        "type": "USER_DELETED",
        "outcome": "SUCCESS",
        "redaction": {
          "mode": "COMMITMENT_ONLY",
          "removedFields": ["detail", "metadata", "signedPayload", "signature", "signerPublicKey"],
          "redactedAt": "2027-01-15T09:00:00.000Z",
          "reason": "gdpr-erasure",
          "commitment": {
            "leaf": "b9a8c7d6e5f4b9a8c7d6e5f4b9a8c7d6e5f4b9a8c7d6e5f4b9a8c7d6e5f4b9a8",
            "tenantSeq": "43"
          }
        },
        "signerDid": null,
        "sigAlg": null
      },
      "proof": { "seq": "1048577", "leaf": "b9a8c7d6e5f4b9a8c7d6e5f4b9a8c7d6e5f4b9a8c7d6e5f4b9a8c7d6e5f4b9a8", "blockRoot": "...", "checkpointRoot": "..." }
    }
  ],
  "checkpoints": [
    {
      "id": "cp-uuid-01",
      "root": "e9f8a7...",
      "anchorRef": "https://transparency.example.org/roots/2026-07-24.json",
      "anchoredAt": "2026-07-24T23:59:00.000Z",
      "seqStart": "1048576",
      "seqEnd": "1049600",
      "entryCount": 1025,
      "prevChainHash": "",
      "chainHash": "6ae54abac75d273317f9f369306f2fbe85f2fafc9dd30685dc4f8a375257ef2b",
      "externallyAnchored": true,
      "externallyAnchoredRequired": 2,
      "anchors": [
        {
          "dailyRoot": "e9f8a7...",
          "timestamp": "2026-07-24T23:59:00.000Z",
          "issuer": "https://rekor.sigstore.dev",
          "keyId": "rekor-2026",
          "algorithm": "ES256",
          "seqStart": "1048576",
          "seqEnd": "1049600",
          "chainHash": "6ae54abac75d273317f9f369306f2fbe85f2fafc9dd30685dc4f8a375257ef2b",
          "signature": "",
          "kind": "REKOR",
          "evidence": "base64-rekor-set-and-inclusion-proof"
        }
      ]
    }
  ]
}
```

Each checkpoint entry carries `seqStart` / `seqEnd`, the global sequence range it commits, its §5.4 chain fields `entryCount` / `prevChainHash` / `chainHash`, and its own `anchors` array — the per-checkpoint anchor set the §5.3 quorum rule is evaluated over. A bundle that reports only a single top-level anchor cannot express quorum, so the array is where independence is actually assessed. A verifier supplied with an anchor policy and key resolver but no anchors of its own MAY evaluate quorum over this array — the signatures still verify only under keys the VERIFIER trusts, so a bundle cannot vouch for itself — but bundle-carried anchors MUST NOT be able to establish the fatal divergence verdict of §5.3, which requires anchors the verifier fetched per checkpoint itself (the producer chooses what a bundle carries). A verifier MUST recompute each checkpoint's `chainHash` from its `prevChainHash`, `root`, `seqStart`, `seqEnd`, `entryCount` and `anchoredAt` and fail the bundle when it does not recompute, and MUST hold every anchor to that checkpoint's position and claimed time (§5.3). `externallyAnchored` is the producer's §5.3 quorum claim for the checkpoint (distinct INDEPENDENT issuers — neither `SELF` nor `WEBHOOK` — ≥ `externallyAnchoredRequired`, which SHOULD be emitted beside it) — display only, per the §6.2 note; `anchoredAt` is the checkpoint's commit instant (self-commitment time), not evidence of external anchoring. A checkpoint that carries anchors but states no `chainHash` or `anchoredAt` — and has no caller-trusted record supplying them — MUST NOT be reported as anchored (§5.3); stripping those fields is exactly how a producer would switch off the time bound.

Entry-level rules, in addition to §7 and §7.2:

- Each committed event appears at most once. A verifier MUST fail an entry whose `proof.leaf` or `seq` already appeared in the bundle; otherwise one genuine event can fill two positions.
- `blockLeafCount` and `checkpointLeafCount` are properties of a tree, so every proof into the same `blockRoot` (respectively checkpoint root) MUST state the same value, and both MUST be consistent with the checkpoint's `entryCount` (caller record first, then the bundle's chain-verified value; §17.3).
- An entry that ships a preimage under an unrecognised `profile` MUST fail (§4.5); its counter is not read.
- The tenant rule of §7.2 applies.

A bundle also carries `profile`, `algorithmRegistry` and `howToVerify` at the top level. `profile` names the leaf profile in force (§4.5), `algorithmRegistry` pins the algorithm identifiers (§12), and `howToVerify` is a human-readable instruction string carrying no normative weight.

## 6.4 Streaming Evidence Export Schema (`dewp.audit.evidence-stream`)

> **Specified, not implemented.** As of 31 Jul 2026 no producer emits this form and no verifier in
> this repository reads it — including the TypeScript reference implementation. The format below is
> normative for anyone who chooses to implement it, but nothing here claims DEWP Extended Profile
> conformance (§9.2), and no INTYGA surface streams evidence. Use
> `dewp.audit.evidence-bundle` (§6.3), which is implemented end to end.

For multi-gigabyte log exports, implementations SHOULD stream evidence formatted as JSON Lines (NDJSON).

Line 1 (Header Object):
```json
{"protocol":"DEWP","version":"1.0","kind":"dewp.audit.evidence-stream","exportedAt":"2026-07-24T12:30:00.000Z","tenantId":"tenant-uuid-01"}
```

Line 2..N (Entry Objects):
```json
{"type":"entry","seq":"1048576","tenantSeq":"42","leaf":"d4e5f6...","canonical":[...],"proof":{...}}
```

Line N+1 (Trailer Commitment Object):
```json
{"type":"trailer","seqStart":"1","seqEnd":"42","entryCount":42,"checkpointRoot":"e9f8a7..."}
```

## 6.5 Kind Values

The canonical `kind` values are `dewp.audit.inclusion-proof`, `dewp.audit.evidence-bundle`, and `dewp.audit.evidence-stream`. A compliant DEWP producer MUST emit these forms and a compliant verifier MUST reject any other value. There are no vendor-prefixed aliases: `kind` names the protocol, never the implementer.

---

# 7. Verification Procedure & Verification Levels

An auditor or Relying Party verifying a DEWP Proof Bundle MUST perform the following steps:

```
                          [ Start Verification ]
                                     │
                                     ▼
                [ Check 1: Verify Domain & Bundle Version ]
                                     │
                                     ▼
           [ Check 2: Recompute Leaf Hash from Canonical Preimage ]
             hashLeaf(canonical) == proof.leaf (if unredacted)
                                     │
                                     ▼
            [ Check 3: Hop 1 - Verify Event Leaf → Block Root ]
   verifyMerkleProof(leaf, blockProof, blockRoot,
                     {leafIndex, blockLeafCount}) == true
                                     │
                                     ▼
          [ Check 4: Hop 2 - Verify Block Root → Daily Root ]
   verifyMerkleProof(hashLeaf(blockRoot), checkpointProof, dailyRoot,
                     {checkpointLeafIndex, checkpointLeafCount}) == true
                                     │
                                     ▼
              [ Check 5: Compare Against Trusted Signed Anchor ]
      verifyAnchorSignature(anchor, 0x03) && dailyRoot == anchor.dailyRoot ?
                                     │
                                     ▼
            [ Check 6: Verify Tenant Sequence Continuity ]
                 tenantSeq_N+1 == tenantSeq_N + 1 ?
                                     │
                                     ▼
          [ Verdict: CONTENT / COMMITMENT / SIGNATURE / FULLY PASSED ]
```

Check 6 is defined over one specific copy of `tenantSeq` and not the others; §7.2 states which.

## 7.1 Verification Properties and Derived Level

A verifier MUST evaluate four **independent** boolean properties. They are orthogonal — in particular, anchor verification is NOT a strict superset of signature verification (a content-only event with no signer can still be anchor-verified; a signed event can be content-and-signature-verified without any anchor):

| Property | Meaning |
|---|---|
| `commitmentVerified` | The two-hop Merkle inclusion (leaf → block root → daily root) recomputes to the bundle's `checkpointRoot`. Holds for redacted entries where only the leaf is retained. |
| `contentVerified` | `commitmentVerified` AND the full Canonical Preimage is present AND `hashLeaf(canonical) == proof.leaf`. Not achievable for `COMMITMENT_ONLY` entries (content purged). |
| `signatureVerified` | The embedded event signature material (`signedPayload`, `signature`, `signerPublicKey`) verifies offline. Requires `contentVerified` (you must have the signed bytes). N/A when no signer is present. |
| `anchorVerified` | The `checkpointRoot` satisfies the verifier's anchor quorum policy (§5.3): ≥ `requiredAnchors` trusted issuers signed the SAME root under the `0x03` domain tag, each anchor binding the checkpoint's position and — for an external witness — witnessed within the §5.3 time bound. |

A bundle MAY carry a summary `verificationLevel` for display, but conformant verifiers MUST also expose the four properties so a Relying Party can apply its own policy. The summary level is derived as:

* **`INVALID`**: `commitmentVerified == false` (inclusion or leaf-hash recomputation failed), OR anchor divergence was detected.
* **`COMMITMENT_VERIFIED`**: `commitmentVerified` only (redacted / commitment-only entry).
* **`CONTENT_VERIFIED`**: `commitmentVerified && contentVerified`.
* **`SIGNATURE_VERIFIED`**: `contentVerified && signatureVerified`.
* **`FULLY_VERIFIED`**: all required properties for the entry passed **and** `anchorVerified`. For a signed event that is `contentVerified && signatureVerified && anchorVerified`; for an unsigned event that is `contentVerified && anchorVerified` (no signature is required to exist).

A Relying Party MUST NOT treat `SIGNATURE_VERIFIED` as implying independent non-repudiation: without `anchorVerified` the root is still only vendor-asserted.

A verifier implementing §4.7 additionally reports, for an Evidence Bundle, an Execution Status per approval nonce and a check per Evidence Record. These sit beside the four properties: they never change a property or the derived level, and an Execution Status is only as meaningful as the entries it was computed from — a `confirmed` status over entries that are not anchor-verified rests on a vendor-asserted root.

## 7.2 Check 6 — Tenant Sequence Continuity: Source, Disclosure, Declared Range

An Evidence Bundle carries `tenantSeq` in up to three places per entry, and only one of them is covered by the Merkle commitment:

| Location | Covered by the leaf? |
|---|---|
| `entries[].event.canonical.tenantSeq` — the final Canonical Preimage element (§4.1) | **Yes.** `hashLeaf(canonical)` is what the two-hop proof binds to the anchored root. |
| `entries[].event.redaction.commitment.tenantSeq` — retained through `COMMITMENT_ONLY` redaction (§15) | No. It is the producer's redaction record. |
| `entries[].event.tenantSeq` — the display copy carried on every entry | No. It is a sibling of `canonical`, and nothing signs it. |

1. A verifier MUST read the counter from `canonical.tenantSeq` for every entry that carries a Canonical Preimage, and from nowhere else: a `null` there means the entry has no counter (rule 5), never "fall back". Preferring the display copy is a conformance failure, not an implementation shortcut: a producer that drops the incriminating events, keeps the honest ones with their genuine proofs, and renumbers the display copies to close the hole yields a bundle that passes such a check reporting no gap — which forfeits §17.2 outright. Falling back to the redaction record for a preimage whose counter is `null` is the same failure: a genuine tenant-less leaf, tagged with an unsigned `redaction.commitment.tenantSeq`, then fills the hole while counting as content-verified. (A preimage the verifier could not bind to its leaf — an entry under an unrecognised Application Profile, §4.5 — is not leaf-bound either; in an Evidence Bundle such an entry fails, and its counter is not read.)

2. Only where an entry has no preimage — a `COMMITMENT_ONLY` entry, whose content was lawfully purged — the verifier MAY fall back to `redaction.commitment.tenantSeq`, and then to `event.tenantSeq`. Without a fallback the position lawful redaction leaves behind would read as an omission.

3. Where a preimage IS present, the verifier MUST compare `event.tenantSeq` and `redaction.commitment.tenantSeq`, when present, against `canonical.tenantSeq` and fail the entry when either differs. The same applies to every other field duplicated alongside the preimage (`seq`, `createdAt`, `type`, `outcome`, `signerDid`, `sigAlg`): the displayed copy is what a human, a console or a SIEM reads, so an unchecked one is a caption over the evidence rather than part of it.

4. A verifier that read any counter under rule 2 MUST disclose it in its verdict. Continuity across values that are not leaf-bound rests on the producer's redaction record, not on the anchored log, and a Relying Party cannot tell that from a bare pass.

5. An entry carrying no `tenantSeq` in any of the three locations — or a preimage whose `tenantSeq` is `null` — MUST NOT be treated as continuous with its neighbours: it occupies no counter position, and the verifier MUST disclose that gaplessness could not be checked across it.

6. `tenantSeq` is a per-tenant counter, so contiguity is meaningful only over one tenant's entries. Every content-verified entry whose `canonical.tenantId` is non-null MUST equal `tenant.id`; a bundle whose `tenant` is absent or has a `null` id declares no tenant, and any entry naming one MUST fail. (Otherwise one tenant's genuine, leaf-bound counters splice into another's gap.)

### Cross-checking `tenantSequenceCommitment`

Contiguity alone proves only that the entries *present* are consecutive — not that the producer exported the range it says it exported. `tenantSequenceCommitment` (§6.3) declares the closed range a bundle covers; the published JSON Schema requires a producer to emit it whenever any entry carries a `tenantSeq`, so a bundle with counters and no declared range is already non-conformant. A verifier MUST check the entries against it:

- The counter read from the first entry that carries one MUST equal `firstTenantSeq`, and the counter read from the last such entry MUST equal `lastTenantSeq`. Either mismatch is a verification failure — the producer narrowed the range it declared.
- `tenantSequenceCommitment.tenantId` SHOULD equal `tenant.id`; a mismatch MUST be disclosed.
- If no entry carries a readable counter, the cross-check is unsatisfiable; the verifier MUST disclose that the declared range went unchecked rather than treat it as met.

Two limits of the cross-check, both structural: `tenantSequenceCommitment` is itself an unsigned producer claim, so it catches only a producer whose truncation contradicts its own declaration; and it says nothing about counters outside the declared range (§3 Invariant 4).

---

# 8. Security Considerations & Threat Model

DEWP provides cryptographic protection against:

* **Post-hoc Modification of Committed Events:** Altering any attribute of a committed event breaks its `leafHash` and invalidates the Merkle inclusion proof against the published root.
* **Deletion of Committed Events:** Deleting an already-committed event breaks the contiguous `tenantSeq` chain, letting auditors detect that a committed event is missing. This does NOT prove a producer never withheld an event from commitment in the first place (see §3 Invariant 4): DEWP evidences the integrity and completeness of the *committed, anchored* history, not of all real-world events.
* **Cross-Domain Signature & Second-Preimage Collisions:** Domain separation prefixes (`0x00` leaves, `0x01` nodes, `0x02` empty root, `0x03` anchors, `0x04` checkpoint chain) prevent attackers from presenting interior node hashes, anchor signatures, or chain links as valid leaf preimages.
* **Vendor Log Forgery:** Requiring daily checkpoint roots to be signed under domain `0x03` and published to independent public anchors prevents platform operators from quietly rewriting historical audit logs.
* **Privacy Retention Compliance:** Commitment-Only verification allows data retention ladders to redact sensitive user data while leaving the immutable Merkle cryptographic commitment intact.

---

# 9. Conformance Requirements & Profiles

A compliant implementation MUST claim conformance to one of two profiles:

### 9.1 DEWP Core Profile
Requires implementation of:
- RFC 8785 JCS 12-element canonical array serialization (Section 4.1).
- Domain-separated Merkle leaf and node hashing (Section 4.4).
- Single inclusion proof verification (`dewp.audit.inclusion-proof`).

The `0x04` checkpoint continuity chain (§5.4) is **outside Core**: it belongs to the roots-file
transport, not to inclusion verification. The repository's TypeScript, Python, Go, Rust and Java
verifiers implement it alongside the Core primitives. External implementations that omit it SHOULD
state that limit explicitly.

### 9.2 DEWP Extended Profile
Requires implementation of **DEWP Core** plus:
- Multi-entry evidence bundle verification with `tenantSeq` gapless validation (`dewp.audit.evidence-bundle`).
- NDJSON evidence streaming (`dewp.audit.evidence-stream`) — see the §6.4 note: specified but unimplemented, so no implementation claims this profile.
- Signed multi-anchor verification with `0x03` domain tag (Section 5.2 & 6.2).
- Offline event-signature verification of embedded intent-proof material (Sections 1.3 & 7.1), evaluated **per entry** in a multi-entry bundle as well as for a single inclusion proof. Only signature material a leaf carries in full is checkable offline: `ES256` over `signedPayload`, or a `WEBAUTHN` assertion when the Application Profile carries `authenticatorData` and `clientDataJSON` and the caller supplies signer trust, expected origin and RP ID (§4.6.1). Missing material/trust is reported as not checked; `AUTO_APPROVED` has no human signature and is not applicable. A caller may require trusted signatures as an additional acceptance policy. An entry whose committed signature does not verify MUST be reported, but MUST NOT by itself invalidate the entry's commitment or content verification — the signature bytes are themselves committed, so a failure there means the producer anchored proof material that does not check out, not that the bundle was altered.
- Support for Application Profile Extensions (Section 4.5).

### 9.3 Execution Evidence (optional, version 1.1)
An Extended implementation MAY additionally claim Execution Evidence conformance, which requires:
- Recognition of Evidence Records and the §4.7.3 statement check, with evidence-source trust separate from approver trust (§4.7.5) in both the statement check and the §4.6.1 signature check.
- The §4.7.4 Execution Status for every nonce in an Evidence Bundle — Approval Records included — with a caller-supplied evaluation time, skew allowance and maximum evidence window; the §4.7.4 findings (dispatch conflict, late contradiction, untrusted contradiction, window capped, source continuity); evidence-source key validity intervals checked at the anchored time (§4.7.5); and an optional caller policy requiring every nonce to be `confirmed`.
- The §4.7.7 parsing procedure wherever §4.7 parses a signed payload, so that no two verifiers classify the same bytes differently.
- The `executionEvidence` cases of `verifier-parity-vectors.json` (§10).

The repository's TypeScript, Python, Go, Rust and Java verifiers claim it.

---

# 10. Reference Test Vectors

Compliant implementations MUST pass the official cross-language golden test vectors, published in this
repository as `packages/mcp-schemas/vectors/ledger-vectors.json` (DEWP) alongside
`canonical-vectors.json` (the companion DIV set). **Those files are the normative source.**
`verifier-parity-vectors.json` additionally pins executable receipt, bundle, anchor-quorum, Rekor,
redaction, sequence-range and continuity cases across all five repository verifiers; its
self-contained `dewpEvidenceHardening` section (own keys) pins the September 2026 evidence rules —
counter source, tenant binding, unknown profiles, caller-trusted checkpoint records, duplicate entries,
leaf-count binding and the anchor algorithm registry — and its `verifierInputHardening` section
(own keys) pins the §5.2 RSA-PSS profile (salt length, key size) and the §5.3 admission rules for
divergence evidence. Its `executionEvidence` section (own keys) pins §4.7: every statement-check
outcome, every Execution Status, the precedence, binding, window and window-bound rules, the
enumeration of Approval Records, the late-contradiction, untrusted-contradiction, dispatch-conflict and source-continuity
findings, key validity at the anchored time, and the separation of evidence-source trust from approver
trust.

The cases below are **not** drawn from those files. They are independent worked examples over the
**bare 12-element Core** array (no Application Profile), provided so an implementer can check a fresh
SHA-256 implementation against known digests before wiring up the full vector suite. The normative
vectors use the 18-element `trust.intyga.audit.v1` profile layout (§4.5) and therefore produce
different digests — passing the examples below is necessary but not sufficient for conformance.

All digests are lowercase hex.

```json
{
  "leafPreimageCase1": {
    "input": [
      "1048576", "2026-07-24T12:00:00.000Z", "ACTION_APPROVED", "SUCCESS",
      "Database drop approved", "{\"target\":\"users\"}", "did:example:human:alice",
      "base64-spki", "{\"actionType\":\"db:dropTable\",\"type\":\"div-intent-verification\",\"v\":1}", "base64-sig", "ES256", "42"
    ],
    "expectedCanonicalJCS": "[\"1048576\",\"2026-07-24T12:00:00.000Z\",\"ACTION_APPROVED\",\"SUCCESS\",\"Database drop approved\",\"{\\\"target\\\":\\\"users\\\"}\",\"did:example:human:alice\",\"base64-spki\",\"{\\\"actionType\\\":\\\"db:dropTable\\\",\\\"type\\\":\\\"div-intent-verification\\\",\\\"v\\\":1}\",\"base64-sig\",\"ES256\",\"42\"]",
    "expectedLeafHash": "0d82acddaf17b6fecccffa03e13d97174d0d0aaf69893251dcd3d79ba48385fe"
  },
  "anchorPreimageCase1": {
    "input": [
      "e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8",
      "2026-07-24T23:59:00.000Z",
      "https://transparency.example.org",
      "ES256",
      "1048576",
      "1049600",
      "6ae54abac75d273317f9f369306f2fbe85f2fafc9dd30685dc4f8a375257ef2b"
    ],
    "expectedAnchorPreimage": "[\"e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8\",\"2026-07-24T23:59:00.000Z\",\"https://transparency.example.org\",\"ES256\",\"1048576\",\"1049600\",\"6ae54abac75d273317f9f369306f2fbe85f2fafc9dd30685dc4f8a375257ef2b\"]",
    "expectedAnchorDigest": "058a3dbd2ad910d9e06597eab8350b9e4df2e94985dd09f7dfb5144df433ed77"
  },
  "emptyTreeRoot": "dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986"
}
```

The `chainHash` in `anchorPreimageCase1` is the genesis §5.4 chain hash of that checkpoint:
`chainHash([ "", "e9f8…e9f8", "1048576", "1049600", "1025", "2026-07-24T23:59:00.000Z" ])`.

`emptyTreeRoot` is `SHA-256(0x02)` — the empty-tree domain tag hashed alone, not the hash of an empty
byte string. An implementation returning `SHA-256("")` for an empty tree is non-conformant.

Note that `expectedAnchorDigest` is the value that gets **signed as 32 raw bytes** (§5.2); its hex form
above is for comparison only. An implementation that signs the 64-character hex text will match this
vector's digest and still fail to interoperate.

---

# 11. Reference Verification Algorithm

## 11.1 Why Bounds Are Mandatory

Recomputing the root from a leaf and a sibling path is **not** sufficient to establish membership in this tree, and an implementation that stops there is non-conformant.

§5.1.3 pads an unpaired trailing node by hashing it against itself. Therefore `merkleRoot([a,b,c])` and `merkleRoot([a,b,c,c])` are equal, and a path constructed for the nonexistent index 3 recomputes the 3-leaf root exactly. A verifier with no index and no leaf count has nothing to reject it with, which falsifies §17.1's claim that forging an inclusion path requires a SHA-256 second preimage.

A verifier MUST therefore be given, and MUST check, the leaf's `index` and the tree's `leafCount`. Three checks follow, and all three are required:

1. **Range** — `0 ≤ index < leafCount`.
2. **Path length** — `proof.length` MUST equal `ceil(log2(leafCount))`, or `0` when `leafCount ≤ 1`.
3. **Self-pairing** — a node hashed against itself is legitimate **only** at the unpaired end of an odd-sized level. Any other self-paired step MUST be rejected.

Check 3 is what actually closes the forgery. `leafCount` arrives inside the proof, so a prover can inflate it: claiming `leafCount = 4` on a 3-leaf tree puts index 3 in range and makes the path length correct, and the duplicate-last root is identical — so range and length alone still accept it. Padding is observable, however: a sibling equal to the running node anywhere except the unpaired end of an odd level is the signature of an index pointing into padding.

Sibling side MUST also be derived from the index rather than read from the proof. Letting the prover choose each side freely restores the flexibility the length check just removed.

## 11.2 Reference Implementation

```typescript
export interface ProofStep {
  siblingHash: string                 // digest of the sibling node
  siblingPosition: "LEFT" | "RIGHT"   // side the SIBLING sits on, relative to the running node
}

/** Position of the leaf this proof is for, and how many leaves its tree had. REQUIRED. */
export interface ProofBounds {
  index: number
  leafCount: number
}

export function expectedPathLength(leafCount: number): number {
  return leafCount <= 1 ? 0 : Math.ceil(Math.log2(leafCount))
}

export function verifyMerkleProof(
  leafHex: string,
  proof: ProofStep[],
  rootHex: string,
  bounds: ProofBounds
): boolean {
  const { index, leafCount } = bounds
  if (!Number.isInteger(index) || !Number.isInteger(leafCount)) return false
  if (leafCount < 1 || index < 0 || index >= leafCount) return false
  if (proof.length !== expectedPathLength(leafCount)) return false

  let idx = index
  let levelSize = leafCount
  let node = leafHex
  for (const step of proof) {
    // The side follows from the index; a prover-chosen side is not accepted.
    const expectedSide = idx % 2 === 1 ? "LEFT" : "RIGHT"
    if (step.siblingPosition !== expectedSide) return false

    // Self-pairing is legitimate ONLY at the unpaired end of an odd-sized level.
    const selfPaired = step.siblingHash === node
    const legitimatelyUnpaired = idx === levelSize - 1 && levelSize % 2 === 1
    if (selfPaired && !legitimatelyUnpaired) return false

    const siblingIsLeft = step.siblingPosition === "LEFT"
    const left = siblingIsLeft ? hexDecode(step.siblingHash) : hexDecode(node)
    const right = siblingIsLeft ? hexDecode(node) : hexDecode(step.siblingHash)
    node = hexEncode(sha256(concat(byte(0x01), left, right)))

    idx = Math.floor(idx / 2)
    levelSize = Math.ceil(levelSize / 2)
  }
  return node === rootHex
}
```

## 11.3 Two-Hop Inclusion

An event is committed under a daily root in two hops: event leaf → block root, then block root → daily root. The daily tree's leaves are `hashLeaf(blockRoot)`, so the block root MUST be re-wrapped with the leaf tag (`0x00`) before the second hop.

```typescript
export function verifyInclusionProof(proof: InclusionProof, dailyRoot: string): boolean {
  if (
    !Number.isInteger(proof.leafIndex) ||
    !Number.isInteger(proof.blockLeafCount) ||
    !Number.isInteger(proof.checkpointLeafIndex) ||
    !Number.isInteger(proof.checkpointLeafCount)
  ) return false

  if (!verifyMerkleProof(proof.leaf, proof.blockProof, proof.blockRoot, {
    index: proof.leafIndex, leafCount: proof.blockLeafCount,
  })) return false

  return verifyMerkleProof(hashLeaf(proof.blockRoot), proof.checkpointProof, dailyRoot, {
    index: proof.checkpointLeafIndex, leafCount: proof.checkpointLeafCount,
  })
}
```

For any verdict a Relying Party acts on, `dailyRoot` MUST be a root the Relying Party obtained **independently** of the proof — one it recorded earlier, or one from the published roots file whose chain it has verified (§5.4.1). It cannot be taken from an external anchor, which holds only a digest committing to the root (§3 Invariant 6). Trusting the root carried inside the proof lets a forged bundle vouch for itself, which defeats the entire construction, so a result computed against `proof.checkpointRoot` MUST NOT be reported as trusted, anchored, or non-repudiable, and MUST NOT on its own produce an overall pass. Running this same function against `proof.checkpointRoot` to establish `commitmentVerified` (§7.1) — internal consistency, when no root was supplied — is permitted, provided the verifier reports the root's provenance alongside the result; the reference implementations expose it as `rootSource: "self-asserted"`, and a supplied root as `rootSource: "caller-supplied"` — never "independent", since the verifier cannot know where the caller got it.

---

# 12. Algorithm Registry & Migration Rules

| Registry Key | Algorithm / Specification | Status |
|---|---|---|
| `hashAlgorithm` | SHA-256 (FIPS 180-4) | MANDATORY |
| `serialization` | RFC 8785 (JSON Canonicalization Scheme / JCS) | MANDATORY |
| `merkleVersion` | 1 (Two-tier block + checkpoint hierarchy) | MANDATORY |
| `signatureAlgorithms` | `ES256` (P-256 + SHA-256), `WEBAUTHN`, `AUTO_APPROVED` | EXTENDED |

> `Ed25519` is an **anchor** signing algorithm (§14), not an event `sigAlg`. It is deliberately absent
> from the emitted `algorithmRegistry` (`ALGORITHM_REGISTRY`, `packages/db/src/checkpoint.ts`) and from
> the §6.1 example — the registry above and the emitted value MUST agree.

## 12.1 Hash Algorithm Migration Procedure

If `hashAlgorithm` is upgraded to `SHA3-256` or `BLAKE3`:
1. The new algorithm identifier MUST be announced in the `algorithmRegistry`.
2. Historical blocks signed under SHA-256 MUST remain verifiable without re-hashing past checkpoint roots.

---

# 13. Version Migration Rules

1. **Preimage Array Format:** The 12-element Canonical Preimage array MUST NOT be reordered. Future protocol extensions MUST append new fields to the end of the array (index 11+ before `tenantSeq`) accompanied by a `version` bump or Application Profile.
2. **Backward Compatibility:** Verifiers encountering a `version: 2` bundle MUST process the fixed core fields `0..10`, and `tenantSeq` at the **final** index, as defined in this specification — "last", not a fixed numeric position, is `tenantSeq`'s only location rule (§4.1/§4.5).
3. **Additive Revisions:** A revision that adds only new event types or new signed statements carried in the existing slots — as version 1.1 does (§4.7) — keeps the bundle `version` at `"1.0"` and the profile unchanged, so earlier verifiers keep verifying commitment and content. Such a revision MUST NOT change the meaning of an existing event type or of existing slot contents.

The §5.2 signed input binds the checkpoint's position (seq range and chain hash) since the September
2026 pre-release correction. That makes a genuine anchor for another checkpoint distinguishable from a
conflicting one by its own signed fields, which a future revision could use to let bundle-carried
anchors establish divergence; this revision does not, because a bundle is still the producer's
selection of anchors.

---

# 14. Key Lifecycle Management

- **Anchor Signing Keys:** Anchor providers MUST sign daily checkpoint objects with a **signature** algorithm — ECDSA P-256 (`ES256`), Ed25519, or RSA-PSS (SHA-256, 32-byte salt, modulus of at least 2048 bits; §5.2). RSA-OAEP MUST NOT be used: it is an encryption padding, not a signature scheme.
- **Rotation & Revocation:** Anchor signatures MUST include a `keyId` and timestamp. Revoked keys MUST NOT invalidate historic daily roots signed prior to the key's revocation timestamp.

---

# 15. Privacy and Retention Model

- **Redaction Policy:** When a tenant triggers data retention or GDPR right-to-be-forgotten deletion, private fields MAY be purged from storage. The purgeable set is all five of `detail`, `metadata`, `signedPayload`, `signature` and `signerPublicKey` — matching the `removedFields` in the §6.3 example and what the retention sweep actually writes (`packages/db/src/evidence.ts`). The proof material (`signature`, `signerPublicKey`) is purgeable because it is personal data about the approver; the retained `leaf` is what preserves the commitment.
- **Commitment Preservation:** A `COMMITMENT_ONLY` redaction MUST preserve, and a compliant bundle MUST carry, all three of:
  1. **`leaf`** — the original `leafHash` (the domain-separated digest of the pre-redaction Canonical Preimage). It MUST NOT be recomputed or altered; it is what still verifies against the anchored Merkle root.
  2. **Commitment metadata** — the non-sensitive positional fields needed to keep the entry meaningful and gapless: `seq`, `tenantSeq`, `createdAt`, `type`, `outcome`, and the inclusion `proof`.
  3. **A redaction proof** — a `redaction` object recording `mode: "COMMITMENT_ONLY"`, `removedFields`, `redactedAt`, and `reason`, so an auditor can see *that* content was purged and *why*, distinguishing lawful redaction from tampering.
- A verifier encountering a `COMMITMENT_ONLY` entry MUST verify inclusion against the retained `leaf` (yielding `commitmentVerified`) and MUST NOT attempt `contentVerified`/`signatureVerified` (the preimage is intentionally absent).

---

# 16. Threat Model

What an attacker gains by compromising each component:

| Compromised Component | Consequence & Mitigation |
|---|---|
| **Audited Application / DB** | Can delete local DB rows. **Mitigation:** Deleting rows breaks `tenantSeq` gaplessness and leaves un-matched leaf hashes under the public anchor. |
| **Witness Platform Server** | Can withhold evidence exports (denial of service). **Mitigation:** Cannot rewrite past events without breaking published daily roots. |
| **Single Anchor Provider** | Could sign an alternate root. **Mitigation:** Multi-anchor verification (`anchors: [...]`) detects anchor divergence. |
| **Executing Party** | Can claim dispatch, write misleading Dispatch Records and withhold contrary evidence. **Mitigation:** It cannot author an Execution Evidence Statement (it lacks the source's key), so it cannot produce `confirmed`; an early Dispatch Record with another hash cannot unbind genuine statements and is reported as a conflict, and a far-out deadline is cut to the verifier's window (§4.7.3); a statement withheld from inside the exported range shows as a gap in the source's `sequence`, one after the last committed statement does not (§4.7.6). |
| **Evidence Source** | Can sign a false observation. **Mitigation:** None within DEWP. Trust sources whose observations are independent physical measurements, prefer several, and note that one trusted `contradicted` outweighs any number of `confirmed` (§4.7.4). |

---

# 17. Formal Security Properties

DEWP's guarantees hold under standard cryptographic assumptions — collision resistance and second-preimage resistance of SHA-256 (FIPS 180-4), and existential unforgeability of the chosen signature scheme. They are conditional on those assumptions, not unconditional:

Each property below is referenced elsewhere as **§17.N**.

1. **§17.1 — Committed-Event Tamper-Evidence:** Producing a distinct event that collides to an already-committed `leafHash`, or forging an inclusion path to a published root, requires a SHA-256 collision/second-preimage — assumed infeasible (~2⁻²⁵⁶ for a random target under the random-oracle heuristic). **This property is conditional on the verifier enforcing proof bounds (§11.1).** Against an unbounded path check it does not hold: §5.1.3 padding lets a path to a nonexistent index recompute the real root with no second-preimage at all.
2. **§17.2 — Committed-Omission Detectability:** Deleting a **committed** event whose `tenantSeq_N` lies between retained `tenantSeq` values yields a detectable gap. This is a structural property of the contiguous counter over the committed set; it says nothing about events never committed (§3 Invariant 4). **The property is conditional on the verifier reading the leaf-bound counter (§7.2).** Against a check run over the unsigned display copy it does not hold at all: the omitted range is closed by renumbering, with no hash broken.
3. **§17.3 — Cross-Domain / Subtree-Substitution Resistance:** Distinct domain tags (`0x00` leaf, `0x01` node, `0x02` empty root, `0x03` anchor, `0x04` checkpoint chain) make a leaf preimage, an interior-node input, an anchor-signing input, and a chain-link input mutually non-interchangeable, so a subtree root cannot be presented as a leaf (nor a tree hash as an anchor signature input, nor a chain hash as any of them) except via a SHA-256 second-preimage. **This property holds where the verifier hashes the leaf from its preimage.** For a `COMMITMENT_ONLY` entry the leaf is taken from the proof, and the proof also supplies `blockLeafCount`, so an interior node of a larger block can be offered as a leaf of a claimed smaller one. A verifier MUST therefore bind the leaf counts where it can: proofs into one block or checkpoint in a bundle MUST agree on them, and, where a checkpoint `entryCount` is known (the sum of its blocks' leaf counts), `checkpointLeafCount ≤ entryCount`, `blockLeafCount + checkpointLeafCount − 1 ≤ entryCount`, and `blockLeafCount = entryCount` when the checkpoint has a single block. A redacted single proof verified with no checkpoint record remains exposed to this and is reported only as `COMMITMENT_VERIFIED`.

---

# 18. References

## 18.1 Normative References

* RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels.
* RFC 8174 — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
* RFC 8785 — JSON Canonicalization Scheme (JCS).
* RFC 6962 §2.1 — Certificate Transparency. Cited specifically for the Merkle audit-path leaf/node domain-separation technique (the `0x00`/`0x01` prefixing) that DEWP adopts and extends; not cited as a general second-preimage authority.
* RFC 9562 — Universally Unique Identifiers (UUIDs), including UUIDv7. Cited for the optional time-ordered event `id`, not for the numeric `seq` counter.
* FIPS 180-4 — Secure Hash Standard (SHS).
* RFC 8017 §8.1 — PKCS #1 v2.2, RSASSA-PSS. Cited for the `RSA-PSS` anchor algorithm (§5.2).

## 18.2 Informative References

* DIV Specification — Deterministic Intent Verification (`docs/DIV.md`).
* RFC 9334 — Remote ATtestation procedureS (RATS) Architecture. Relevant to evidence sources that report measured-boot or attestation results (Appendix A).
* RFC 3161 — Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP).
* draft-williams-intent-token — describes a JWT-based pre-execution authorization token paired with a hash-chained audit structure ("Fractal Crypto-Temporal Graph"); DEWP differs by providing two-hop Merkle inclusion proofs and independently-anchored quorum verification (§3, §5) rather than a single unanchored hash chain.

---

# Appendix A. Evidence Criteria for Physical Actions (Non-Normative)

What a statement should establish depends on the action. These criteria, from control-system
practice, illustrate the bar for an independent observation:

- **Separation from the command path.** The party that sent a command should not be able to write the
  evidence about its effect. Evidence produced by the same controller, service or credential that
  issued the command is that party's own account.
- **Cross-checked state, not reported intent.** For a circuit breaker, position from the auxiliary
  contacts (52a/52b) cross-checked against independently measured current or voltage within a defined
  window. Account for prior conditions: if no current flowed before, zero current afterwards proves
  nothing, and the observation should record the prior state alongside the new one.
- **What actually runs, not what was installed.** For firmware, the digest of the image that actually
  booted, from measured boot or remote attestation (RFC 9334) — never a hash the updated application
  reports about itself.
- **Missing, stale or contradictory evidence is not success — and the two are not the same.** A source
  should sign `contradicted` when its measurements disagree with the approved effect, and sign nothing
  when it cannot decide. Neither outcome defaults to success, but they call for different responses:
  `unconfirmed` (the source could not tell — often a lost or stale sensor) calls for investigation,
  `contradicted` (a trusted source saw the action not take effect) for escalation.
- **A compromised source limits the claim.** If the source itself may be compromised, claim only what
  independent physical measurements support.
- **Read-back is not independence.** Evidence read back through the controller under test — the PLC
  that executed the command reporting its own outputs, the updated device reporting its own firmware
  hash — is that controller's account, not an observation of it.
- **Independent means separately sensed.** Sources that share a sensing path (one transducer, one I/O
  card, one network tap) or one time source are not independent of each other; "prefer several" means
  several that fail separately, not several readings of one signal.
- **Observe after settling.** The evidence window must open after the process has settled: a breaker
  takes tens of milliseconds, a reboot minutes. A source that samples before settling sees the old state
  and signs `contradicted` for an action that then succeeded; the executing party sizes the window for
  the process, and the source signs `sampledAt` so a verifier can tell when it looked. This is also why
  the pre-dispatch allowance is small and covers clock error only (§4.7.3 step 6): a measurement from
  just before dispatch, of a state that was already in place, confirms a no-op.
- **One-way from source to log.** Where possible the path from an evidence source to the log should be
  one-way (a data diode, a push-only forwarder), so that neither the party being observed nor the log
  can reach back into the source.

These criteria are offered as review criteria, not as field-validated results.
