# Deterministic Intent Verification (DIV) Protocol Specification

**A Stateless Protocol Primitive for Non-Repudiable Action Authorization in Autonomous and High-Risk Infrastructure.**

*Open Specification · Version 1.0.0 · 4 October 2026*

---

## Abstract

This document specifies Deterministic Intent Verification (DIV), a transport-independent format for signed action approvals and their offline verification. A relying party reconstructs the signed payload from its expected execution parameters, verifies witnesses against locally selected trust anchors, and checks the signed approval requirement against any locally configured approval policy. The specification covers ordinary approvals, offline approvals, delegation, agent authority, and platform hash-only intents. Cryptographic verification is stateless; enforcing single-use execution requires stateful nonce redemption. A valid signature establishes approval of the signed bytes under the selected trust policy, not execution of the action or the approver's understanding of it.

---

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

---

# 1. Scope & Explicit Non-Goals

To maintain a minimal trust surface, DIV narrowly defines only the intent object, its proof envelope, its deterministic serialization, and the local verification algorithm.

## 1.1 Scope

DIV specifies exclusively:

1. The canonical data schema for an explicit intent payload and its proof envelope.
2. The deterministic serialization rules adhering to JSON Canonicalization Scheme (JCS) [RFC8785].
3. The local, in-process algorithm executed by a Relying Party to verify an intent proof against runtime parameters.

## 1.2 Out-of-Scope (Explicit Non-Goals)

DIV explicitly does **NOT** define:

* **Authentication or Identity Management:** DIV assumes identity attestation (e.g., OIDC, SPIFFE, DIDs) is established independently.
* **Key Distribution or PKI:** Public key discovery, trust anchors, and key rotation mechanisms are deferred to external key-management infrastructure.
* **Transport Protocols:** DIV envelopes MAY be carried over HTTP, gRPC, WebSockets, or file-based IPC.
* **Approval Workflow Orchestration:** Step-up prompting, notification routing, and quorum scheduling are operational concerns outside this specification.

---

# 2. Terminology & Core Definitions

* **Irreversible Action (IA):** Any state-mutating operation whose execution cannot be completely and atomically rolled back without side effects.

* **Relying Party (RP):** The executing system, application, service, or tool server that receives an execution request and validates the intent proof against its own internal parameter state before invoking the target operation.

* **Issuing Service:** The service that conducts the approval ceremony: it freezes the Intent Payload (including its `requirement`) at issuance, presents it to Approvers, and records the resulting witnesses. Referred to interchangeably in this document as the *approval service* (§5a) and the *issuing deployment* (§5b); the client component that drives a WebAuthn ceremony on its behalf is part of this role. It is distinct from the Relying Party, and the issuer-side MUSTs of §4.3.3 bind it — not Core Profile verifiers.

* **Approver:** A human authority holding a private signing key who cryptographically attests to an explicit execution payload.

* **Target:** A unique, machine-readable string identifying the specific Relying Party instance or execution environment expected to perform the action.

* **Intent Payload:** The canonical structured object containing the exact execution parameters and contextual metadata subject to signature verification.

* **Proof Envelope:** The top-level cryptographic container carrying the Intent Payload and corresponding signature metadata.

* **Intent Proof:** A successfully verified Proof Envelope satisfying all DIV validation requirements.

---

# 3. Protocol Invariants

A compliant DIV implementation MUST satisfy the following structural invariants:

1. **Parameter-Bound Binding**

   The signature MUST be computed over the complete Intent Payload containing the exact execution parameters.

2. **Local Payload Reconstruction**

   The Relying Party MUST NOT trust the payload supplied within the Proof Envelope.

   The Relying Party MUST reconstruct the expected Intent Payload before signature verification,
   taking the **security-binding fields** — `target`, `actionType`, `params` — exclusively from its
   own runtime execution parameters, and asserting the `nonce` of the challenge it is redeeming
   itself. The remaining, **issuance-frozen** fields (`display`, `requester`, `requirement`,
   `evidence`, `expiresAt`, and any type-specific fields) MAY be taken from the envelope: they are inputs to
   reconstruction, not trusted facts, because the signature covers them — a forged value changes the
   reconstructed bytes and fails verification (§4.4.1).

   The signature protects issuance-frozen fields against **third parties only**. They are authored
   by whoever composed the bytes — the Issuing Service, or any Approver composing a payload of their
   own — and each signer attests to them. In particular the `requirement` bounds only what the
   signers themselves stated: it cannot, on its own, stop the Approvers it constrains from stating a
   weaker one. A Relying Party that holds its own approval policy MUST therefore compare the signed
   `requirement` against it (§5 step 3d).

3. **Offline Relying Party Verification**

   The Relying Party MUST verify the signature locally using a trusted Approver public key resolved according to deployment-specific key-management policy.

   Verification MUST NOT require outbound calls to external brokers or verification services.

4. **Fail-Closed Execution**

   Any Irreversible Action encountering missing, malformed, unverified, expired, or replayed Intent Proofs MUST abort execution before invoking the underlying system operation.

5. **Target Isolation**

   The Intent Payload MUST explicitly bind the intended Target identifier to prevent cross-service replay attacks.

---

# 4. Canonical Payload and Proof Envelope Specification

## 4.1 Serialization Format

Intent Payloads MUST be serialized into a deterministic byte sequence using JSON Canonicalization Scheme (JCS) [RFC8785].

Implementations MUST NOT rely on arbitrary JSON serialization behavior.

Canonicalization accepts JSON data only. Runtime arrays with missing elements (for example a sparse
JavaScript array) MUST be refused, rather than collapsed into an empty array or converted to null
elements. A present JSON null element is preserved: `[]` and `[null]` have different signed bytes.

Strings MUST be valid Unicode, as RFC 8785 inherits from I-JSON [RFC7493] §2.1. A string — a value
or a member name — containing an unpaired UTF-16 surrogate (a high surrogate not followed by a low
one, or a low surrogate not preceded by a high one) MUST be refused by producers and verifiers
alike. It MUST NOT be serialized as a `\udXXX` escape, replaced with U+FFFD, or passed through: each
of those was the behaviour of some implementation, and a signature over such a string then verified
in some languages and not in others. A verifier that parses signed JSON text MUST likewise refuse a
`\u` escape naming an unpaired surrogate, and text that is not valid UTF-8, rather than decode a
replacement character. Valid text, including characters outside the Basic Multilingual Plane, is
unaffected: this rule changes no canonical bytes for any valid input.

The cryptographic signature MUST cover only the canonical serialized Intent Payload.

Proof Envelope metadata, transport metadata, and external execution context MUST NOT be included in signature computation.

### 4.1.1 Portable Number Range

RFC 8785 defines a serialization for every finite double, but independent implementations do not agree in practice: each language's number formatter switches to exponent notation at its own threshold, and `-0` has no single spelling. Because the signature covers the serialized bytes, two parties that format one number differently produce different bytes for the same payload — so the signature fails and the verifier reports what looks like tampering.

A number appearing anywhere in a signed payload (including inside `params`) is **portable** when it is finite, is not `-0`, and satisfies one of:

- it is an integer with `|x| < 1e16`; or
- it is `0`; or
- it is a non-integer with `1e-4 <= |x| < 1e16`.

**Producers MUST refuse to sign a payload containing a non-portable number**, rather than emitting bytes some verifiers cannot reproduce. Carry such a value as a decimal string, as an integer in smaller units (e.g. minor currency units), or not at all. Verifiers MAY refuse such a payload for the same reason.

This is stricter than RFC 8785 alone, deliberately: the range is the intersection on which every conformant implementation agrees, and a signature is worth nothing outside it. The reference implementations enforce it at signing time in all five languages, and the conformance vectors (§7a) pin it. DEWP §4.3.1 applies the identical range to committed ledger metadata.

**Integers above 2^53.** The integer clause admits values in `(2^53, 10^16)` that an IEEE-754 double cannot represent exactly. A runtime whose JSON parser preserves big integers (Java, Rust, Python) canonicalizes such a value to its exact digits, while a double-based parser (ECMAScript, Go) rounds it at parse time — the same document then produces different canonical bytes in different languages, and the mismatch reads as tampering. A double-based producer cannot emit such a value in the first place, and the reference producer refuses non-portable content at ingestion, so the case is reachable only from hand-authored or foreign documents. Producers on arbitrary-precision runtimes SHOULD keep integers within `±2^53` and carry larger values as decimal strings; a future revision may tighten the integer bound to `2^53` outright.

#### 4.1.1.1 Shortest Round-Trip Formatting

Restricting the range is necessary but not sufficient. **Inside** the portable range an implementation MUST serialize a number as the **shortest decimal string that round-trips to the same IEEE-754 double** — the ECMAScript `Number::toString` behaviour RFC 8785 §3.2.2.3 mandates. A formatter that emits more digits than necessary produces different bytes for the same value, which fails the signature exactly as an out-of-range value does.

This is called out explicitly because a language's built-in formatter is not automatically conformant, and the failure is silent and version-dependent:

- **Java.** `Double.toString` does **NOT** produce the shortest round-trip form before JDK 19 (JDK-4511638); it emits extra digits for some values. A conformant Java implementation MUST therefore implement shortest-round-trip formatting itself rather than delegating to `Double.toString` — otherwise the same receipt canonicalizes differently on JDK 17 and JDK 21, and interoperates with neither. The reference implementation does this in `packages/verify-java` (`Canonical.formatShortestDouble`).
- **Integers.** A value that is mathematically integral MUST serialize with no decimal point and no exponent (`1`, not `1.0` or `1E0`), for every integral double in the portable range.

An implementation whose standard library already emits the shortest round-trip form (ECMAScript, Go `strconv` with `'g'`/-1, Rust `ryu`, Python `repr`) satisfies this clause without extra work; one whose library does not MUST supply it. The `floats-portable` conformance vectors (§7a) pin the expected strings.

---

## 4.2 Intent Payload Schema

```json
{
  "v": 1,
  "type": "div-intent-verification",
  "target": "prod-db-cluster-01",
  "actionType": "db:dropTable",
  "display": "Delete production users table",
  "params": {
    "environment": "production",
    "table": "users"
  },
  "evidence": null,
  "requester": {
    "did": "did:example:service:deploy-pipeline",
    "attestation": null
  },
  "requirement": {
    "requiredApprovals": 2,
    "requireHardwareKey": true,
    "allowedAaguids": ["adce0002-35bc-c60a-2b7b-40b2ede212b7"],
    "requesterCannotApprove": true,
    "signerClass": "human"
  },
  "nonce": "c_8f91a2b4c6e8",
  "expiresAt": "2026-07-24T12:05:00Z"
}
```

---

## 4.3 Intent Payload Field Definitions

| Field | Type | Requirement | Description |
|---|---|---|---|
| v | uint8 | REQUIRED | DIV protocol version. MUST equal 1. |
| type | string | REQUIRED | MUST equal div-intent-verification. |
| target | string | REQUIRED | Intended execution target identifier. |
| actionType | string | REQUIRED | Machine-readable operation identifier. |
| display | string | REQUIRED | Human-readable approval summary. |
| params | object | REQUIRED | Exact execution parameters. |
| evidence | null | REQUIRED | Reserved for external facts upon which authorization may be conditioned (§4.3.4). MUST be present, and MUST be `null` in this version. |
| requester | object | REQUIRED | Request context metadata (§4.3.1). |
| requirement | object | REQUIRED | Approval policy in force at issuance (§4.3.2). |
| nonce | string | REQUIRED | Replay prevention identifier. |
| expiresAt | string | REQUIRED | RFC3339 UTC expiration timestamp. |

For an `AI_AGENT` requester, the unpublished v1 format uses the agent extension in §4.3.6.
`exp` replaces `expiresAt`; `action`, `agent`, `session` and `nbf` are REQUIRED. The ordinary
human/service payload above retains `expiresAt`. A verifier MUST reject an agent payload unless
its RP independently supplies the agent context expected for the action it is about to execute.

### 4.3.1 Requester Object

The `requester` object binds who requested the action:

| Field | Type | Requirement | Description |
|---|---|---|---|
| did | string | REQUIRED | Decentralized identifier of the requesting principal. |
| attestation | object \| null | REQUIRED | Third-party workload attestation, or the literal `null` when the requester is unattested. The `null` is signed and load-bearing: it distinguishes an attested workload from a bare credential holder. |

When present, `attestation` MUST contain exactly:

| Field | Type | Requirement | Description |
|---|---|---|---|
| method | string | REQUIRED | Attestation method (e.g. `oidc`, `spiffe`). |
| issuer | string | REQUIRED | Trust root that vouched for the workload. |
| subject | string | REQUIRED | Attested workload identity. |

### 4.3.2 Requirement Object

The `requirement` object binds the approval policy that was in force when the challenge was issued. It MUST be frozen at issuance and MUST NOT be recomputed at verification time.

| Field | Type | Requirement | Description |
|---|---|---|---|
| requiredApprovals | uint | REQUIRED | Quorum size. The number of distinct approver **identities** that must each contribute a valid witness signature. MUST be an integer ≥ 1, and a verifier MUST reject a payload whose value is absent, non-integral or below 1: §5-step-7 rejects unless the counted identities are *at least* `requiredApprovals`, so a value of 0 is satisfied vacuously and would admit an envelope carrying no valid witness signature at all. Counting signatures rather than identities is a conformance error — see §4.4.2 and §5-step-7. |
| requireHardwareKey | boolean | REQUIRED | Whether the policy demanded an authenticator with verified manufacturer attestation (the reference gateway checks a registration-verified `packed`/`tpm` attestation chain against an independently provisioned hardware-trust root — see its operational docs), not merely a device-bound / non-synced credential: `singleDevice`/`backedUp=false` alone is a backup-flag classification, not evidence of hardware. |
| allowedAaguids | array of string | REQUIRED | Authenticator models the policy admitted, as AAGUIDs. MUST be sorted ascending; the empty array means unrestricted. |
| requesterCannotApprove | boolean | REQUIRED | Whether four-eyes / separation of duties was demanded, i.e. the approver MUST NOT be the requester. |
| signerClass | string | REQUIRED | The class of signer the policy requires. `"human"` is the only value this version defines. Verifiers MUST reject a payload whose `signerClass` is absent or is a value they do not recognize (§5-step-3a). |

**Signer-class registry.** This version defines exactly one signer class:

| Value | Meaning |
|---|---|
| `human` | Every witness signature counted toward `requiredApprovals` must come from a human identity. The issuing service enforces this at signing time; §5-step-3a defines what a verifier can and cannot re-check. |

The field is a string rather than a boolean so that a future class (for example, an agent signing
under a sealed delegation of authority) is a new **value** — one that deployed verifiers refuse
until they are explicitly taught its verification semantics — rather than a change to the payload
shape. Rejecting unknown values is therefore not defensive pedantry; it is the mechanism that keeps
"this receipt is human-approved" a checkable claim as signer classes multiply.

`signerClass` deliberately names the **required class**, not any actual signer: the payload is
frozen at issuance, before any witness exists, and an M-of-N quorum's witnesses need not be
homogeneous in any future class scheme. Per-witness facts live in the Proof Envelope's witness
entries, never in the signed intent.

**Future signer classes (non-normative).** The anticipated second class is an agent approving
within authority a human granted it — call it `delegated-agent`. A future version that defines it
MUST specify, before any verifier accepts the value:

1. **A delegation-of-authority artifact**: a human-signed statement binding the agent's signing key
   to the granting human's identity, with an action scope, parameter bounds, and an expiry — the
   shape §5a.5's Delegation already has, with the delegate being an agent key instead of a human
   operator. A delegation that merely names an agent DID without binding its key inherits the
   §4.4.6 identity-association problem.
2. **Two-signature verification**: the envelope carries the agent's witness signature over the
   Intent Payload AND the delegation artifact (or a resolvable reference to it); the verifier
   checks both, so "the agent approved" is never separable from "a human authorized this agent for
   exactly this scope". The accountable-human chain must survive offline verification with no
   issuer secret, exactly as human approvals do.
3. **Revocation semantics**: what an offline verifier may assume about a delegation's validity
   window, mirroring §5a.6's treatment.

Under this scheme the witness ledger records the agent as the signer and the delegation as the
authority chain — the human's accountability is cryptographic, not annotated. Deployed verifiers
built against this version already refuse `delegated-agent` payloads by the registry rule, which is
precisely the intended migration: nothing verifies as agent-approved until a verifier is upgraded
to check the delegation chain. The scope-declaration half of that artifact is the Agent Authority
(§5b); the key-binding half is what this future class adds.

`allowedAaguids` MUST be sorted because the **set** is the policy: an unordered list would make two identical policies produce different signed bytes depending on the order the rule happened to enumerate them in, and the canonical serialization would no longer be a function of the policy alone.

Without `requirement` in the signed bytes, a receipt from a 3-of-3 hardware-pinned challenge is byte-for-byte identical to a 1-of-1 one. A Relying Party "verifying offline" would then still have to trust the issuer for the entire policy — the precise dependency offline verification exists to remove. Signing it also means each approver attests to the policy their signature is being counted toward.

**The signed requirement is the signers' own statement.** Signing makes the requirement tamper-evident to third parties; it does not make it binding on the signers. Whoever composes the payload chooses its `requirement`, so a single Approver — including one who is also the requester — can compose `requiredApprovals: 1, requesterCannotApprove: false` for an action the Relying Party's policy gates at 3-of-3 with four-eyes, sign it alone, and produce an envelope that satisfies §5 steps 1–7 against the signed value. A compromised Issuing Service can do the same by freezing a weaker requirement at issuance. Verifying the signed requirement proves that the quorum *the signers stated* was met, never that the Relying Party's own policy was. A Relying Party that holds that policy MUST compare the two (§5 step 3d).

**Offline checkability differs per field.** A Relying Party MUST NOT assume all five are equally enforceable from a Proof Envelope alone:

| Field | Offline verifiable? | Why |
|---|---|---|
| requiredApprovals | Fully | Count distinct approver identities among the valid witnesses (not signature entries — §4.4.2), which requires an identity-associating trust anchor (§4.4.6). |
| requesterCannotApprove | Fully, under an identity-associating anchor only | Compare each witness identity against `requester.did`. Under a key-set anchor (§4.4.6) the witness identity IS the key and `signerDid` is an unverified string, so the comparison has nothing to compare: the rule is not verifiable at all and the envelope MUST be rejected (§5 step 3b). |
| requireHardwareKey | Partially | An assertion proves a WebAuthn credential signed, not that the authenticator carries verified manufacturer attestation — that check is made once, at registration time, against the attestation object an assertion does not carry. It does carry the signed Backup Eligible / Backup State flags, and a witness with either set MUST NOT count (§4.4.5 rule 6); the flags clear is the authenticator's own claim, not attestation. |
| allowedAaguids | Not at all | The AAGUID appears in registration data, never in an assertion. What a verifier CAN refuse is what could never satisfy it: a non-empty allowlist is treated exactly like `requireHardwareKey` — a bare-key (ES256) witness MUST NOT count, and an offline proof MUST be rejected (§5a.3). |
| signerClass | Partially | For a WebAuthn witness, the UV flag (§4.4.5) is cryptographic evidence a user-verification ceremony — a human gesture — occurred at signing. A bare-key (ES256) witness carries no signer-class evidence at all: there the class rests on the issuing service's signing-time enforcement, or, for an offline proof (§5a), on the delegation ceremony that named the operators. What a verifier MUST enforce unconditionally is the registry rule: reject absent or unrecognized values. |

A Relying Party that requires enforcement of `requireHardwareKey` or `allowedAaguids` MUST obtain it from enrollment records, not from the envelope. Where no enrollment record is available — an offline proof above all — such a requirement MUST be treated as unsatisfied rather than as satisfied by default. A Relying Party MUST NOT reject an ES256 witness merely because `signerClass` is `"human"` — humans legitimately sign with bare keys (§5a); a deployment wanting cryptographic proof of the ceremony pins `requireHardwareKey`.

**The signed requirement is a projection, not the whole policy.** A deployment MAY enforce
additional approval-policy dimensions beyond the five signed fields — the reference gateway, for
example, also enforces a named eligible-approver list and requester-attestation constraints
(`approverDids`, `requireAttestedRequester`, `allowedIssuers`) when granting an approval. Such
fields are deliberately NOT part of the signed `requirement`: they are enforced online by the
issuing service at approval time and are therefore invisible to offline verification. A Relying
Party MUST NOT read the signed `requirement` as the complete policy in force — it is the
offline-checkable projection of it, chosen so that every signed field is one an approver's
signature can meaningfully attest to.

### 4.3.3 Denial Payload — the decision is signed

A signature over an Intent Payload (or over a §5a.5 Delegation or §5b Agent Authority payload)
attests to **approval of** that payload. Refusal is a different act and MUST be signed over
different bytes.

The **Denial Payload** for a payload `P` is derived from the exact canonical bytes of `P`:

1. Parse `P`. It MUST be a JSON object carrying a non-empty string `type`.
2. Set `type` to `<P.type> + "-denial"`.
3. Add `decision` with the value `"deny"`.
4. Re-serialize under JCS (§4.1).

Every other field is carried through verbatim, so the denial is bound to the same nonce, target,
parameters, requester, requirement and expiry as the approval it refuses. Deriving rather than
rebuilding is normative: it makes it structurally impossible for the two to disagree about *what*
is being decided.

An implementation MUST refuse to derive a denial from a payload whose `type` already ends in
`-denial`.

The derivation is defined for any DIV payload type, but this version requires denial support only
for the three service-issued ceremony kinds (`div-intent-verification`, `div-delegation`,
`div-agent-authority`), and only those are vectored (§7a). An offline refusal (§5a) produces no
signed artifact: the Approver simply declines to sign, and there is no issuing service whose record
needs non-repudiable refusal evidence — the Relying Party that constructed the challenge already
knows it was not approved. `div-offline-intent-denial` is therefore not defined by this version and
MUST NOT be emitted; verifiers refuse it by the ordinary unknown-type rule.

**Why this is a MUST.** An issuing service that verifies both decisions against the approval bytes,
and takes the decision from an unauthenticated request field instead, makes one signature valid
evidence of two contradictory acts. An approval signature is then replayable as a refusal: the
resulting witness carries the approver's real signature, public key and payload, verifies offline,
and attests to a denial that human never made. The reference implementation had exactly this defect.
Note that replay counters do not mitigate it — a synced platform authenticator reports a counter of
`0` indefinitely (§4.4.5), so the same assertion remains presentable for as long as the challenge is
open.

Consequently:

- An issuing service MUST select the bytes to verify from the decision being claimed, and MUST
  record those same bytes as the witness payload for that decision.
- A client generating a WebAuthn challenge MUST bind the bytes for the decision the user is being
  asked to make, at the moment the ceremony is created — an assertion produced for an approval is
  not convertible into a refusal afterwards.

Denial witnesses are ledger entries, not Proof Envelopes: they are verified by recomputing the
committed leaf (DEWP §4.1–§4.2), not by rebuilding a canonical payload, so a verifier implementing
only the Core Profile needs no Denial Payload support. Conformance vectors for the transform are pinned
in §7a alongside the approval payloads.

### 4.3.4 Evidence — reserved

`evidence` is part of the canonical Intent Payload and is therefore covered by every witness
signature. In this version of the specification its value **MUST** be the literal `null`.

`null` is signed and load-bearing, exactly as `requester.attestation`'s `null` is (§4.3.1): it is the
payload's explicit statement that **no external-evidence condition is represented by this
authorization**. It is not padding and it is not a default.

Normative rules:

1. The `evidence` key **MUST** be present in every Intent Payload and Offline Intent Payload. A
   payload in which the key is absent **MUST** be rejected.
2. An absent key, a JSON `undefined`, an empty array `[]` and an empty object `{}` **MUST NOT** be
   treated as equivalent to `null`. An implementation that normalizes any of them into `null` — on
   either the producing or the verifying side — is non-conformant, because it converts a
   shape it does not understand into an assertion that no condition applied.
3. Non-`null` values are **reserved** for a later version of this specification. An implementation
   **MUST** reject a payload whose `evidence` is not `null`, and **MUST NOT** treat it as
   unconditioned. This is the same fail-closed-on-unknown rule as the `signerClass` registry
   (§4.3.2, §5-step-3a), and for the same reason: an evidence-conditioned authorization that
   verified as though it were unconditioned would be the one failure this reservation exists to
   prevent.
4. An implementation **MUST NOT** encode external-evidence commitments in `params` as a substitute
   for this field. `params` is a security-binding, runtime-owned field (Invariant 2) that a Relying
   Party reconstructs from the operation it is about to perform, that an Approver interface is
   expected to render in full (§7), and that participates in the Delegation agreement rule of
   §5a.6. An evidence commitment satisfies none of those three properties.

**Where evidence sits relative to the payload's other fields.** The four are deliberately distinct
and a conformant implementation MUST NOT conflate them:

| Field | Describes |
|---|---|
| `params` | What will execute. Runtime-owned; reconstructed by the Relying Party. |
| `requirement` | Who may approve and how that approval must be produced (§4.3.2). |
| `requester.attestation` | The provenance of the requesting principal (§4.3.1). |
| `evidence` | External facts upon which the authorization may be conditioned. |

**Payload families that do not carry `evidence`, and why.** A Delegation (§5a.5) is sealed before the
action it authorizes occurs, so it cannot commit to a fact established at approval time; conditioning
a delegated action is a statement about *required* evidence, not a commitment to particular evidence,
and is left to a later version. An Agent Authority (§5b) declares scope for requests, and a request
within scope still takes the ordinary approval path, where the Intent Payload carries any
conditioning. A Platform Hash-Only Intent (§5c) is issued by a party that never receives the payload
and so has verified nothing it could commit to.

---

### 4.3.5 Key Ordering

Because serialization is JCS, keys in the signed bytes are sorted by UTF-16 code unit (RFC 8785 §3.2.3) at every level (e.g. within `requester`: `attestation` before `did`; within an attestation: `issuer`, `method`, `subject`; within `requirement`: `allowedAaguids`, `requesterCannotApprove`, `requireHardwareKey`, `requiredApprovals`, `signerClass`). The middle pair in that example depends on code-unit order (`H` precedes `d`); implementations MUST NOT use locale-aware or case-insensitive sorting or hand-order keys. The recursive sort is the contract.

---

### 4.3.6 Agent continuity and composition

The agent extension is part of the **same JCS object and the same WebAuthn challenge bytes** as
`target`, `params`, `requester`, `requirement` and `nonce`:

```json
{
  "action": { "reversibility": "irreversible", "amount": { "amount": "4200", "currency": "USD" } },
  "agent": { "label": "payments-agent", "configDigest": "sha256:<64 lowercase hex>", "delegatedBy": null },
  "session": { "id": "sha256:<64 lowercase hex>", "seq": "1", "prev": null,
    "aggregate": { "amount": "4200", "currency": "USD" } },
  "nbf": "2026-09-20T12:00:00.000Z",
  "exp": "2026-09-20T12:05:00.000Z"
}
```

The nested groups have separate meanings. `action` commits the operation's **effect** as well as
the existing exact `params`: `reversibility` is `reversible` or `irreversible`; the latter MUST go
through human signing, never policy auto-approval or discovery. `amount` is either `null` or a
nonnegative decimal string and ISO 4217-style three-letter currency. The PEP derives it from the
operation it will actually perform; requester-provided prose and numeric floats are not evidence
of the amount. `agent` commits a non-personal machine label, the RP's `configDigest`, and
`delegatedBy` (hash of the complete, signed leaf Agent Authority receipt, or `null`). The label
helps the human read the ceremony; the DID in `requester.did` remains the identity binding.
`session` commits a SHA-256 digest of an RP-owned, random opaque session ID (never a name or email), positive decimal-string sequence, predecessor receipt
hash (`null` only at sequence 1), and running aggregate. These fields are grouped because they
form one ordered, per-session statement; they do not add an independent authorization. `nbf`,
`exp` and the existing `nonce` limit that statement to one fresh request and at most five minutes.
Timestamps MUST be canonical UTC ISO strings. Monetary strings MUST use base-10 digits with at
most nine fractional places; a float, exponent, leading zero, or signed number is invalid.

`configDigest` is **an RP assertion, not a self-attestation and not proof of agent integrity**.
The reference computation is SHA-256 of UTF-8 bytes: ASCII `intyga-agent-config-v1`, one NUL byte
(`0x00`), then JCS of `{model:{provider,version},tools:[{id,version,schemaDigest}],systemPrompt}`.
Sort tools by `id` using UTF-16 code-unit order before JCS and refuse duplicate IDs. Return
`sha256:` plus lowercase hex. The RP's policy enforcement point (PEP) MUST recompute
it from the live runtime immediately before execution and refuse drift. The gateway cannot see
inside that runtime. The raw system prompt, raw tool schemas and personal data MUST NOT be placed
in these new receipt fields or audit metadata; use digests and opaque identifiers. The RP must
also minimize existing `params` and `display` according to its data policy.

The complete agent receipt digest uses SHA-256 of UTF-8 bytes: ASCII
`intyga-agent-receipt-v1`, one NUL byte (`0x00`), then JCS of
`{canonicalPayload,witnesses}`. `canonicalPayload` is the exact signed string. Each witness is
projected to exactly six fields: `signerDid`, `signerPublicKey`, `signature`, `sigAlg`,
`authenticatorData`, and `clientDataJSON`; absent optional fields become JSON `null`. Sort the
projected witnesses by their JCS strings in UTF-16 code-unit order before serializing the outer
object. A legacy single-witness receipt supplies its top-level witness as a one-element array;
the digest still commits to the complete signed proof. Return `sha256:` plus lowercase hex.
Both constructions have pinned `agentDigests` cases in `canonical-vectors.json`.

The PEP MUST reconstruct the intended target, action, parameters, reversibility, amount, agent
identity/configuration and session state from its own protected state, verify the receipt and
approver keys, and atomically reserve `nonce`, the per-session head/sequence and any global budget
before executing. The reference SDK returns the next receipt hash for such a compare-and-swap; it
cannot perform the RP's database transaction. Signing in INTYGA remains asynchronous. Agent drift
is checked locally at execution, never by calling the signing service to inspect a live model.

An offline verifier MUST receive the complete ordered session bundle and a trusted head obtained
**outside** that bundle. It verifies each signature, contiguous sequence and predecessor hash,
then recomputes each `session.aggregate` from the signed action amounts using integer decimal
arithmetic. A gap, branch, duplicate, mixed currency, false aggregate or wrong final head is a
verification failure. A verifier that has no implementation of the complete root-to-leaf authority
check MUST refuse a delegated agent receipt; validating its human signature alone does not
establish the subagent's scope. A single unanchored branch cannot prove that another branch was withheld;
the RP must maintain a durable authoritative head and an independently enforced budget across
sessions (ten individually approved payments may still exceed a global limit).

---

## 4.4 Proof Envelope Schema

A DIV Proof Envelope contains:

1. The canonical Intent Payload, **as a string** — the exact bytes that were signed.
2. One or more witness signatures over those bytes.
3. The metadata a Relying Party needs to resolve keys and recompute the payload.

The payload MUST be carried as the serialized canonical string, not as a nested object. A nested object would have to be re-serialized before verification, reintroducing exactly the serialization ambiguity §4.1 exists to eliminate.

### 4.4.1 Envelope Fields

| Field | Type | Requirement | Description |
|---|---|---|---|
| canonicalPayload | string | REQUIRED | The exact signed bytes (§4.1 canonical serialization of the Intent Payload). |
| signatures | array of Witness | CONDITIONAL | Every witness signature over `canonicalPayload`, one entry per approver (§4.4.2). REQUIRED for a quorum receipt; absent in the single-signature form (§4.4.3). |
| verificationCode | string | REQUIRED | Short human-readable code for out-of-band confirmation (§4.4.4). |
| target | string | OPTIONAL | Echo of the payload's target, for display only. |
| actionType | string | OPTIONAL | Echo, for display only. |
| actionDescription | string | REQUIRED | Echo of the payload's `display` field. |
| params | object | REQUIRED | Echo of the payload's params. |
| requester | object | OPTIONAL | Echo of the payload's requester, so a Relying Party can recompute the signed bytes. |
| signerDid, signerPublicKey, signature, sigAlg, authenticatorData, clientDataJSON | — | CONDITIONAL | Single-signature form (§4.4.3). |

Envelope fields fall into two classes under Invariant 2 (Local Payload Reconstruction), and the
distinction is what makes reconstruction meaningful:

- **Security-binding fields** — `target`, `actionType`, `params` — MUST come exclusively from the
  Relying Party's own runtime during reconstruction. Their envelope copies (and the `params` echo)
  are display/tooling conveniences a Relying Party MUST NOT feed into reconstruction: doing so
  verifies the envelope against itself and voids the binding.
- **Issuance-frozen fields** — `actionDescription` (the payload's `display`), `requester`, and the
  `requirement`, `evidence`, `nonce` and `expiresAt` carried inside `canonicalPayload` — are frozen by the
  Issuing Service before any witness signs, so the Relying Party has no runtime source for them. It
  takes them from the envelope as reconstruction *inputs*, which is safe rather than circular: the
  signature covers them, so a forged value changes the reconstructed bytes and fails verification.
  The `nonce` is additionally bound by the caller, who MUST assert which challenge is being redeemed
  and refuse a payload naming a different one. "Forged" here means altered by a third party: the
  signers author these fields, so the `requirement` is additionally bounded by the caller's own
  policy where it has one (§5 step 3d).

`evidence` has **no envelope echo, deliberately**. `target`, `actionType`, `params` and `requester`
are echoed because a Relying Party needs them for display or tooling; `evidence` needs neither. It is
issuance-frozen, so the verifier reads it from `canonicalPayload` — where a forged value fails the
byte comparison of §5-step-6 — and asserts the expected `null` during reconstruction. Adding an echo
would create a second, untrusted copy of a field whose only purpose is to be checked against the
signed bytes, which is the circularity §4.4.1 exists to prevent.

`actionDescription` is REQUIRED rather than OPTIONAL despite being an echo, and that requiredness is
behaviourally enforced: the reference verifier feeds it into `display` during reconstruction, so
omitting it changes the reconstructed bytes and fails the signature check. `params` is REQUIRED for
display and tooling interoperability, but reconstruction always uses the Relying Party's own runtime
parameters, as Invariant 2 demands; the presence of the envelope's `params` echo is therefore
enforced structurally by the schema only, and the echo is never trusted.

### 4.4.2 Witness Object

| Field | Type | Requirement | Description |
|---|---|---|---|
| signerDid | string | REQUIRED | Identifier of the approving principal. |
| signerPublicKey | string | REQUIRED | Base64 SPKI (ES256) or base64 COSE_Key (WEBAUTHN). |
| signature | string | REQUIRED | Base64 signature over `canonicalPayload` (for `WEBAUTHN` witnesses: unpadded base64url over `authenticatorData ‖ SHA-256(clientDataJSON)` — see the encoding note below). |
| sigAlg | string | REQUIRED | `ES256` or `WEBAUTHN`. |
| authenticatorData | string | CONDITIONAL | Base64url. REQUIRED when `sigAlg` is `WEBAUTHN`. |
| clientDataJSON | string | CONDITIONAL | Base64url. REQUIRED when `sigAlg` is `WEBAUTHN`; its `challenge` MUST equal `base64url(canonicalPayload)`. |

**WEBAUTHN witness field encodings.** The browser's assertion API yields `authenticatorData`,
`clientDataJSON` and `signature` as **unpadded base64url**, and that is the wire form producers emit
(the shared `webauthn-vector.json` pins it). Verifiers MUST accept unpadded base64url for these
three fields and SHOULD additionally accept standard base64, padded or not — the two alphabets
differ only in characters 62/63, so tolerant decoding is lossless and cannot make an invalid
encoding valid. A verifier that decodes only the standard alphabet refuses valid production
receipts while appearing to pass a standard-encoded test suite; this exact drift shipped in three
of the reference ports and was caught only by re-encoding the golden vector.

**ES256 signature encodings.** For an `ES256` witness the base64-decoded `signature` MAY be either
raw IEEE P1363 (`r ‖ s`, exactly 64 bytes for P-256) or ASN.1 DER, and verifiers MUST accept both.
The two are encodings of the same `(r, s)` pair, so tolerant decoding cannot widen what verifies —
the signature still has to verify under a trusted key. WebAuthn assertions carry DER-encoded ECDSA
signatures (that is what the WebAuthn API yields). The §7a receipt fixtures pin one accepted
receipt in each encoding.

Producers MUST emit `sigAlg`. For legacy compatibility, a verifier MUST treat an absent or null
witness `sigAlg` as `ES256`, and MUST fall back to ES256 verification for a value it does not
recognize; the signature must still verify under a trusted P-256 key, so the fallback can only fail
closed — it never widens acceptance. `AUTO_APPROVED` is not an unrecognized value: §4.4.3 defines
it, it carries no witness signature to verify, and it MUST NOT fall through to the ES256 path.
(Contrast §5-step-3a, where an unrecognized `signerClass` is rejected outright: `sigAlg` names how
one signature is checked and the fallback still demands a valid signature, while `signerClass`
names *what kind of authority* the whole receipt claims, which no fallback can safely assume.)

A quorum receipt MUST carry one entry per approver. Emitting only the first approval makes an M-of-N approval indistinguishable from a 1-of-1 one, so `requirement.requiredApprovals` could not be checked offline at all — the quorum would be unverifiable precisely where it matters most.

When counting toward `requirement.requiredApprovals`, a Relying Party MUST count **distinct approver identities**, not signature entries. Two signatures from one approver's two registered credentials are one approval.

### 4.4.3 Single-Signature Form

When `signatures` is absent, the flat `signerDid` / `signerPublicKey` / `signature` / `sigAlg` fields MUST be read as a one-element witness list. This form also carries the `AUTO_APPROVED` case, which has no witness at all: `sigAlg` is `AUTO_APPROVED` and there is no human signature. A Relying Party MUST refuse an `AUTO_APPROVED` envelope unless it has explicitly opted in for that specific call site.

Example (ES256, single signature; required echo fields shown):

```json
{
  "canonicalPayload": "{\"actionType\":\"db:dropTable\",\"display\":\"Delete production users table\",…}",
  "signerDid": "did:example:human:alice",
  "signerPublicKey": "base64-spki-p256",
  "signature": "base64-signature",
  "sigAlg": "ES256",
  "verificationCode": "AB12-CD34",
  "actionDescription": "Delete production users table",
  "params": { "environment": "production", "table": "users" }
}
```

### 4.4.4 Verification Code

`verificationCode` is a short code derived from the canonical payload, formatted `AB12-CD34`. It exists so an approver can confirm out of band that the challenge they are signing is the one the requester raised. It is a human-factors control, not a cryptographic one, and MUST NOT be treated as authentication.

The derivation is fixed so that both ends of the out-of-band channel compute the same code with no
coordination: take `SHA-256(canonicalPayload)` as lowercase hex, keep the first 8 characters,
uppercase them, and insert a hyphen after the fourth (`XXXX-XXXX`). Because the input is the exact
signed bytes, any change to the action, its parameters, or the signed requirement produces a
different code.

### 4.4.5 WebAuthn Envelopes

A Relying Party verifying a `WEBAUTHN` witness MUST:

1. Pin the expected `origin` and RP ID and reject any assertion that does not match. Without both pinned, an assertion harvested at any other Relying Party verifies.
2. Enforce the User-Present flag, and by default the User-Verified flag.
3. Verify the signature over `authenticatorData || SHA-256(clientDataJSON)`, not over the payload directly.
4. Confirm `clientDataJSON.challenge` equals `base64url(canonicalPayload)`.
5. Reject an assertion whose `clientDataJSON.crossOrigin` is `true`, or whose WebAuthn L3 `topOrigin` is present and differs from `origin`, unless the deployment explicitly opts in. The two are the same embedding reported two ways, and a verifier that checks only `crossOrigin` accepts assertions the issuing service refuses. Origin and RP-ID pinning see the frame's origin inside a cross-origin iframe, so they cannot by themselves detect a third-party embedder driving the ceremony. The hosted INTYGA service applies this rule at ingest, on every ceremony it runs or relays (console, hosted approvals and the platform plane, registration included), with no opt-in: it also refuses a WebAuthn L3 `topOrigin` that differs from `origin`. Every receipt it issues therefore passes a verifier's default for this rule, and a verifier that turns on `allowCrossOrigin` accepts nothing the service would have issued.
6. When the signed `requirement.requireHardwareKey` is `true`, not count a witness whose `authenticatorData` flags byte has Backup Eligible (bit 3, `0x08`) or Backup State (bit 4, `0x10`) set. A backup-eligible credential is by definition not device-bound, and both flags are covered by the assertion signature, so this catches an issuer that let a synced passkey sign a hardware-pinned action. The converse proves nothing: flags that are clear are the authenticator's claim, not attestation (§4.3.2). A non-empty `allowedAaguids` alone does not trigger this rule — an allowlist may legitimately name a synced-passkey provider.

The authenticator's signature counter is not a usable replay control here: a synced platform
authenticator (passkey) legitimately reports a counter of `0` on every assertion, so counter
monotonicity cannot distinguish a replay from a fresh ceremony. Replay protection comes from the
challenge binding (rule 4) plus nonce redemption (§6.1), never from the counter.

Example (WEBAUTHN, 2-of-N quorum; required echo fields shown):

```json
{
  "canonicalPayload": "{\"actionType\":\"db:dropTable\",…}",
  "signatures": [
    {
      "signerDid": "did:example:human:alice",
      "signerPublicKey": "base64-cose-key",
      "signature": "base64-assertion-signature",
      "sigAlg": "WEBAUTHN",
      "authenticatorData": "base64url-authenticator-data",
      "clientDataJSON": "base64url-client-data-json"
    },
    {
      "signerDid": "did:example:human:bob",
      "signerPublicKey": "base64-cose-key",
      "signature": "base64-assertion-signature",
      "sigAlg": "WEBAUTHN",
      "authenticatorData": "base64url-authenticator-data",
      "clientDataJSON": "base64url-client-data-json"
    }
  ],
  "verificationCode": "AB12-CD34",
  "actionDescription": "Delete production users table",
  "params": { "environment": "production", "table": "users" }
}
```

### 4.4.6 Trust Anchor Modes and Identity Association

A Relying Party resolves trusted Approver keys from a **trust anchor** it controls (§5 step 3). Three shapes are in common use, and they are not equivalent for quorum:

- **Identity-associating anchor (REQUIRED for `requiredApprovals` > 1).** The anchor maps an approver *identity* — a DID, or an equivalent stable subject identifier — to the set of public keys bound to it. This is what makes §4.4.2's rule expressible: several credentials belonging to one person collapse to one approval, exactly as an offline Trust Bundle requires (§5a.4).

- **Key-set anchor.** The anchor is a flat allowlist of trusted public keys with no identity attached. Because nothing binds a key to a person, **each trusted key is necessarily treated as its own identity**, and the envelope's `signerDid` cannot be relied upon to close the gap: in this mode it is an unverified string, and counting it would let one approver claim to be three. The consequence is unavoidable and MUST be understood by anyone configuring one: a deployment using a key-set anchor with `requiredApprovals` > 1 is counting **credentials, not people**, so one approver holding *M* listed keys satisfies an *M*-of-*N* quorum alone.
  For the same reason a verifier MUST reject a key-set anchor when the signed
  `requesterCannotApprove` rule is true (§5 step 3b): a receipt-controlled `signerDid` cannot
  establish separation of duties. Use an identity-associating anchor for that rule.

Therefore a deployment MUST NOT use a key-set anchor when `requiredApprovals` > 1, unless it also guarantees at most one listed key per approver — which is the same requirement stated differently, and is fragile in exactly the way credential rotation and multi-device enrollment make likely.

**One key, one approver.** An identity-associating anchor can itself map one key to two identities — an export error, or one person enrolled under two identifiers. Counting distinct identities alone would then let that key's holder satisfy a 2-of-N quorum alone. A verifier MUST count distinct identities AND distinct keys: once a key has been counted for one identity, a witness verifying under the same key for a different identity MUST NOT count. The reference verifiers compare keys by their decoded bytes; the same key in two different encodings (a COSE_Key and an SPKI) is not detected, so an anchor SHOULD NOT carry one key in two encodings.

- **Identity-committing anchor (self-certifying identifiers). Support is OPTIONAL.** The pinned identifier itself commits to a key — e.g. `did:intyga:key:<base64url(sha256(key bytes))>` — so the anchor entry needs no key material at all: the verifier accepts the envelope-carried key exactly when it hashes to the pinned identifier. This does not conflict with §5 step 3's prohibition on trusting envelope-carried keys, because the *commitment* is resolved from the Relying Party's own configuration; the envelope merely transports bytes that are checked against it. **Precedence:** an anchor that additionally maps keys to such an identity takes precedence over the commitment — the explicit mapping must be able to both extend the identity to later-enrolled credentials and *narrow* it away from a revoked one, neither of which a commitment-always-wins rule can express. A single-key commitment cannot rotate; identities expected to hold several credentials over time SHOULD use a stable identifier under an identity-associating anchor instead.

Delegations (§5a.5) name approver identities in `delegatedTo`, so they need an identity-associating anchor and MUST be refused under a key-set anchor.

*(Note for conformance testing: the golden vectors can only demonstrate the distinct-identity rule under an identity-associating anchor, since a key-set anchor has no identities to be distinct about. A vector suite passing under a key-set anchor is not evidence that §4.4.2 is satisfied.)*

---

# 5. Verification Procedure

The Relying Party MUST execute verification immediately before performing an Irreversible Action.

The verification procedure is:

1. Receive the Proof Envelope.
2. Validate Proof Envelope structure.
3. Resolve the trusted Approver public key(s) according to local policy. The key MUST come from the Relying Party's own key management; a key read from the envelope proves only that the envelope is internally consistent. (An identity-committing anchor — §4.4.6, OPTIONAL — satisfies this rule by pinning a key *commitment* in the Relying Party's own configuration: the envelope-carried key is accepted only when it matches that commitment.) When `requirement.requiredApprovals` is greater than 1, the trust anchor MUST associate keys with identities (§4.4.6) — a key-set anchor cannot express the distinct-identity rule of §4.4.2.
   - **3a.** Validate `requirement.signerClass` against the registry of §4.3.2, reading the `requirement` from the envelope's `canonicalPayload` (an issuance-frozen field — §4.4.1; a forged value fails the byte comparison in step 6): reject the envelope if the field is absent or carries a value this verifier does not recognize. An unrecognized class MUST NOT be treated as human-equivalent — future signer classes become acceptable only when a verifier is explicitly taught their semantics, never by default.
   - **3b.** If `requirement.requiredApprovals` is greater than 1, **or** `requirement.requesterCannotApprove` is true, the anchor MUST be identity-associating (§4.4.6); reject the envelope otherwise. For `requesterCannotApprove` the reason is that separation of duties is a statement about *identities*: under a key-set anchor each key is its own identity and the envelope's `signerDid` is attacker-controlled, so "this signer is not the requester" cannot be established. Reject at this step rather than at step 7 — the failure is that the Relying Party's anchor is the wrong shape for the signed policy, not that a quorum came up short, and reporting it as a shortfall sends an operator looking for missing approvals that were never the problem.
   - **3c.** Validate `evidence`, reading it from the envelope's `canonicalPayload` (an
     issuance-frozen field — §4.4.1; a forged value fails the byte comparison in step 6): reject the
     envelope if the key is absent, and reject it if the value is anything other than `null`. A
     non-`null` value MUST NOT be treated as unconditioned — evidence semantics become acceptable
     only when a verifier is explicitly taught them, never by default (§4.3.4). An implementation
     MUST distinguish an absent key from a present `null`; collapsing the two turns this step into a
     no-op.
   - **3d.** If the Relying Party holds a local approval policy for the action, it MUST compare the
     signed `requirement` (read from `canonicalPayload`, as in 3a) against it and reject any weaker
     value: a `requiredApprovals` below the policy's, `requesterCannotApprove` false where the policy
     sets it, or `requireHardwareKey` false where the policy sets it. An equal or stricter signed value
     passes, and steps 3b and 7 then enforce the *signed* value. The signed requirement alone bounds
     only what the signers stated (§4.3.2): without this step, one Approver can author and satisfy a
     quorum of one. Reject here, before any signature is counted — the failure is a policy
     downgrade, not a shortfall. A local policy the verifier cannot read (for example a quorum below
     1) MUST be rejected rather than treated as absent. `allowedAaguids` is outside this comparison;
     a deployment restricting authenticator models expresses that as `requireHardwareKey` here and
     enforces the model list from enrollment records (§4.3.2).
4. Construct the expected Intent Payload from local runtime execution parameters.
5. Serialize the expected payload using RFC8785 JCS.
6. Verify each witness signature against the canonical bytes.
7. Validate the approval requirement: count **distinct** approver identities with a valid signature. If `requirement.requesterCannotApprove` is true, a signature from `requester.did` MUST NOT be counted toward `requiredApprovals`; its presence does not by itself invalidate the envelope. (This step is reached only under an identity-associating anchor — step 3b rejects a key-set anchor outright when this rule is set, because there the comparison is not expressible.) Reject unless the remaining count is at least `requirement.requiredApprovals`. A `requiredApprovals` that is absent, non-integral or below 1 MUST have been rejected before this step (§4.3.2): "at least 0" is true with nothing counted, so an implementation that reaches here with a 0 accepts an envelope carrying no valid witness signature.
8. Validate Target binding.
9. Validate expiration.
10. Validate nonce freshness.
11. Record nonce redemption.
12. Permit execution.

If any step fails, execution MUST be denied.

Step 7 is what makes quorum meaningful offline. A Relying Party that verifies one signature and stops has verified an approval, not *the* approval the policy required. Step 3d is what makes it *the Relying Party's* quorum: step 7 counts against the signed value, and a verifier that skips 3d has proved only that the signers met the quorum they chose.

Steps 1–9 constitute the **stateless cryptographic check** and MAY be implemented by a self-contained offline verifier that holds no state. Steps 10–11 (nonce freshness and redemption) are inherently **stateful**: they require the Relying Party to persist which nonces it has already consumed. A conformant deployment MAY therefore satisfy steps 10–11 in a stateful gatekeeper (which atomically marks a challenge consumed) while running steps 1–9 as a defense-in-depth offline re-verification at the point of execution. Because the stateless verifier cannot itself record redemption, it MUST require the caller to name the nonce being redeemed, so that single-use enforcement remains the caller's explicit responsibility.

---

# 5a. Offline Approval

## 5a.1 Motivation

A DIV deployment is fail-closed (Invariant 4): when the approval service is unreachable, no proof can
be obtained and the Irreversible Action does not execute. That is correct, and it places the approval
service in the critical path of every governed action.

An operator therefore needs a mechanism that survives the outage. The naive answer — pre-signing
approvals for anticipated actions and holding them until needed — is **NOT RECOMMENDED** by this
specification. Such a proof is a bearer capability at rest: possessing the file is sufficient to act,
it cannot be revoked at an offline Relying Party, and the human signature attests to a judgment made
about a hypothetical rather than about the incident in progress. Narrowing the action and its
parameters does not repair this, because the defect is in *when* the human decided, not in *how much*
they authorized.

This section specifies the alternative. **Offline Approval moves the signing ceremony off the network
rather than earlier in time.** The Relying Party constructs the challenge locally at incident time,
Approvers review and sign it on a device with no connectivity, and the Relying Party verifies the
result with the same stateless procedure of §5. No capability exists at rest, the humans see the
actual incident, and the validity window is minutes rather than weeks.

Two mechanisms are defined. §5a.2–§5a.4 specify **Offline Approval**, which applies when the approval
service is unreachable but the Approvers are not. §5a.5–§5a.6 specify **Delegation**, a narrow
pre-signed artifact for the residual case where the Approvers themselves cannot be reached; a
Delegation authorizes no action by itself and transfers only the authority to approve.

## 5a.2 Offline Intent Payload

An Offline Intent Payload is identical to the Intent Payload of §4.2 except that:

| Field | Requirement | Description |
|---|---|---|
| `type` | REQUIRED | MUST equal `div-offline-intent`. |
| `challengedAt` | REQUIRED | RFC3339 UTC timestamp at which the Relying Party constructed the challenge. |

The `type` discriminator is inside the signed bytes. An Offline Intent Proof therefore **MUST NOT**
verify as an Intent Proof, and an Intent Proof **MUST NOT** verify as an Offline Intent Proof, even
for a byte-identical action. Implementations MUST provide the two canonicalizations as distinct
operations; a single operation parameterized by type is NOT RECOMMENDED, because it permits the
ordinary path to emit an offline payload by mistake.

The `nonce` MUST be generated by the Relying Party (§6.1), which is the party that will redeem it.
Because the approval service never sees the challenge, no other party can enforce its single use.

`challengedAt` exists so a verifier can bound the validity **window**, not merely the expiry. Without
it, a payload minted with an over-long `expiresAt` is indistinguishable at verification time from a
correctly minted one.

## 5a.3 Offline Verification

A Relying Party verifying an Offline Intent Proof MUST perform the §5 procedure, reconstructing the
payload with the offline canonicalization, and MUST additionally:

1. **Refuse by default.** An Offline Intent Proof MUST be rejected unless the caller has explicitly
   opted in at that call site. A process-wide or default-on opt-in is NOT RECOMMENDED. An Offline
   Intent Proof with no human signature (`sigAlg: AUTO_APPROVED`) MUST be rejected regardless of any
   auto-approval opt-in.
2. **Bound the window.** `expiresAt - challengedAt` has a fixed ceiling of **60 minutes**. A
   deployment MAY enforce a shorter window and MUST NOT accept a longer one; a proof whose window
   exceeds the deployment's cap MUST be rejected even when its signature is valid.
3. **Reject inverted and forward-dated windows.** `expiresAt` earlier than `challengedAt` MUST be
   rejected. A `challengedAt` later than the verification time plus the §6.2 clock-skew tolerance
   MUST also be rejected: capping the window's *width* without bounding its *position* leaves the
   window free to slide, so a proof dated years ahead with a compliant 60-minute window would verify
   today and keep verifying until that date — exactly the pre-signed bearer capability §5a.1
   rejects. This rejection is unconditional and is NOT waived by the audit override of §6.2, which
   exists to re-examine a proof that *was* valid and has since lapsed and says nothing about one
   dated in the future.
4. **Refuse a hardware-key requirement.** If the signed approval requirement sets
   `requireHardwareKey`, or carries a non-empty `allowedAaguids` authenticator-model allowlist, the
   proof MUST be rejected. See §5a.8; this constraint is normative because the requirement cannot be
   satisfied offline — an offline witness is a bare key, which has no authenticator model at all — and
   accepting the proof anyway would silently downgrade the policy the Approver attested to. A producer
   SHOULD refuse to create an offline challenge, or declare an offline runbook, under such a rule.
5. **Enforce every other invariant unchanged** — Target Isolation (§3 Invariant 5), parameter binding
   (§3 Invariant 1), local payload reconstruction (§3 Invariant 2), the signed approval requirement
   including `requesterCannotApprove` (§4.3.2), the §5-step-3d comparison against the Relying
   Party's policy — normally the Trust Bundle rule for the action (§5a.4) — and expiry (§6.2).

The approval requirement bound into an Offline Intent Payload MUST be obtained from an authority
outside the Relying Party — normally a Trust Bundle (§5a.4). A Relying Party that composes the
requirement itself is setting its own quorum, and the resulting proof attests to nothing beyond that
Relying Party's own configuration.

## 5a.4 Trust Bundle

Offline verification requires the Approver keys to be resolvable locally: Invariant 3 forbids taking
them from the proof under verification, and the directory that would ordinarily answer the lookup is
by definition unreachable. A **Trust Bundle** is the offline projection of the approval policy,
exported while connectivity exists and verified locally thereafter.

A Trust Bundle MUST carry, at minimum:

| Field | Requirement | Description |
|---|---|---|
| `type` | REQUIRED | MUST equal `div-trust-bundle-v1` for the first public exact action policy profile. The internal tenant policy migration number is separate. |
| `v` | REQUIRED | MUST equal `1` for this profile. Unknown versions MUST be refused. |
| `approvers` | REQUIRED | Approver identities and the public keys bound to each. |
| `policy` | REQUIRED | The tenant baseline and exact action-ID requirements, including eligible Approver identities. |
| `unmatchedActionPolicy` | REQUIRED | `DENY` or `BASELINE`, covered by the bundle signature. |
| `issuedAt` | REQUIRED | RFC3339 UTC timestamp of export. |
| `expiresAt` | REQUIRED | RFC3339 UTC timestamp after which the bundle MUST be refused. |

A Trust Bundle MUST be integrity-protected by a signature the Relying Party can verify without
network access, using key material pinned at export time. A Relying Party MUST refuse an expired
bundle, and MUST NOT fall back to an unverified or unbounded Approver set when no valid bundle is
available.

*Reference format (informative).* The reference implementation
(`packages/sdk/src/trust-bundle.ts`, exported with `intyga trust-bundle export`) carries the Trust
Bundle as a compact **JWS (RS256)** whose payload is the bundle JSON above, verified against the
issuing gateway's public key stored alongside it at export time — the pinned-at-export key material
this section requires. The exact policy profile carries complete quorum, hardware, four-eyes,
requester-attestation, allowlist, eligibility, escalation and automatic-window metadata. Group membership
is expanded at export; escalation signers remain separate from initial eligibility. The selected rule
MUST preserve every constraint of the `*` baseline or resolution MUST refuse the action. Unknown
actions use the baseline only when the signed `unmatchedActionPolicy` says `BASELINE`; unsupported offline controls MUST be refused. Signed `selectionRank`/`selectionKey` fields
are informational, not a substitute for validating the complete constraints. Legacy bundles MUST NOT
be used to create new approvals under this profile; ordinary historical receipt verification is unchanged.
See the implementation's rollout and compatibility guidance for disconnected consumers.
On top of the bundle's own `expiresAt` it enforces a **30-day maximum age**
from `issuedAt`, so an operator who sets a distant expiry still cannot keep a stale approver set in
service indefinitely. Other formats satisfying the normative requirements above are equally
conformant.

Because an Approver identity may be bound to more than one public key (for example a software key and
several registered authenticators), a conformant trust anchor MUST be able to associate multiple keys
with one identity, and quorum MUST count distinct **identities** rather than distinct keys. Counting
keys would let a single Approver holding several credentials satisfy an M-of-N quorum alone.

## 5a.5 Delegation of Approval Authority

Offline Approval requires the Approvers to be reachable out of band. Where that cannot be assumed, a
deployment MAY pre-authorize a **Delegation**: a proof, signed in advance by the ordinary quorum,
that transfers the authority to approve one pre-declared action to a named set of local operators.

A Delegation Payload is identical to the Intent Payload of §4.2 except that:

| Field | Requirement | Description |
|---|---|---|
| `type` | REQUIRED | MUST equal `div-delegation`. |
| `delegatedTo` | REQUIRED | The identities permitted to approve at incident time. MUST be a set, canonicalized in sorted order. |
| `delegatedQuorum` | REQUIRED | How many distinct members of `delegatedTo` MUST sign. MUST be ≥ 1 and ≤ the size of `delegatedTo`. |
| `sealedAt` | REQUIRED | RFC3339 UTC time the sealing ceremony was opened; frozen into the bytes every quorum member signs (as in §5b.2). |

**A Delegation authorizes no action.** It is not an approval and MUST NOT be accepted as one: an
implementation MUST reject a Delegation Payload presented to the approval verification procedure of
§5, and MUST expose Delegation verification as a distinct operation. There is deliberately no opt-in
flag that would permit the substitution, because a Delegation that could authorize its own action
would be exactly the pre-signed bearer capability §5a.1 rejects.

The `requirement` in a Delegation Payload describes the quorum that signed the **Delegation** and
MUST be at least as strict as the ordinary requirement for the delegated action. Delegating authority
is never the cheaper path.

## 5a.6 Delegation Verification

A Relying Party using a Delegation MUST:

1. **Verify the Delegation itself** against the Trust Bundle's ordinary Approver set, enforcing its
   signed `requirement` — including the §5-step-3a `signerClass` registry check — and its expiry.
   `expiresAt - sealedAt` has a fixed ceiling of **72 hours**: a deployment MAY enforce a shorter
   window and MUST NOT accept a longer one. A `sealedAt` later than the verification time plus the
   §6.2 clock-skew tolerance MUST be rejected, for the reason §5a.3 rule 3 gives — a ceiling on the
   window's width bounds nothing about where that window sits — and, as there, unconditionally. A
   Delegation with no human signature (`sigAlg: AUTO_APPROVED`) MUST be rejected regardless of any
   auto-approval opt-in.
   The ordinary Approver set and minimum sealing requirement are those of the action being executed,
   resolved from the Trust Bundle's policy, and the signed sealing `requirement` MUST be compared
   against that minimum under §5 step 3d. When the Offline Intent Proof is then verified under the
   Delegation, the same ordinary rule is the step-3d policy for it: `delegatedQuorum` is already at
   least as strict (§5a.5). A cached successful verification does not extend the
   Delegation's life: its expiry MUST be checked again at approval use time under §6.2. Trust Bundle
   freshness MUST also still hold after collecting incident signatures.
2. **Require agreement on the action.** The Delegation's `target`, `actionType` and `params` MUST
   equal those of the Offline Intent Proof being verified. A Delegation MUST NOT widen the action it
   was issued for.
3. **Substitute, not widen.** `delegatedTo` replaces the eligible Approver set and `delegatedQuorum`
   replaces `requiredApprovals` for that verification, and only for it. The Offline Intent Payload's
   signed `requiredApprovals` MUST equal `delegatedQuorum`, so the operators still sign the policy
   their signatures are counted toward.
4. **Resolve delegate keys from the Trust Bundle**, never from the Delegation or the Offline Intent
   Proof. A Delegation names identities; it does not carry key material.
5. **Enforce every constraint of §5a.3** on the Offline Intent Proof unchanged.

A Delegation therefore narrows two things and widens none: who may approve, and for which single
action.

## 5a.7 Reconciliation

An approval obtained offline is invisible to the approval service at the time it is granted. A
deployment MUST record every offline approval locally and MUST report it to the approval service when
connectivity returns, retaining the local record until the report is definitely acknowledged. An
unreported approval is indistinguishable from an unauthorized action.

A reported offline approval SHOULD be re-verified by the receiving service against its own record of
the action and its own Approver key material, rather than accepted on the reporter's assertion. The
Approver signatures make the report independently checkable; a report that cannot be checked
establishes little.

An offline approval MUST be surfaced to the caller under a status distinct from an ordinary approval.
The prevailing caller guard is a test for the ordinary approved status, so a distinct status ensures
that enabling offline approval in an existing service cannot silently begin permitting actions.

## 5a.8 Security Considerations

**No capability at rest.** The mechanism of §5a.2–§5a.4 leaves nothing on disk that authorizes an
action. This is its principal advantage over pre-signing and the reason the remaining considerations
are comparatively narrow.

**Hardware-backed authenticators.** A WebAuthn assertion cannot in general be produced offline: the
ceremony requires a secure context and binds to a Relying Party identifier that an offline signing
surface will not satisfy. Consequently `requireHardwareKey` cannot be honoured offline, and §5a.3
requires such a proof to be rejected rather than accepted under a weaker signature class. A
deployment that must retain offline capability for hardware-pinned actions has to provision an
attested offline authenticator, which is out of scope here. A non-empty `allowedAaguids` is the same
class of requirement: it is uncheckable offline for the reasons given in §4.3.2, and §5a.3 rejects it
exactly as it rejects `requireHardwareKey` — an allowlist that a key with no model could satisfy would
not be an allowlist.

**Out-of-band channel integrity.** The payload travels to the Approver, and the signature back,
across a channel this specification does not define. That channel need not be confidential — the
payload carries no secret and the signature is verified cryptographically — but the Approver MUST be
able to read the action they are authorizing in full, and SHOULD confirm the verification code
(§4.4.4) against the operator's display. An Approver who signs an opaque blob has not approved
anything.

**Local single use.** Nonce redemption is stateful and local (§5, steps 10–11). Because the Relying
Party generates its own nonce, single use within that Relying Party is enforceable exactly as in the
online case. Two Relying Parties cannot observe each other's redemptions, so a deployment sharing one
Approver set across several Relying Parties MUST scope nonces per Relying Party (§6.1).

**Delegation is a standing capability.** Everything §5a.1 says about pre-signing applies to a
Delegation, with one mitigation: it authorizes no action alone, so possessing the file is not
sufficient to act. The residual risk is collusion between a Delegation holder and `delegatedQuorum`
of the named operators. Deployments using Delegation SHOULD keep the window short, cap the number of
live Delegations, and monitor the ratio of delegated to ordinary approvals.

**Revocation.** Neither mechanism can be revoked at a Relying Party that is offline. For Offline
Approval the exposure is bounded by the window cap of §5a.3 and by the fact that a human decides at
incident time. For Delegation the window cap of §5a.6 is the only mitigation, which is why it is
short. Both caps bound the window's width *and*, through the forward-dating rule of §5a.3 rule 3,
its position — without that second half a cap bounds nothing durable, since an artifact minted today
for a window opening years from now would satisfy the width ceiling and still be a capability at
rest for its whole wait.

**Unforeseen incidents.** Offline Approval imposes no pre-declaration: any action the Relying Party
can describe can be approved offline, because the humans are in the loop when it happens. Delegation
does fix the action and its parameters in advance and is therefore limited to anticipated incidents.

**Relying Party compromise.** Out of scope, as in §7. Note that a Relying Party constructs its own
offline challenge, so a compromised one can choose the action it asks to have approved — but it
cannot obtain a signature over an action the Approvers decline, and it could equally have declined to
ask at all.

---

# 5b. Agent Authority

## 5b.1 Motivation

As agents take on delegated work, deployments need a governed, verifiable answer to "who authorized
this agent to operate in this scope" — an answer that survives offline verification with no issuer
secret, exactly as approvals do. An Agent Authority is that artifact: a statement of **standing
scope for one named agent**, sealed by a human quorum through the same signing ceremony as an
ordinary approval.

An Agent Authority is deliberately **declarative**: a target, a set of action patterns, a validity
window. It defines no evaluation semantics beyond substring matching and carries no expression
language. It is also **not a Delegation** (§5a.5): a Delegation pre-authorizes WHO MAY APPROVE at
incident time — hence its one-action, no-wildcard, ≤72-hour constraints — while an Authority
authorizes nothing at all. Execution always still requires an ordinary Intent Proof (§5). Loosening
Delegation to carry scope would have weakened the break-glass invariants; the distinct type keeps
both sets of constraints intact.

## 5b.2 Agent Authority Payload

The canonical payload has `type` `div-agent-authority` and serializes under the same JCS rules as
§4.1:

| Field | Type | Requirement | Description |
|---|---|---|---|
| v | uint8 | REQUIRED | DIV protocol version. MUST equal 1. |
| type | string | REQUIRED | MUST equal `div-agent-authority`. |
| target | string | REQUIRED | Target identifier the authority is scoped to (Target Isolation). |
| actionPatterns | array of string | REQUIRED, non-empty | Case-insensitive substring patterns over the machine action identifier (`actionType`). `"*"` matches all. MUST be sorted ascending by UTF-16 code unit — the SET is the scope. Deliberately NOT matched against the human-readable description: the description is authored by the agent being bounded, so matching it would let an out-of-scope request cover itself by quoting a pattern in its own text. |
| display | string | REQUIRED | Human-readable name of the authority, shown to the sealing quorum. |
| agent | object | REQUIRED | `{ "did": string }` — the agent the authority is ABOUT. Key-binding for the agent is introduced together with the `delegated-agent` signer class (§4.3.2), not here. |
| parentReceiptHash | string or null | REQUIRED | Domain-separated SHA-256 of the **complete signed parent authority receipt**, including all witnesses. `null` identifies a root grant. A child grant MUST name a live parent grant and fit inside its target, action scope and lifetime. |
| requester | object | REQUIRED | Who opened the sealing ceremony (§4.3.1). |
| requirement | object | REQUIRED | The sealing quorum's policy attestation (§4.3.2), including `signerClass`. |
| nonce | string | REQUIRED | The ceremony's single-use identifier. |
| sealedAt | string | REQUIRED | RFC3339 UTC time the ceremony was opened; frozen into the bytes. |
| expiresAt | string | REQUIRED | RFC3339 UTC end of validity. Renewal is a fresh ceremony. |

There is **no 72-hour window cap**: that cap exists because a Delegation pre-authorizes offline
approval and cannot be revoked at an offline Relying Party. An Authority is enforced — and revoked —
online by the issuing deployment; its window is deployment policy. A verifier MUST still reject a
payload whose `expiresAt` precedes its `sealedAt`, and one whose `sealedAt` is later than the
verification time plus the §6.2 clock-skew tolerance — an Authority sealed in the future was not
live at that time, and §5b.3's evidence claim is precisely about liveness then (§5a.3 rule 3).

The issuing deployment SHOULD floor the sealing quorum at the strictest approval rule covering any
action the patterns reach, so that sealing standing scope over an action is never cheaper than
approving that action once. This is a SHOULD on the issuing deployment, not a verifier check: the
artifact does not carry the deployment's approval rules, so a verifier cannot re-derive the floor.

## 5b.3 Agent Authority Verification

A verifier MUST expose Agent Authority verification as a function **separate from** Intent Proof
verification, and Intent Proof verification MUST reject a `div-agent-authority` payload outright.
The result of verifying an Authority is governance evidence — "these named humans granted this
agent this scope, and the grant was live at the evaluation time" — never an authorization to
execute.

For a delegated subagent, the verifier MUST receive the complete root-to-leaf authority receipt
chain and independently trusted approver keys for every link. Each child `parentReceiptHash`
MUST equal the digest of its verified parent receipt; the root MUST carry `null`. Targets MUST
match, the child's validity interval MUST fit inside the parent's, and every child substring
pattern MUST contain at least one parent pattern (or the parent has `"*"`). This is a conservative,
provable subset test: ambiguous patterns are refused. The leaf's agent DID MUST equal the executing
agent DID, the action type MUST match a leaf pattern, and the action intent's `agent.delegatedBy`
MUST equal the leaf receipt digest. A scope seal still never substitutes for an action approval.
An offline verifier cannot learn later revocations; the gateway's online path rejects a child if
any ancestor has been revoked or expired.

Verification proceeds as §5a.6 does for Delegations, with the §5-step-3a `signerClass` registry
check and the §5-step-3d comparison against the Relying Party's own sealing policy (how many humans,
with what separation of duties, must grant agent scope) applied to the sealing requirement. Without
that comparison a seal proves only the quorum its sealers stated. Validate the payload type and
version; validate
`actionPatterns`, `sealedAt`, `expiresAt`; reconstruct the canonical bytes from the verifier's OWN
`target` and `agent.did` (Local Payload Reconstruction — both come from the caller's policy, never
from the artifact); verify each witness signature against a trust anchor resolved from local
policy; count distinct approver identities against `requirement.requiredApprovals`; reject
`AUTO_APPROVED`. Expiry is checked against the evaluation time; an expired Authority MAY be
re-verified for audit with an explicit override (§6.2).

**Revocation is authoritative online only.** An offline verifier sees validity, not revocation
state. Treat a sealed Authority like a certificate, not a bearer token: the issuing deployment
records seals in its witness ledger (the sealing event commits the payload digest, the agent, and
the scope), revokes them there, and answers for liveness.

**Request-time enforcement (non-normative).** The issuing deployment MAY use live seals as a
request boundary. The reference gateway does, with a deliberately simple rule: **sealing is the
switch** — an agent with no live seal is unbounded (every request escalates to a human, unchanged),
and an agent with one or more live seals is confined to the union of its sealed scopes, with
out-of-scope requests refused before a challenge exists and the refusal witnessed. Coverage is
decided from the scope's `target` and the request's `actionType` alone — a bounded agent that
omits `actionType` matches nothing but `"*"`. A subagent's seal counts as scope only while every
ancestor seal is live; one whose ancestry was revoked or expired still bounds the agent but covers
nothing, so a parent's revocation never widens a child. An in-scope request is not thereby approved; it
takes the ordinary §5 path. This keeps the Authority's normative claim intact — it authorizes
nothing — while making "no agent acts outside human-granted scope" an enforceable, auditable
property.

---

# 5c. Platform Hash-Only Intent

## 5c.1 Motivation

An integrating platform — a service with its own end customers and its own UI — needs the
non-repudiation primitive without handing its payloads to the issuer. Its requests carry financial,
personal, or payroll data; transmitting them in plaintext would make the issuer a data processor
for the platform's entire customer base while adding no verification value, since the Relying Party
(the platform itself, or its auditor) already holds the payload.

The Platform Hash-Only Intent inverts §4.2's display model: the **platform canonicalizes its own
payload** (under the §4.1 rules), renders its approval UI from that one serialization, and submits
only the payload's digest. The issuer binds a WebAuthn ceremony to the digest, verifies the
assertion against the subject's enrolled credential and the platform's **own registered Relying
Party** (rpId/origins), and witnesses the result. The signed bytes never contain the payload.

**What shifts, stated plainly.** In §4.2 the `display` string inside the signed bytes is the
What-You-See-Is-What-You-Sign anchor, and the issuer's approval surface renders it. Here the
platform's UI is the display authority: the issuer attests that *this enrolled key signed this
digest at this time on this RP*, and cannot attest what the person was shown. A platform that
renders one thing and hashes another defeats WYSIWYS for its own users — which is why an
integration MUST derive displayed, signed and executed bytes from the single canonical
serialization, and MUST NOT rebuild the payload between approval and execution. This is an
integration requirement on the platform, verifiable by the platform's auditor against its own
codebase, not a property the receipt can carry.

## 5c.2 Platform Intent Payload

The canonical payload has `type` `div-platform-intent` and serializes under the same JCS rules as
§4.1:

| Field | Type | Requirement | Description |
|---|---|---|---|
| v | uint8 | REQUIRED | DIV protocol version. MUST equal 1. |
| type | string | REQUIRED | MUST equal `div-platform-intent`. |
| hashAlg | string | REQUIRED | MUST equal `SHA-256`. |
| payloadHash | string | REQUIRED | Lowercase hex SHA-256 (exactly 64 characters) of the platform's canonical payload bytes. Producers MUST refuse any other form — uppercase or mixed-case hex of the same digest would produce different signed bytes for the same payload. |
| rpId | string | REQUIRED | The WebAuthn RP ID the signing ceremony ran on — the PLATFORM's registered Relying Party, never the issuer's. Binding it into the signed bytes ties the receipt to the surface that performed the ceremony. |
| subject | object | REQUIRED | `{ "externalId": string }` — the platform's opaque, tenant-scoped subject identifier. Never a global identity claim: binding this key to a legal person is the platform's claim, carried as enrollment metadata, not asserted here. |
| signedAt | string | REQUIRED | RFC3339 UTC time the issuer froze the challenge. Informative binding — the tamper-evident time authority is the issuer's witness ledger, where challenge creation and receipt issuance are committed and anchored. |
| expiresAt | string | REQUIRED | RFC3339 UTC end of the challenge's validity. |
| nonce | string | REQUIRED | The challenge's single-use identifier (§6.1). |

The WebAuthn assertion challenge is the canonical payload's bytes in base64url, exactly as §4.4.5
defines for other payload kinds.

## 5c.3 Verification

A verifier MUST expose Platform Intent verification as a function **separate from** Intent Proof
verification (`verifyPlatformReceipt` in the reference implementation), and Intent Proof
verification MUST reject a `div-platform-intent` payload outright — the two attest different
things, and neither may ever be mistaken for the other.

The Relying Party supplies, from its own state and never from the receipt: the `payloadHash` it
recomputes from its own copy of the canonical payload, its `rpId`, the ceremony `nonce` it is
redeeming, its WebAuthn `origin` expectation, and the subject's trusted keys (§4.4.6 trust-anchor
modes; the self-certifying DID mode applies unchanged). Verification reconstructs the canonical
bytes from those values plus the receipt's `signedAt`/`expiresAt`/`subject`, byte-compares against
the signed payload, then verifies each WebAuthn witness under §4.4.5 with the PLATFORM's
origin/rpId as the expected values. Every witness MUST be a WebAuthn assertion (`sigAlg`
`WEBAUTHN`) with user verification asserted — unconditionally: a verifier option that waives the
User-Verified flag for ordinary receipts (§4.4.5 rule 2) MUST NOT apply here; `AUTO_APPROVED` MUST be rejected with no override —
this plane has no policy pre-approval. At least one distinct verified witness is REQUIRED. Expiry
follows §6.2, fail closed.

**Credential revocation is evaluated at signing time.** The issuer refuses a revoked credential in
every ceremony from the moment of revocation, and witnesses both the revocation
(`CREDENTIAL_REVOKED`) and each refusal. Receipts signed before revocation remain valid; an offline
verifier sees validity, not revocation state (the same bound as §5b.3's revocation note).

## 5c.4 Security Considerations

The origin binding is the trust boundary **for a browser-mediated ceremony**. A standards-compliant
browser is what refuses to let a page assert an origin other than its own when it constructs
`clientDataJSON`, so an assertion produced *through a browser* on one of the platform's registered
origins is the only kind whose `clientDataJSON.origin` can be trusted, and §4.4.5 verification
rejects anything else the browser could have produced. This binding is a property of the browser as
client, not of the authenticator or of WebAuthn as a wire format: a native CTAP2 client that talks to
a security key directly (bypassing a browser — e.g. a custom app built on `libfido2` or an
equivalent) constructs its own `clientDataJSON` and can put any origin string in it; the key itself
does not know or enforce origin, so it signs whatever it is asked to. No offline verifier can
distinguish that from a genuine browser assertion after the fact — the guarantee holds only for the
class of client that cannot lie about where the interaction happened, and general-purpose end-user
devices are not restricted to that class. Enrollment MUST therefore verify the attestation against
the registered RP configuration, and registration of that configuration is a privileged, witnessed
act; neither closes this residual.

Because credentials are scoped to the platform's RP ID, one person enrolled by two platforms holds
two unrelated keypairs and two subject identities; nothing in this profile links them — deliberate
data minimization, and the §1.2 non-goal (DIV is not an identity system) applies with extra force.

**Implementation status.** TypeScript, Go, Rust, Python and Java implement `div-platform-intent`
through dedicated platform-receipt verifiers. Their ordinary approval verifiers continue to refuse
this type: a platform signature is never an ordinary action approval. Shared verifier parity
fixtures pin successful verification and digest/RP/origin/subject/nonce refusals.

---

# 6. Replay Protection and Expiration

## 6.1 Nonce Requirements

The nonce MUST be unique within the replay-protection scope of the Relying Party.

The Relying Party SHOULD generate the nonce whenever approval requests originate from untrusted requesters.

A redeemed nonce MUST remain unavailable for reuse until the associated proof expiration time has elapsed. Recording and enforcing redemption is a stateful Relying Party responsibility (see the note on §5 steps 10–11) and is distinct from the stateless cryptographic verification of the Proof Envelope.

## 6.2 Expiration Validation

The Relying Party MUST reject proofs where the current time exceeds expiresAt.

**Timestamp syntax.** Every signed timestamp (`expiresAt`, `challengedAt`, `sealedAt`, `signedAt`)
MUST be an RFC 3339 §5.6 `date-time`, and a verifier MUST refuse any other spelling rather than
guess at it: exactly `YYYY-MM-DDTHH:MM:SS`, an optional fraction of one to nine digits introduced by
`.`, and a zone of `Z` or `±HH:MM`; `T` and `Z` uppercase; the date MUST exist (30 February and a
non-leap 29 February are refused); hours `00`–`23`, minutes and seconds `00`–`59` (no leap second);
offset hours `00`–`23` and offset minutes `00`–`59`. A numeric offset denotes the same instant as
its UTC equivalent. A bare date, a zone-less time — which a lenient parser reads in the verifier
host's own time zone, so the verdict moved with the machine — a space or lowercase separator, a
comma fraction and an expanded year are all refused. The reference producer emits
`YYYY-MM-DDTHH:MM:SS.sssZ`, which every conformant verifier accepts.

Implementations SHOULD support configurable clock-skew tolerance.

A default tolerance of ±30 seconds is RECOMMENDED.

A verifier MAY support re-verifying an expired proof for post-hoc audit or forensics, behind an
explicit per-call override (`allowExpired` in the reference implementation, available on intent,
delegation, and agent-authority verification alike). The result of such a re-verification is
evidence for the record — "this was validly signed while it was live" — never authorization to
execute: Invariant 4's fail-closed rule binds execution regardless of the override.

---

# 7. Security Considerations

DIV provides protection against:

* Modification of approved execution parameters.
* Replay of approvals against unintended targets.
* Unauthorized execution using valid standing credentials.
* Transport-layer alteration of intent artifacts.

DIV does not provide protection against:

* Compromise of the Approver private signing key.
* Malicious approval by a trusted Approver.
* A weaker `requirement` authored by the signers themselves, unless the Relying Party supplies its own
  approval policy (§5 step 3d). Without that policy a verifier proves only the quorum the signers
  stated.
* Compromise of the Relying Party execution environment.
* Incorrect interpretation of valid parameters by the executing application.

The Approver interface SHOULD display the exact execution parameters or an equivalent deterministic rendering before signature generation to reduce blind-signing risk.

---

# 7a. Reference Test Vectors

Compliant implementations MUST pass the official cross-language golden vectors, published in this
repository as `packages/mcp-schemas/vectors/canonical-vectors.json` (the companion DEWP set is
`ledger-vectors.json`; see DEWP §10). `verifier-parity-vectors.json` in the same directory is also
part of the conformance set: it pins executable **verdicts** rather than bytes — each case fixes the
`ok` result and, where present, the signers and a required fragment of the refusal reason, so a
refusal that lands for the wrong rule fails visibly instead of reading as green. The shared `webauthn-vector.json` in the same directory is
part of the conformance set: it pins the §4.4.5 WEBAUTHN witness path — the unpadded-base64url wire
encodings of §4.4.2, origin/RP-ID pinning, and the `clientDataJSON.challenge` binding — for every
port that verifies WebAuthn witnesses. **These files are the normative source**, so a port that
drifts from them fails visibly rather than at a relying party's site. `canonical-vectors.json` is
consumed by the TypeScript canonical implementation and verifier and by the Go, Rust, Python and
Java ports. `webauthn-vector.json` is *produced* by the TypeScript implementation and consumed by
the Go, Rust, Java and Python ports; the reference TypeScript verifier implements §4.4.5 but pins it
with its own fixtures rather than this file — which is how the §4.4.2 encoding it defines came to be
tightened in TypeScript and ship unmirrored in three ports. A TypeScript consumer for the shared
WebAuthn vector is a known gap, not an exemption.

The vectors pin, among other things:

* Canonical serialization (`stableStringify`) including the cross-language number-portability
  rules, UTF-16 key ordering with astral-plane keys, and HTML-sensitive characters.
* The canonical bytes of all five payload kinds — `div-intent-verification`,
  `div-offline-intent` (§5a.2), `div-delegation` (§5a.5), `div-agent-authority` (§5b.2) and
  `div-platform-intent` (§5c.2) —
  including that no kind can verify as another and that `allowedAaguids`, `delegatedTo` and
  `actionPatterns` are canonicalized as sorted sets. Every pinned `requirement` block carries
  `signerClass` (§4.3.2). All five builders are pinned in every port. Dedicated verifiers check §5b and §5c artifacts;
  the ordinary approval verifier still refuses them, as pinned by the receipt fixtures
  `agent-authority-refused-by-approval-verifier` and `platform-intent-refused-by-approval-verifier`.
* **Denial payloads** (§4.3.3) for each of the three ceremony kinds, pinning both the derivation and
  the property the derivation exists for: the denial bytes never equal the approval bytes they
  negate, so a signature over one cannot be presented as the other. Consumed by the TypeScript
  implementation only — denial witnesses are ledger entries verified by DEWP leaf recomputation, not
  Proof Envelopes, so a Core Profile verifier has nothing to check here.
* Quorum fixtures are evaluated under an **identity-associating** anchor (§4.4.6); a key-set anchor
  has no identities to be distinct about, so passing them in that mode is not evidence that §4.4.2 is
  satisfied.
* Signed **receipt** fixtures a verifier must accept or refuse as committed: single-signature
  (raw-P1363 and DER ECDSA encodings), tampered parameters, `AUTO_APPROVED` refusal, and a missing
  requester block. Nine refusal fixtures carry a VALID signature over their own bytes so the rule
  under test is the only gate: a Delegation presented to the approval verifier (§5a.5), an Agent
  Authority presented to the approval verifier (§5b.3), a Platform Hash-Only Intent presented to the
  approval verifier (§5c.3 — pinned in every port, like the §5b case), an
  intent whose signed `requirement.signerClass` is the unknown `delegated-agent` value
  (§5-step-3a's registry rule — refused, never treated as human), and five pinning the reserved
  `evidence` field of §4.3.4 (§5-step-3c).
* **Evidence fixtures** (§4.3.4, §5-step-3c). `evidence-null-verifies` is the positive control;
  `evidence-missing-refused` strips the key and re-signs, so the refusal is the presence rule and not
  a broken signature; `evidence-empty-array-refused`, `evidence-empty-object-refused` and
  `evidence-arbitrary-value-refused` pin that `[]`, `{}` and a populated value are each refused
  rather than normalized to `null`. `evidence-mutated-after-signing-refused` is the exception that
  does NOT re-sign: it pins that the check runs before Local Payload Reconstruction, so the refusal
  names the unsupported payload shape instead of reporting a parameter mismatch. The same six cases
  appear in `verifier-parity-vectors.json` under `approvals`, where each additionally pins a fragment
  of the refusal reason.
* **Quorum receipts** pinning §4.4.2/§5-step-7: distinct approver **identities** are counted,
  never signature entries (one approver's two registered credentials are one approval), and
  `requesterCannotApprove` excludes the requester's own signature.
* **Offline and delegation receipts** pinning the §5a.3 refuse-by-default opt-in, the 60-minute
  offline window cap, and the 72-hour delegation window cap — each including a validly signed
  proof whose signed window exceeds the cap and MUST be rejected anyway. Every case in these two
  sections carries an explicit `asOf` (RFC3339 UTC) that the consumer MUST pass to its verifier as
  the evaluation time. The fixtures are dated far in the future so they never expire, which makes
  them forward-dated relative to a real clock; `asOf` sits between each case's
  `challengedAt`/`sealedAt` and its `expiresAt`, so one file can pin both the width caps and the
  §5a.3 rule 3 position rule. Each section also carries a case whose bytes are those of its
  accepted sibling, evaluated at an `asOf` BEFORE the signed `challengedAt`/`sealedAt` — validly
  signed, inside every width cap, and MUST be rejected as forward-dated.
* A **`requiredApprovals: 0`** intent receipt carrying a valid signature, which MUST be rejected on
  the §4.3.2 minimum rather than passing §5-step-7 vacuously.
* **Requirement-floor verdicts** (§5 step 3d), in `verifier-parity-vectors.json`. They reuse already
  signed receipts, because the policy is a verifier input and never signed bytes: the
  `requirement-floor-*` cases under `approvals` pin that a signed 1-of-1 requirement verifies with no
  floor (the signers' own quorum), is refused under a floor raising the quorum, requiring four-eyes
  or requiring a hardware key, and is accepted under an equal floor — with an equal hardware floor
  accepted for a device-bound WebAuthn witness. `authority-requirement-floor-*` under
  `agentAuthority` pin the same for a sealing requirement. Every refusal pins the reason fragment
  `weaker than the relying party's policy`.
* **Verifier input handling**, in the self-contained `verifierInputHardening` section of
  `verifier-parity-vectors.json` (own keys): each accepted and refused §6.2 timestamp spelling, an
  offline `challengedAt` without a zone, a `topOrigin` that differs from `origin` (§4.4.5 rule 5), a
  platform receipt without user verification under a caller waiver (§5c.3), two DIDs sharing one key
  (§4.4.6) and an agent authority whose signed pattern carries an unpaired-surrogate escape (§4.1).
  The file stays I-JSON: the escape lives inside the `canonicalPayload` text, never as a raw string.
* The `verificationCode` derivation of §4.4.4 and the payload digest.

The signing keys and ECDSA signatures inside the file are regenerated whenever the vectors are —
they are test fixtures, not trust anchors — but every committed signature remains verifiable
against the committed key in the same file. Trust Bundles (§5a.4) are not vectored; their
reference format is documented in that section.

---

# 8. IANA Considerations

This document requires no IANA actions.

---

# 9. References

## 9.1 Normative References

* RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels.
* RFC 8174 — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
* RFC 8785 — JSON Canonicalization Scheme (JCS).
* RFC 7493 — The I-JSON Message Format.
* RFC 3339 — Date and Time on the Internet: Timestamps.

## 9.2 Informative References

* WebAuthn.
* FIDO2.
* DID Core.
* SPIFFE/SPIRE.
* Model Context Protocol (MCP).
* draft-williams-intent-token — "The Intent Token: A Cryptographic Authorization Primitive for Autonomous Agents" (Individual Internet-Draft, non-normative). Addresses a related pre-execution authorization problem via a JWT-based token; DIV differs by remaining transport- and identity-agnostic and by requiring local payload reconstruction (§3, Invariant 2) rather than trusting an embedded claim set.
