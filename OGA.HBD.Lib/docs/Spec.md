# OGA.HBD: Host Bootstrap Document — Specification

**Project:** OGA.HBD
**Short description:** A signed identity document and supporting library used by hosts and a central authority to attest host identity and bootstrap host management.
**Author:** [Project owner]
**Status:** Draft
**Created:** 2026-05-10T09:05:32Z
**Last Updated:** 2026-05-11T06:15:07Z
**Related Documents:** None at this revision. Future related documents include the `groundcontrol` central authority spec and the host provisioning script spec, both of which will reference this document as a foundation.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Functional Requirements](#2-functional-requirements)
3. [Non-Functional Requirements](#3-non-functional-requirements)
4. [Constraints and Technology Decisions](#4-constraints-and-technology-decisions)
5. [Architectural Overview](#5-architectural-overview)
6. [Data Model](#6-data-model)
7. [Solution Structure](#7-solution-structure)
8. [Key Interfaces and Contracts](#8-key-interfaces-and-contracts)
9. [Protocols and Flows](#9-protocols-and-flows)
10. [API Surface](#10-api-surface)
11. [Infrastructure](#11-infrastructure)
12. [Key Decisions](#12-key-decisions)
13. [Open Items](#13-open-items)
14. [Revision Log](#14-revision-log)

---

## 1. Project Overview

### 1.1 Background

The project owner manages a fleet of hosts and virtual machines spanning multiple cloud providers (AWS, DigitalOcean) and an on-premises VMware vSphere cluster, organized into per-customer or per-purpose clusters. Some clusters belong to specific customers; others are reserved for the owner's own work or shared build tooling. Each cluster runs over an administrative mesh overlay network that connects back, via a VLAN-isolated jump VM in the local vSphere cluster, to the owner's local administrative infrastructure. Cloud cluster VMs do not expose SSH or RDP to the public internet; all administrative access is mediated by the per-cluster jump VM.

The owner's existing fleet management is centered on a single Ansible plus RunDeck VM that reaches into each cluster through this mesh-and-jump arrangement. This works for executing playbooks but provides no unified view of fleet state — service status, deployment history, container versions, certificate expiry, secrets distribution status, backup outcomes — and the central control plane has implicit access to every host in every cluster, which makes its blast radius coextensive with the fleet.

The owner has begun building a host-resident agent, the **Host Control Service (HCS)**, deployed to every host in every cluster. Today it serves secrets and configuration that are pushed to it by an Ansible job. Its planned extensions are observation and reporting, status collection, and eventually serving as the local deployment agent for everything on a host. To do any of this safely, the HCS needs to authenticate to a central authority (the **groundcontrol** service, planned but not yet built), and the central authority needs to know which host it is talking to. The Host Bootstrap Document (HBD) is the identity primitive that makes that authentication possible.

The HBD is conceptually similar to AWS's Instance Identity Document (IID), but cloud-agnostic, self-issued by an authority the owner controls, and bound by proof-of-possession to a key the host owns. A C# library (the subject of this spec) implements HBD creation, signing, and verification.

### 1.2 Purpose

The HBD library exists to provide a verifiable, portable, cloud-agnostic identity document for hosts in a managed fleet. The document carries enough metadata for a central authority to recognize a host's tenancy, environment, region, and cluster membership; carries proof-of-possession binding to a host-owned key; and is signed by an authority the fleet trusts. The library provides the primitives any component (issuer, host agent, central controller, diagnostic tool) needs to produce, validate, and read these documents without reimplementing JWS handling.

### 1.3 Scope

This spec covers the HBD document format, the C# library that implements it, and the contracts the document and library expose to callers. It covers the rules a verifier MUST follow, the modes in which verification can be performed, and the format and semantics of the proof-of-possession binding.

This spec does NOT cover the central authority that mints HBDs (groundcontrol), the host-resident agent that uses them (HCS), the provisioning script that bootstraps a host into the fleet, or the protocol by which an HBD is transported from issuer to host. Each of those is a downstream concern with its own future spec; each will reference this document as a foundation.

### 1.4 Problem Statement

The problem this project addresses is sufficiently described in §1.1 and §1.2. To restate it precisely: hosts in the owner's fleet currently have no portable, verifiable identity that a central authority can authenticate. They have provider-specific identifiers (AWS instance IDs, DigitalOcean droplet IDs, vSphere VM UUIDs), but no common shape, no signed assertion of cluster or tenant membership, and no proof that a given host owns a given key. The HBD is the document that fills this gap.

### 1.5 Goals

The library shall enable a host or any other consumer to read a Host Bootstrap Document and learn, with cryptographic confidence, what host the document is about and who issued it. The document shall be readable by anyone but trustable only when verified against a known signing key. When proof-of-possession binding is fully implemented, the document shall be usable only by the host that owns the binding key whose thumbprint it carries; a copy of the document on a different host shall fail verification.

The library shall be small, single-purpose, and implementation-language-friendly enough that future ports to other languages (Go or Rust, for hosts where a .NET runtime is undesirable) are tractable. The document format shall be expressible as a standard JWS, so that off-the-shelf JOSE tooling can decode and inspect HBDs even without this library.

The library shall present a clear separation between document semantics (the shape of an HBD, the rules of verification) and host platform concerns (where a binding key lives, how it is generated, how the HBD is stored on a host). Host platform concerns are the responsibility of consumers of the library, not the library itself.

### 1.6 User Requirements

In this spec, "user" refers to a programmatic consumer of the library — typically the groundcontrol service (issuer-side), the HCS or HCS bootstrap (verifier-side), or a diagnostic tool (parser-side). The library does not have human end-users.

**UR-01 — Mint a signed HBD.** An issuer-side caller shall be able to construct a Host Bootstrap Document from supplied claims, sign it with a supplied issuer key, and produce a JWS-encoded representation suitable for transmission or storage.

**UR-02 — Verify a signed HBD.** A verifier-side caller shall be able to take a JWS-encoded HBD, supply a key-retrieval mechanism and verification settings, and learn whether the document's signature is valid and whether its claims are trustworthy.

**UR-03 — Read an HBD's claims.** A caller shall be able to recover the host metadata claims from a verified HBD as strongly-typed values.

**UR-04 — Parse without verification.** A caller shall be able to decode an HBD without verifying its signature, for diagnostic and inspection purposes, and shall receive a result that clearly indicates the signature was not verified.

**UR-05 — Bind an HBD to a host's key.** An issuer-side caller shall be able to embed a binding-key thumbprint in an HBD such that a future verifier can confirm the host presenting the HBD owns the corresponding key.

**UR-06 — Verify binding-key possession.** A verifier-side caller running on a host shall be able to confirm that the host's locally-available binding key matches the thumbprint embedded in the HBD it is verifying.

**UR-07 — Manage issuer keys.** An issuer-side caller shall be able to generate a new issuer signing key, persist it as a PEM file, reload it on subsequent runs, and produce a JWKS suitable for distribution to verifiers.

**UR-08 — Identify issuers unambiguously.** An issuer's identity, as it appears in HBDs, shall be a structured URN that names the organization, the issuer's role, the tenant the issuer serves, the environment, and (optionally) the region, in a form parseable by automated systems.

### 1.7 Non-Goals

- **Storage of HBDs on disk.** Where an HBD lives on a host, what its filename is, what permissions protect it, and how it is rotated on disk are concerns of the consumer (the provisioning script and the HCS bootstrap), not of this library.
- **Transport of HBDs from issuer to host.** Whether HBDs travel over HTTPS, in a signed envelope, or by some other channel is out of scope. The HBD is self-protecting (signed) so transport requires only integrity-and-confidentiality, not document-format awareness.
- **Distribution of issuer public keys.** How verifiers obtain trusted issuer public keys is delegated to the caller via a key-retrieval callback. The library expresses no opinion on JWKS endpoints, public-key files, embedded trust roots, or any other distribution mechanism.
- **Revocation.** This library does not implement revocation lists, revocation endpoints, or revocation status caching. Short HBD lifetimes (controlled by the issuer's choice of `exp`) are the v1 mitigation for compromised HBDs.
- **The minting protocol.** How a host requests an HBD, how the issuer authenticates the host, how the host proves possession of its binding key at mint time — all out of scope. The HBD format depends on *some* such mechanism existing; the design and specification of that mechanism belongs to the future groundcontrol spec.
- **Renewal protocol.** The library produces and verifies HBDs but expresses no opinion on the renewal handshake. That belongs to the future groundcontrol spec.
- **Host platform key management.** Generation, storage, ACLs, and access of binding keys on a Linux or Windows host are out of scope. The library accepts a binding key as an SPKI/PEM file (via the supplied thumbprint provider) or via any other implementation of the thumbprint provider interface; how that file got there is the host platform's concern, specified in the future provisioning script spec.

### 1.8 Glossary

- **HBD** — Host Bootstrap Document. The signed identity document this library produces and verifies. Defined fully in §6.2.
- **HBK** — Host Binding Key. The keypair an HBD is bound to via the `cnf.pkthumb` claim. The host owns the private half; the public half's SPKI thumbprint appears in the HBD. Defined fully in §6.6.
- **groundcontrol** — The planned central authority and controller that issues HBDs and orchestrates host operations. Referenced by name in this spec as an external component but not specified here. The base URL of a host's assigned groundcontrol channel appears in the HBD's `gcBaseUrl` field.
- **HCS** — Host Control Service. The host-resident agent that uses HBDs to authenticate to groundcontrol. Referenced by name as an external component.
- **JWS / JWT / JWK / JWKS / JOSE** — Standard IETF terms (RFC 7515, 7519, 7517). Used throughout. See those RFCs for definitions.
- **SPKI** — SubjectPublicKeyInfo, the DER-encoded structure described by RFC 5280 §4.1.2.7 that wraps a public key with its algorithm identifier. Used in this spec as the canonical binary form from which thumbprints are computed.
- **SPKI thumbprint** — `base64url(SHA-256(spki_der_bytes))`. The identifier scheme used throughout this design for both issuer key identification (`kid`) and host-binding-key proof-of-possession (`cnf.pkthumb`). See KD-01 for why this scheme is used in preference to RFC 7638 JWK thumbprints.
- **Issuer URN** — The structured URN used as the value of an HBD's `iss` claim. Format and grammar defined in §6.7.
- **PoP** — Proof-of-Possession (RFC 7800). The property that a token's holder demonstrably controls a key associated with the token, defending against simple bearer-token theft.

### 1.9 Spec Conventions

This section is identical across all specs produced under this template. It is included verbatim so that any single spec is self-describing.

**Item identifiers.** Items in this spec are identified by a type prefix and a two-digit zero-padded sequence number:

- **UR-NN** — User Requirement
- **FR-NN** — Functional Requirement
- **NFR-NN** — Non-Functional Requirement
- **KD-NN** — Key Decision
- **OI-NN** — Open Item

Sequence numbers are assigned in the order items are *created*, not the order they appear in the document. Items may be moved within the document as the spec evolves; their sequence number does not change once assigned.

**Number stability.** Item numbers are stable across all revisions of the spec. A removed item is not deleted from its section — it remains in place with title `### XX-NN — (withdrawn)` and a brief note explaining the removal. New items always take `max(existing_number) + 1` for their type, where the maximum includes all withdrawn entries. Numbers are addresses; addresses are not recycled.

If a project's item count for a given type approaches 99, that is treated as a spec event warranting a major revision and a deliberately widened identifier scheme.

**Cross-references.** Sections are referenced by number (e.g., `§6.5`). Items are referenced by their full identifier (e.g., `FR-14`, `KD-03`).

**Document order is independent of item numbering.** A section may contain `FR-03, FR-15, FR-04, FR-22` in that order because requirements are grouped topically, not by creation order. The identifier is the address; the position is the organization.

**Open Item disposition flags.** Open Items carry one of three dispositions, indicated in the item's title:

- `⚠ NEEDS YOUR INPUT` — requires the project owner to make a decision. The author has no recommendation, or the decision is not theirs to make.
- `⚠ NEEDS YOUR REVIEW` — the author has a recommendation; the project owner reviews before commit.
- (no flag) — known gap, intentionally not addressed at this stage of the spec.

**The template is a superset.** This template lists all sections a spec may have. Any individual spec produced from this template is expected to use a subset of these sections. Sections that do not apply to a given project are not deleted — they remain in place with a brief design statement explaining *why* the section was considered and found inapplicable. A bare "not applicable" is insufficient; the explanation is itself a small piece of design reasoning that confirms the consideration happened.

**Tables are for tabular data.** Tables are reserved for information whose presentation genuinely benefits from a tabular rendering — DDL columns, enum values, header/value pairs, dimensional matrices. Requirements, decisions, and open items are prose. Numbered subsections that stand up like a document outline scale better as items grow rationale, get reframed, and accumulate cross-references.

**Requirement language.** Requirements use RFC 2119 vocabulary:
- **SHALL** / **MUST** — mandatory
- **SHOULD** — strong recommendation; deviations require justification
- **MAY** — optional

SHALL is the default and the strong preference for all requirement statements. A well-formed requirement does not hedge — if a behavior is conditional, the condition belongs inside the SHALL: "When X occurs, the system shall Y" rather than "The system should Y." SHOULD and MAY are available if a requirement genuinely cannot be expressed in conditional SHALL form, but the author should attempt the rewrite first.

**Timestamp consistency.** The `Last Updated` field in the title block must match the timestamp of the most recent entry in the Revision Log (§14). Any spec edit that warrants a `Last Updated` change shall also produce a corresponding Revision Log entry. The two values are kept in lockstep.

---

## 2. Functional Requirements

### 2.1 Document Construction

**FR-01 — Construct an HBD instance.** The library shall provide a model type representing an HBD that can be constructed in code, populated with claim values, and submitted to the signing function. Default-constructed instances shall have a coherent shape (docType set, version set, claim fields initialized to empty) such that a caller need only populate the substantive claims.

**FR-02 — Sign an HBD.** The library shall provide a signing function that takes a constructed HBD instance, an issuer private key, and an issuer key identifier, and returns a JWS-encoded compact serialization of the HBD. The signing function shall produce a header containing `alg`, `kid`, and `typ` and shall not modify the HBD's payload claims.

**FR-03 — Caller-managed temporal claims.** The signing function shall not set `iat` or `exp` claims on the HBD. The caller is responsible for populating these claims before submission. The signing function shall fail if `iat` or `exp` are zero or missing in the input.

(Note: the current implementation does not enforce non-zero iat/exp at sign time. See OI-08.)

### 2.2 Verification

**FR-04 — Verify an HBD signature.** The library shall provide an asynchronous verification function that takes a JWS-encoded HBD and a verification settings object, and returns a verification result indicating whether the signature is valid. The function shall not throw on malformed input; it shall return a result with `Ok = false` and a populated `FailureReason`. Asynchrony in the verifier reflects the upstream `Microsoft.IdentityModel` validation pipeline's async API and is documented in OI-15.

**FR-05 — Verification mode ladder.** Verification shall support four modes of strictness, each a strict superset of the previous: ParseOnly, VerifySignature, VerifySignatureAndCnfWarn, EnforceAll. Mode semantics are defined in §6.5.

**FR-06 — Issuer allowlist.** When the verification settings provide a non-empty list of allowed issuers, verification shall fail if the HBD's `iss` claim is not in the list. When the list is empty, the issuer check is skipped. (See KD-06 for the rationale and the deployment convention this implies.)

**FR-07 — Optional lifetime check.** The verifier shall validate the HBD's `iat` and `exp` claims against current time, with configurable clock skew tolerance, only when the settings opt in. Lifetime *presence* is mandatory in all modes (see FR-09); lifetime *enforcement* is mode-independent and opt-in.

**FR-08 — Key retrieval via callback.** Verification shall obtain the public key for signature verification by invoking a caller-supplied callback, passing the kid extracted from the JWS header. The callback returns the key or an error indication. The library shall not maintain a key store.

**FR-09 — Mandatory claim presence.** The verifier shall require the presence of `docType`, `version`, `iss`, `iat`, and `exp` in every HBD it processes, in all verification modes including ParseOnly. An HBD missing any of these claims shall fail verification.

**FR-10 — Document type check.** The verifier shall confirm the HBD's `docType` claim is exactly `"hbd"` (case-sensitive) and reject documents with any other docType.

**FR-11 — Version compatibility.** The verifier shall accept HBDs declaring `version` exactly 1 and reject all other versions. Forward compatibility with future versions is not silent; future versions require a library update.

**FR-12 — Algorithm pinning.** The verifier shall accept signatures only when `alg` in the JWS header is `ES256`. Any other algorithm value, including `none`, shall cause verification to fail.

**FR-13 — Token type check.** The verifier shall require the JWS header `typ` to be exactly `"JWT"` and reject documents with any other typ value.

### 2.3 Proof-of-Possession Binding

**FR-14 — Bind to host key.** The library shall support populating the HBD's `cnf` claim with a `pkthumb` value carrying the SPKI thumbprint of a Host Binding Key, in the form defined in §6.4.

**FR-15 — Compute SPKI thumbprint from PEM.** The library shall provide a utility function that takes a path to a PEM-encoded SPKI public key file and returns its base64url(SHA-256(SPKI)) thumbprint, suitable for use as a `cnf.pkthumb` value.

**FR-16 — Pluggable thumbprint provider.** The library shall define an interface, ILocalKeyThumbprintProvider, that returns the thumbprint of a host's binding key, and the verifier shall use this interface to obtain the local thumbprint for cnf checking. The library shall provide a default implementation that reads an SPKI/PEM file from a configured path.

**FR-17 — Cnf check (warn mode).** When verification mode is VerifySignatureAndCnfWarn, the verifier shall compute the local binding-key thumbprint, compare to the HBD's `cnf.pkthumb`, and return a result indicating whether the binding matched, but shall not fail verification on mismatch. The result shall expose `CnfChecked` and `CnfMatched` so the caller can observe the binding state.

**FR-18 — Cnf check (enforce mode).** When verification mode is EnforceAll, the verifier shall compute the local binding-key thumbprint, compare to the HBD's `cnf.pkthumb`, and fail verification on mismatch.

(Note: FR-17 and FR-18 are designed but not yet implemented. See OI-01.)

**FR-19 — Cnf required in non-bare modes.** When verification mode is VerifySignatureAndCnfWarn or EnforceAll, the verifier shall fail if the HBD lacks a populated `cnf.pkthumb` claim.

### 2.4 Issuer Key Lifecycle

**FR-20 — Generate issuer key.** The library shall provide a function that generates a new ES256 issuer keypair and returns the in-memory key, the kid (computed as the SPKI thumbprint of the public key), the public-key JWKS in JSON, and the public and private keys as PKCS#8 PEM strings.

**FR-21 — Persist and reload issuer key.** The library shall provide functions to save an issuer private key to a PEM file and to reload it from a PEM file, restoring an equivalent in-memory key suitable for signing. The reloaded key shall produce the same kid as the original.

**FR-22 — Export JWKS for distribution.** The library shall provide a function that takes an issuer keypair and produces a JWKS-formatted JSON document containing the public key and its kid, suitable for distribution to verifiers.

### 2.5 Reading Claims

**FR-23 — Recover HostInfo from a verified payload.** The library shall provide a function that takes a verified HBD's JsonDocument payload and produces a strongly-typed HostInfo_V1 instance, returning failure if any required field is missing. (See OI-09 for the consequences of this function's strictness regarding `gcBaseUrl`.)

---

## 3. Non-Functional Requirements

### 3.1 Performance

This is a small library performing standard JOSE operations on documents under a few kilobytes. Performance is dominated by ES256 signature verification (~100µs on commodity hardware) and is not a design constraint. No specific performance NFRs apply at v1.

### 3.2 Reliability and Availability

The library is a pure-function library; reliability is the consumer's concern and depends on the consumer's deployment shape. The library itself shall not introduce ambient state, file handles, or background work that could fail outside the scope of an explicit method invocation.

**NFR-01 — Stateless API.** The library's public functions shall not retain state between invocations. Issuer keys, verification settings, and key retrieval callbacks are all caller-managed.

**NFR-02 — No throwing on malformed input.** Public functions shall return error indications via their result types rather than throwing exceptions on malformed or invalid input. This includes malformed JWS, invalid signatures, missing claims, and unparseable PEM. Implementation bugs (out-of-memory, programmer errors) may still throw.

### 3.3 Security

Security is the central concern of this library. Several requirements here have corresponding Key Decisions in §12.

**NFR-03 — Pinned signing algorithm.** The library shall accept and produce only ES256 signatures. The `alg=none` attack and the various confusion attacks involving HMAC-with-public-key are eliminated by construction. (See KD-02.)

**NFR-04 — Constant-time thumbprint comparison.** The library shall compare cnf.pkthumb thumbprints using a constant-time comparison function, to defend against timing attacks on thumbprint matching.

**NFR-05 — Signed-claims-only.** The verifier shall draw HBD claims only from the verified payload of the JWS. Header claims (other than `alg`, `kid`, `typ`) shall not be treated as authoritative.

**NFR-06 — No silent permissiveness on cnf failure.** When the verifier is in a mode that requires a cnf check, any failure of that check (mismatch, unavailable local thumbprint, malformed cnf claim) shall be surfaced in the result rather than silently accepted. (See OI-02.)

**NFR-07 — Issuer trust is caller-managed.** The library shall not embed or hardcode trusted issuer public keys, JWKS endpoints, or trust roots. Trust establishment is the caller's responsibility.

### 3.4 Observability

The library does not emit logs, metrics, or traces. The result types it returns carry sufficient information (failure reasons, observed kid, observed iss, signature/cnf check states) for the caller to log appropriately.

**NFR-08 — Diagnostic-rich result types.** Verification results shall carry the observed kid, observed issuer, signature verification state, cnf check state, and a failure reason string (where applicable), so the caller can produce useful logs without re-parsing the input.

### 3.5 Accessibility

Not applicable: this is a programmatic library with no human-facing surface.

### 3.6 Regulatory and Compliance

Not applicable: this library is a building block in a personal-use fleet management system. No regulated data passes through it; no regulatory constraints apply at this revision. If the library is later used in a regulated context, this section is revisited.

---

## 4. Constraints and Technology Decisions

### 4.1 Tech Stack

The library is implemented in C# and targets the .NET runtime. It is currently distributed as a NuGet package targeting .NET 5, .NET 6, and .NET 7, with platform support for `linux-any` and `win-any`. Newer .NET targets (8, 9) are anticipated but not required at v1; the library's surface is small enough that retargeting is mechanical. (See KD-08.)

The library is built from a single Shared Project (`OGA.HBD.Lib_SP`) that holds the actual source, with thin per-target wrapper projects (`OGA.HBD.Lib_NET5`, etc.) that compile the shared sources against a specific framework. Tests follow the same pattern.

### 4.2 Library Dependencies

**Microsoft.IdentityModel.JsonWebTokens** — Role: JWS parsing, signature validation, token introspection. Rationale: the canonical .NET JOSE implementation, maintained by the Azure Active Directory identity team. Switching libraries is conceivable but would require rewriting the verifier; the alternative (jose-jwt for both sign and verify) was considered but rejected because Microsoft.IdentityModel.* offers a richer validation pipeline with TokenValidationParameters that maps cleanly onto the verification mode ladder.

**Microsoft.IdentityModel.Tokens** — Role: token validation parameters, security key abstractions, base64url helpers. Rationale: paired with Microsoft.IdentityModel.JsonWebTokens; same maintainer.

**jose-jwt** — Role: JWS encoding on the signing side (`JWT.Encode` with explicit header support). Rationale: more direct control over header construction than Microsoft.IdentityModel offers for issuance, allowing the library to produce JWS bytes whose pre-image exactly matches what was serialized. Used only in the signer; the verifier does not depend on it.

The library's external API surface does not leak any of these libraries' types, except for `SecurityKey` (from Microsoft.IdentityModel.Tokens), which is used as the return type of the key retrieval callback. A future revision may abstract this away if it constrains language ports.

### 4.3 Environment Constraints

This is a library, not a service. Environment constraints apply to consumers of the library, not to the library itself. The library shall function on any host where the supported .NET runtime is available and where standard cryptographic primitives (ECDSA P-256, SHA-256) are accessible via the platform's CryptoAPI.

The library makes no network calls, opens no listening sockets, and does not rely on any specific filesystem layout. Calls that read PEM files (`SpkiFileThumbprintProvider`, `LoadIssuer_fromPrivateKeyPEMPkcs8`) take their paths from the caller; those paths are conventions of the consumer, not constraints of the library.

### 4.4 Repository Structure

The existing repository structure is preserved. The Shared Project pattern is intentional: it lets per-framework wrapper projects build the same source against different .NET targets without source duplication.

```
OGA.HBD.Lib/
  OGA.HBD.Lib_SP/                  shared project: actual library source
    Model/                         POCO types: HBD, HostInfo, ConfirmationInfo, JWS_Header, BootstrapDocResult, JWK_ECDsa, PublicKeyCache, Enumerations
    Service/                       HBD_Signer, HBD_ContextVerifier, VerificationSettings
    Helpers/                       ES256_Issuer, SpkiFileThumbprintProvider, PEMConverter, JsonDocument_Helpers
    OGA.HBD.Lib_SP.shproj
    OGA.HBD.Lib_SP.projitems
  OGA.HBD.Lib_NET5/                wrapper csproj targeting net5.0
  OGA.HBD.Lib_NET6/                wrapper csproj targeting net6.0
  OGA.HBD.Lib_NET7/                wrapper csproj targeting net7.0
  OGA.HBD.Lib_Tests_SP/            shared test source
    HBDVerifier_Tests.cs
    ES256Issuer_Tests.cs
    ES256Issuer_LifeCycle_Tests.cs
    HBDSampleGeneration_Tests.cs
    PEMConverter_Tests.cs
    Helpers/                       Test_TestBase, TestTemplate_Assembly
  OGA.HBD.Lib_Tests_NET5/          per-target test wrappers
  OGA.HBD.Lib_Tests_NET6/
  OGA.HBD.Lib_Tests_NET7/
  OGA.HBD.Lib.sln
  OGA.HBD.Lib.nuspec
  README.md
  LICENSE
  docs/
    SPEC.md                        this document (proposed location)
```

The `docs/` directory does not currently exist in the repository. Adding it as the home for SPEC.md and any future design documents (architecture diagrams, key decisions outside this spec) is part of adopting this spec as the authoritative reference.

### 4.5 Non-Requirements (Explicit Exclusions)

- **No support for non-ES256 algorithms.** Algorithm agility is a security liability the library will not adopt. (See KD-02.)
- **No support for HBD versions other than 1.** When v2 is needed, the library will be revised to handle it explicitly. Mixed-version verification is a v2-onward concern. (See KD-09.)
- **No revocation mechanism.** v1 mitigates compromised HBDs through short lifetimes only. (See KD-10.)
- **No issuer key distribution.** Verifiers obtain trusted public keys via a caller-supplied callback; the library is silent on how that callback is implemented.
- **No JWKS endpoint client.** The library produces JWKS JSON (`ExportJwks`) but does not host or fetch one.
- **No HBD storage on disk.** Where HBDs live is the consumer's concern.
- **No TPM or HSM integration.** v1 binding keys are software keys (Linux SSH host key, Windows generated key). TPM-backed binding is anticipated as a future migration but is not v1. (See KD-04.)

---

## 5. Architectural Overview

### 5.1 Tiers and Components

The library has no tiers in the conventional sense — it is a single-process, in-process library consumed by other components. Within the library, there are a few clusters of types worth naming:

**Document model.** The POCO types that represent an HBD and its parts: `Host_BootstrapDoc`, `HostInfo_V1`, `ConfirmationInfo`, `JWS_Header`, `JWK_ECDsa`, and the `BootstrapDocResult` returned by verification. These types carry no behavior beyond data initialization and (in the case of `HostInfo_V1`) a static recovery method that reads from a `JsonDocument`.

**Issuer side.** `HBD_Signer` provides the encode-and-sign primitive. `ES256_Issuer` provides issuer-key lifecycle: generate, derive properties (kid, JWKS, public PEM, private PEM), reload from PEM, export JWKS.

**Verifier side.** `HBD_ContextVerifier` provides the verify-and-parse primitive. `VerificationSettings` carries the configuration for a verification call: mode, allowed issuers, key retrieval callback, optional thumbprint provider, lifetime validation flag, clock skew. `ILocalKeyThumbprintProvider` is the interface for cnf binding's local-side computation, with `SpkiFileThumbprintProvider` as the default implementation reading from a PEM file. `PublicKeyCache` is an optional in-memory cache helper for verifiers that want to pool known issuer public keys (not used by the verifier directly; offered to callers).

**Helpers.** `PEMConverter` handles PEM↔DER conversions for keys. `JsonDocument_Helpers` provides safe accessors for reading typed values from a `JsonDocument`.

The library has no startup path of its own; consumers construct settings, call functions, and consume results.

### 5.2 Data Flow

The library participates in two principal flows: HBD issuance and HBD verification. The flows are described in their full architectural context (involving groundcontrol, HCS, the bootstrap script) in §9.2; the in-library data flow is summarized here.

**Issuance.** A caller (typically groundcontrol) constructs a `Host_BootstrapDoc`, populates `iss`, `iat`, `exp`, the `hostInfo` block, and (in production) a `cnf` with the host's binding-key thumbprint. The caller submits the document to `HBD_Signer.CreateBootstrapJws`, supplying the issuer's private key and the kid. The signer serializes the payload as JSON, attaches a header (`alg=ES256`, `kid`, `typ=JWT`), signs the compact-serialization input bytes with ECDSA-SHA-256, and returns the JWS-encoded compact form as a string.

**Verification.** A caller (typically HCS, on a host) receives an HBD as a JWS string and a `VerificationSettings` instance. The verifier parses the JWS, extracts the header, performs document-type and version checks against the payload, validates required claim presence, and (if mode > ParseOnly) retrieves the signing key via the callback, validates the signature using `Microsoft.IdentityModel`'s validation pipeline (configured by translating the `VerificationSettings` into `TokenValidationParameters`), and (if mode includes cnf checking) computes the local binding-key thumbprint via `ILocalKeyThumbprintProvider` and compares to the HBD's `cnf.pkthumb`. The result returned to the caller carries the verified payload (as a `JsonDocument`), the observed kid and iss, and flags for signature and cnf check states.

---

## 6. Data Model

### 6.1 Entity Overview

The library handles one principal entity (the HBD) plus several supporting types. Everything is structured data; nothing is persisted by the library itself.

**Host Bootstrap Document (HBD).** A signed JWS whose payload contains a small structured set of claims about a host. Issued by an authority, consumed by hosts and other verifiers. Bound to a host-owned key via the `cnf.pkthumb` claim (when populated).

**Issuer key.** An ES256 keypair owned by an HBD-minting authority. The private half stays with the issuer; the public half is distributed to verifiers (typically as a JWKS).

**Host Binding Key (HBK).** An ES256 keypair owned by a host. The host owns the private half; the public half's SPKI thumbprint appears in the HBD's `cnf.pkthumb`. Detailed in §6.6.

### 6.2 Schema

An HBD is a JWS in compact serialization, of the form `<header>.<payload>.<signature>`, where each part is base64url-encoded.

**Header.**

| Claim | Type | Required | Value / Notes |
|------|------|----------|---------------|
| `alg` | string | Required | `"ES256"` (only accepted value) |
| `kid` | string | Required | SPKI thumbprint of the issuer's public key |
| `typ` | string | Required | `"JWT"` (only accepted value) |

**Payload (HBD claims).**

| Claim | Type | Required | Value / Notes |
|------|------|----------|---------------|
| `docType` | string | Required | Always `"hbd"` (case-sensitive) |
| `version` | int | Required | Currently `1` only |
| `iss` | string | Required | Issuer URN (see §6.7) |
| `iat` | int (Unix seconds) | Required | Issued-at time |
| `exp` | int (Unix seconds) | Required | Expiry time |
| `hostInfo` | object | Required | HostInfo_V1 block (see below) |
| `cnf` | object \| null | Conditionally required | RFC 7800 confirmation claim (see §6.4) |

**HostInfo_V1.**

| Field | Type | Required | Value / Notes |
|------|------|----------|---------------|
| `region` | string | Required, may be empty | Region of the host. Cloud region or a label like `"lee-house"` for on-prem. |
| `availZone` | string | Required, may be empty | AZ within the region; empty for non-cloud hosts |
| `instanceId` | string | Required | Stable identifier for this host within the fleet (UUID format suggested but not enforced; format is owner's convention) |
| `tenant` | string | Required | Canonical slug of the tenant the host belongs to |
| `imageName` | string | Required | Identifier of the image the host was provisioned from |
| `creationTime` | int (Unix seconds) | Required | When the host was created (distinct from HBD `iat`) |
| `clusterId` | string | Required | Identifier of the cluster the host participates in |
| `clusterName` | string | Required | Human-readable cluster name |
| `environment` | string | Required | Operator-defined. The convention in this fleet is one of `dev`, `test`, `stage`, `val`, `prod` (lowercase). The library does not validate this field; see KD-07 on the library's general posture toward opaque string claims. |
| `gcBaseUrl` | string | Required | Base URL of the host's assigned groundcontrol channel |

The `gcBaseUrl` field is required by the recovery function (`HostInfo_V1.RecoverHostInfo_fromPayload`); HBDs lacking it cannot be recovered into a HostInfo_V1 instance. This is consistent with the field's role: the HBD tells the host where its controller is, and an HBD without that information cannot fulfill its role. (See OI-09 for the implication that historic test fixtures predate this field.)

### 6.3 Identifiers

**`instanceId`.** A stable per-host identifier minted at host creation. Format: UUID in canonical 8-4-4-4-12 hyphenated form is the established convention based on existing test fixtures, but the schema does not enforce this. The identifier is opaque to the library; its uniqueness scope and assignment policy are concerns of the issuing authority.

**`clusterId`.** A stable per-cluster identifier in the same shape as `instanceId`. Issued by the controlling authority at cluster creation.

**Issuer kid.** The SPKI thumbprint of the issuer's public key, formed as `base64url(SHA-256(spki_der_bytes))`. This means kids are derived deterministically from keys, not assigned out-of-band. A consequence: two issuers with the same key would have the same kid (degenerate case); two distinct keys cannot share a kid by construction. Key rotation is "publish a new public key with its derived kid; the old kid continues identifying the old key for as long as old HBDs need verifying."

**`cnf.pkthumb`.** The SPKI thumbprint of the host binding key, in the same form. See KD-01 for why this is SPKI-based rather than RFC 7638-based and what this means for the field name.

### 6.4 The cnf Confirmation Claim

The `cnf` claim follows the shape introduced by RFC 7800 (Proof-of-Possession Key Semantics for JWTs). RFC 7800 defines a confirmation claim block whose contents identify the proof-of-possession key bound to the token; this library uses that block but populates it with a single field, `pkthumb`, carrying an SPKI thumbprint of the host's binding key.

```json
"cnf": {
  "pkthumb": "ZMD9Cl__fS-2N4tfFrfm-cugKMvhwSXWDR5IzWE2Vok"
}
```

The value of `pkthumb` is the SPKI thumbprint of the binding key's public half: `base64url(SHA-256(spki_der_bytes))`. This is a deliberate departure from the more standards-conformant choice of using `jkt` with an RFC 7638 JWK thumbprint; see KD-01 for the rationale. The field is named `pkthumb` (rather than reusing `jkt`) precisely to avoid implying RFC 7638 semantics that this library does not provide.

When `cnf` is null or absent, the HBD has no proof-of-possession binding. The verifier rejects such HBDs in modes that require a cnf check (see FR-19).

### 6.5 Verification Modes

Verification operates in one of four modes, each strictly more demanding than the last.

**ParseOnly (mode 0).** Decode the JWS, validate header shape (`typ=JWT`), validate document shape (docType, version, required claims present), but do not verify the signature. Returns the payload as a `JsonDocument` and reports `SignatureVerified=false`. Use case: diagnostic inspection of an HBD whose signing key is not available to the verifier.

**VerifySignature (mode 1).** All ParseOnly checks, plus signature verification using the key returned by the caller's key retrieval callback, plus issuer allowlist check (if a non-empty list was supplied). Lifetime check is performed only if `ValidateLifetime=true`. The cnf claim is not consulted. Use case: verifying an HBD whose ownership binding is not relevant or not yet implemented.

**VerifySignatureAndCnfWarn (mode 2).** All VerifySignature checks, plus the cnf check (compute local thumbprint, compare to HBD's `cnf.pkthumb`). On mismatch, the result reports `CnfChecked=true, CnfMatched=false` but `Ok=true` — verification succeeds with a warning. On absence of cnf in the HBD, verification fails (cnf is required in this mode). Use case: rolling out cnf binding incrementally, where mismatches should be detected and logged but not break operation.

Additional branch behavior for both Warn and Enforce modes: when the local thumbprint provider throws (binding-key material missing, unreadable, malformed), Warn mode SHALL return `Ok=true` with `CnfChecked=true`, `CnfMatched=false`, and `FailureReason` populated with a diagnostic describing the exception so the caller can log it. Enforce mode SHALL return `Ok=false` with `FailureReason` populated with the same diagnostic. (The fact that Warn returns `Ok=true` even when the provider is broken reflects the purpose of Warn mode — surface signals without breaking operation. The diagnostic is the signal; failing on a broken provider would defeat the deployment-rollout use case.)

**EnforceAll (mode 3).** All VerifySignatureAndCnfWarn checks, but cnf mismatch fails verification. Use case: production verification where binding is required for security.

The current implementation supports ParseOnly and VerifySignature. Modes 2 and 3 are designed but stubbed; see OI-01.

### 6.6 The Host Binding Key

The Host Binding Key (HBK) is an ES256 (EC P-256) keypair the host owns and whose public-key SPKI thumbprint is embedded in the HBD's `cnf.pkthumb` claim. The HBK is the cryptographic anchor that ties an HBD to a specific host.

**Lifecycle (v1, bootstrap-once).** The HBK is generated or designated at host provisioning time and persists for the host's lifetime. The HBK is not rotated in normal operation; key compromise is handled by host re-imaging. (See KD-05.)

**Linux v1.** The HBK is the existing host SSH key (typically `/etc/ssh/ssh_host_ed25519_key` or equivalent), with its public component converted to SPKI/PEM form at provisioning time and stored at a path agreed with the HCS bootstrap. Reusing the existing host SSH key avoids minting a parallel identity for the host.

**Windows v1.** No native equivalent of the Linux host SSH key exists. The HBK is generated by the provisioning script as an EC P-256 keypair and stored in the Windows Certificate Store (`LocalMachine\My`), with the private key marked non-exportable, ACLs limiting access appropriately. Reading the binding-key thumbprint on Windows requires a Windows-specific `ILocalKeyThumbprintProvider` implementation that consults the cert store. That provider lives in the Windows HCS (or HCS bootstrap) library, not in this library — see §4.1 and OI-04 (resolved).

**Future migrations.** vTPM-backed binding keys are an anticipated future migration. The HBD format does not change to support them — `cnf.pkthumb` remains an SPKI thumbprint of a public key, regardless of where the private half lives. Only host-side key management changes. (See KD-04.)

**Library posture.** The library is cross-platform — it runs on any supported .NET target on Linux or Windows — but it is not entirely platform-agnostic in the providers it ships. The default `SpkiFileThumbprintProvider` reads a PEM file from a configured path; PEM is a cross-platform wire format, so this provider works on either OS. Platform-specific providers — notably a Windows Certificate Store provider — live in the consuming projects (the Windows HCS or HCS bootstrap library) rather than in this library, to avoid pulling Windows-specific dependencies into a library that targets both Linux and Windows. The `ILocalKeyThumbprintProvider` interface itself accommodates providers written outside this library. See OI-04 (resolved) for the rationale.

### 6.7 Issuer Identifier

The HBD `iss` claim identifies the issuer of the document. The library treats `iss` as an opaque string and performs no structural validation: issuer matching during verification is exact-string comparison against `VerificationSettings.AllowedIssuers`.

In practice, fleet operators using this library will adopt some convention for constructing issuer identifiers (a URN, a URL, a hostname, or other) so identifiers are stable, unique, and meaningful. The choice of convention belongs to the issuing system (the future groundcontrol service) and to the operator, not to this library. Operators populating `AllowedIssuers` SHOULD use full issuer-identifier strings matching whatever convention their issuing system produces. The spec's deliberate position is that this library is not the place to encode that convention.

(See KD-07 for the rationale for moving this concern out of the library spec.)

### 6.8 Versioning and Soft Delete

Not applicable as a data-storage concern: the library does not persist HBDs or maintain a history. Document-format versioning is addressed by the `version` field on the HBD payload; see §6.2 and KD-09.

### 6.9 Data Retention

Not applicable: the library does not retain data. HBDs flow through the library; their persistence (if any) is the consumer's responsibility.

---

## 7. Solution Structure

### 7.1 Libraries and Projects Overview

The library is a single deliverable — a NuGet package containing the OGA.HBD.Lib types. There is no further internal library decomposition at v1.

**OGA.HBD.Lib_SP** — Shared project containing all source. Three top-level namespaces:
- `OGA.HBD.Model` — POCO types (HBD, HostInfo, ConfirmationInfo, JWS_Header, JWK_ECDsa, BootstrapDocResult, PublicKeyCache, Enumerations).
- `OGA.HBD.Service` — services and settings (HBD_Signer, HBD_ContextVerifier, VerificationSettings).
- `OGA.HBD.Helpers` — utilities (ES256_Issuer, SpkiFileThumbprintProvider, ILocalKeyThumbprintProvider, PEMConverter, JsonDocument_Helpers).

**OGA.HBD.Lib_NET5 / NET6 / NET7** — Per-target wrapper csproj files that compile the shared sources against a specific .NET framework. They contain no logic of their own.

**OGA.HBD.Lib_Tests_SP** and per-target test wrappers — MSTest test projects, organized in the same shared-project pattern.

### 7.2 Library Boundary Rationale

The single-library shape is deliberate. The library is small (a few thousand lines including comments), the types are tightly coupled in their semantics (an HBD references a HostInfo_V1, ConfirmationInfo, etc.), and there is no reuse benefit from splitting them. A future split would be motivated only by:

- Wanting to ship the model types as a separate package consumed by callers that need to construct HBDs without taking a dependency on the JOSE machinery (this is hypothetical and would justify a `Model`-only package then).
- Decomposing the verifier from the signer if some consumers need only one (also hypothetical).

Neither motivation applies at v1. Reconsidering is cheap; relitigating in advance is not.

### 7.3 Reference Rules

The internal namespaces have only the following reference relationships:

- `OGA.HBD.Model` references nothing else in the library (and only base .NET).
- `OGA.HBD.Helpers` references `OGA.HBD.Model` for the ILocalKeyThumbprintProvider interface and PEM helpers.
- `OGA.HBD.Service` references both `OGA.HBD.Model` and `OGA.HBD.Helpers`.
- The test project references all three.

These rules are enforceable by inspection if not by build-time guards. Future contributors should preserve them.

---

## 8. Key Interfaces and Contracts

### 8.1 Internal Interfaces

**ILocalKeyThumbprintProvider.** The interface by which the verifier obtains the local host's binding-key thumbprint for cnf checking.

```csharp
public interface ILocalKeyThumbprintProvider
{
    string GetLocalPkthumb();
}
```

The interface intentionally returns an already-computed thumbprint string rather than a key. The verifier never sees the key itself; it compares thumbprints. This means a future TPM-backed implementation of the interface can produce the same thumbprint (since the thumbprint is of the public key, not the private one) without exposing the private key to the verifier process.

The interface name and the `Pkthumb` terminology in member names align with the `cnf.pkthumb` wire field defined in §6.4. The current implementation uses `GetLocalJktThumbprint`; renaming to `GetLocalPkthumb` is part of the rename pass described in the implementation directive.

The interface SHALL carry a doc comment indicating that the Windows Certificate Store implementation of `ILocalKeyThumbprintProvider` lives in the Windows HCS project, not in this library. The cross-reference is essential because a reader of this library who needs Windows support will otherwise expect to find the implementation here.

**Default implementation: SpkiFileThumbprintProvider.** Reads a PEM-encoded SPKI public key from a configured path and returns `base64url(SHA-256(spki))`. Suitable for v1 Linux binding (SSH host public key, after SPKI conversion at provisioning time) and any future case where binding-key material is available as a PEM file at a known path. SHALL carry a doc comment that points to the Windows cert-store provider's location in the Windows HCS project. Anticipated future implementations: a `WindowsCertStoreThumbprintProvider` (which lives outside this library, in the Windows HCS project), a `TpmThumbprintProvider` (when the vTPM migration occurs).

**Key retrieval callback.**

```csharp
public delegate (int res, SecurityKey? data) dKeyRetrievalCallback(string kid);
```

Caller-supplied function the verifier invokes to obtain a public key by kid. Returning `(1, key)` signals success; any other result code signals failure to retrieve. This delegate is the verifier's only window onto the caller's trust roots — the library does not know what keys exist or where they come from. (See OI-06 for the cosmetic note that this delegate type is duplicated in PublicKeyCache as `dKeyRetrieval`.)

### 8.2 External Contracts

The library's external contract is the HBD format itself, described in §6.2 (header), §6.2 (payload), §6.4 (cnf), §6.7 (issuer URN). Any system that produces or consumes HBDs — this library, a future Go or Rust port, a hand-written verifier — is held to that format.

**Versioning of the contract.** The HBD `version` claim is the signal for breaking changes to the document format. v1 is the only version defined at this revision. A v2 will be introduced when a breaking change is unavoidable; the policy for parallel-version operation during v1→v2 transitions is captured as a future concern in KD-09.

**Versioning of the library.** The library follows semantic versioning. A library version that supports HBD v2 will explicitly state that support; a library version that supports only HBD v1 will reject v2 documents (per FR-11).

### 8.3 DTOs and Wire Types

The HBD payload is itself the wire type. The C# types (`Host_BootstrapDoc`, `HostInfo_V1`, `ConfirmationInfo`) are the in-memory representation of the wire type, with property names that match the JSON wire format exactly (no `[JsonPropertyName]` remapping; deliberate, see KD-11).

`JsonSerializerOptions` used by the signer:
- `PropertyNamingPolicy = null` — preserves exact C# property names (camelCase as written).
- `WriteIndented = false` — compact output.
- `DefaultIgnoreCondition = JsonIgnoreCondition.Never` — all properties serialize, including null and default values.

The compact, no-rename, never-ignore stance ensures the bytes the signer signs match the bytes a verifier reads, with no canonical-form drift between implementations.

---

## 9. Protocols and Flows

### 9.1 Protocols

The library implements no bespoke protocols. JWS compact serialization (RFC 7515) and the supporting JOSE specs are the only wire format involved.

The protocols that *use* HBDs — minting, transport, renewal, host bootstrap — are out of scope for this spec; they belong to groundcontrol's spec and the provisioning script's spec. The HBD format depends on those protocols having certain properties (notably, that the minting protocol verifies binding-key possession at issuance time; see OI-03), but does not itself define them.

### 9.2 Architectural Data Flows

Two flows touch the library directly. Their full architectural context is sketched here for the implementer's understanding; implementers of consumer systems will see this material expanded in those systems' own specs.

**HBD issuance.** A host needs an HBD. The host (or its provisioning script) presents itself to the issuing authority (groundcontrol, in some role like `bootstrap-ca`). The minting protocol — out of scope for this spec — establishes that the requesting host owns a particular binding-key public half. Once that is established, the issuer constructs a `Host_BootstrapDoc` populated with the host's metadata (region, cluster, tenant, environment, etc.), the issuer's URN as `iss`, current Unix time as `iat`, an `exp` consistent with the issuer's lifetime policy, the `gcBaseUrl` that points the host at its assigned controller channel, and a `cnf.pkthumb` containing the SPKI thumbprint of the host's binding-key public half. The issuer calls `HBD_Signer.CreateBootstrapJws` with the document, the issuer's private key, and the kid. The resulting JWS string is returned to the host (via the minting protocol) where the host stores it according to whatever convention the consumer system has established.

**HBD verification on a host.** The HCS or HCS bootstrap, on a host, holds an HBD as a JWS string. It needs to confirm the HBD is authentic and (in production) that this host owns the binding key the HBD references. The host constructs a `VerificationSettings` populated with: the appropriate verification mode (typically `EnforceAll` in production, `VerifySignature` in early-deployment / pre-cnf-implementation phases), the set of allowed issuers (the URNs the host trusts to issue its HBDs), a key retrieval callback that resolves issuer kids to public keys (typically against a JWKS file the host received at provisioning, or a caching wrapper around such a file), and an `ILocalKeyThumbprintProvider` configured to read the host's binding-key public PEM. The host awaits `HBD_ContextVerifier.VerifyAsync` with the JWS and the settings. The result tells the host whether the HBD is trustworthy and, in non-bare modes, whether the binding to this host was confirmed.

### 9.3 User Workflow Narration

Not applicable: the library has no human users. Workflow narration for the host operator's experience belongs in the provisioning script's spec and the HCS spec.

---

## 10. API Surface

This is a library distributed as a NuGet package; its surface is the public API of its types, documented in §8.1 and the model definitions in §6. The library exposes no HTTP surface.

For reference, the principal public entry points consumers call directly are:

- `HBD_Signer.CreateBootstrapJws(payload, issuerPrivateKey, kid)` — sign an HBD.
- `HBD_Signer.ComputePkthumbFromSpkiPem(spkiPemPath)` — utility for issuer-side computation of a `cnf.pkthumb` value. (Currently named `ComputeJktFromSpkiPem`; renamed as part of the rename pass.)
- `HBD_Signer.ExportJwks(issuerPrivateKey, kid)` — produce JWKS for distribution.
- `HBD_ContextVerifier.VerifyAsync(jwsCompact, versettings)` — verify an HBD. Returns `Task<BootstrapDocResult>`.
- `HostInfo_V1.RecoverHostInfo_fromPayload(payload)` — recover strongly-typed claims from a verified payload.
- `ES256_Issuer.Create_NewIssuer()` — generate a new issuer keypair.
- `ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemPath)` — reload an issuer from a stored PEM.
- `ES256_Issuer.Get_IssuerProperties(ecdsa)` — derive kid, JWKS, public/private PEM from a key.
- `new SpkiFileThumbprintProvider(spkiPemPath)` — default implementation of `ILocalKeyThumbprintProvider`.

---

## 11. Infrastructure

This is a NuGet-distributed library; deployment shape is the consumer's concern. There is no runtime infrastructure to specify here. Any infrastructure-adjacent constraints (the .NET runtime, supported targets, platform availability) are documented in §4.1 and §4.3.

---

## 12. Key Decisions

### KD-01 — SPKI thumbprint, not RFC 7638 JWK thumbprint, for `kid` and `cnf.pkthumb`

**Decision.** The thumbprint used for both issuer key identification (`kid`) and host binding-key proof-of-possession (`cnf.pkthumb`) is `base64url(SHA-256(spki_der_bytes))` — the SHA-256 of the DER-encoded SubjectPublicKeyInfo. This is *not* the JWK thumbprint specified by RFC 7638 (which hashes a canonicalized JWK JSON object). The cnf field is named `pkthumb` (not `jkt`) precisely to keep the name honest about this difference.

**Rationale.** The SPKI thumbprint is simpler to compute on the host side: a host has its public key in some form (a PEM file, a TPM-resident key with an exportable public component, a Windows certificate) and can hash the SPKI bytes directly without first constructing a JWK JSON object. The library uses this same scheme uniformly for issuer kids (computed from the issuer's public-key SPKI) and for binding-key thumbprints, keeping a single hashing technique throughout. The implementation is identical between `cnf.pkthumb` computation and `kid` computation, which simplifies the code and the spec.

**Alternatives considered.** RFC 7638 JWK thumbprints. They are the more standards-conformant choice and would interoperate cleanly with off-the-shelf JOSE tooling that expects `cnf.jkt` to be an RFC 7638 thumbprint. They were rejected because (a) the library is for personal-use and not held to public interoperability, (b) the SPKI approach is materially simpler on the host side, and (c) the host-side keys are not natively JWKs and would require translation through a JWK construction step. Keeping the standard `jkt` name with non-standard semantics was also considered and rejected as a footgun for future reimplementers — see KD-12.

**Consequences.** A second implementation of this library (a Go or Rust port) must reproduce the SPKI hashing exactly. The chosen field name `pkthumb` ("public key thumbprint") is intentionally neutral about computation technique — it does not invoke RFC 7638 or any other standard, leaving the spec itself as the authoritative source on how the thumbprint is computed. The library's `ConfirmationInfo` class doc comment is updated as part of the rename pass to describe SPKI-SHA256 hashing accurately and to remove an obsolete RFC 7638 reference.

### KD-02 — ES256-only

**Decision.** The library accepts and produces only ES256 signatures. `alg=none`, HS256, RS256, and other JWS algorithms are not supported in any mode or configuration.

**Rationale.** Algorithm agility is a well-known JOSE liability. Several attack classes (downgrade to `none`, HMAC-with-public-key confusion) depend on the verifier accepting algorithms it shouldn't. By pinning to a single algorithm at both the signer and verifier, these attack classes are eliminated by construction. ES256 is the right choice for v1: it is widely supported in cryptographic libraries on every platform the library targets, the signatures and keys are small, and it pairs naturally with the SPKI thumbprint scheme (which is platform-agnostic for EC keys).

**Alternatives considered.** Algorithm agility (offering EdDSA, RS256 alongside ES256). Rejected because the security cost of agility exceeds the operational benefit for a personal-use library where the owner controls all issuers and verifiers and can move to a new algorithm by versioning the library and the HBD format.

**Consequences.** A move to a different algorithm is a coordinated upgrade across all issuers and verifiers, not a configuration change. This is acceptable given the operational shape of the fleet (single owner, manageable number of components). Required by NFR-03; enforced by FR-12.

### KD-03 — Signer is a pure encode-and-sign primitive

**Decision.** The signer (`HBD_Signer.CreateBootstrapJws`) does not set `iat`, `exp`, `iss`, or any other payload claim. The caller is responsible for populating all claims before submitting the HBD for signing.

**Rationale.** Different callers have different lifetime policies and different ways of constructing claims. A signer that auto-sets `iat = now` and `exp = now + 24h` would constrain all callers to a single TTL policy or require parameter explosion to override defaults. By delegating claim population to the caller (groundcontrol, in production), the signer remains a stable primitive whose behavior is deterministic and easy to reason about.

**Alternatives considered.** A higher-level `IssueHbd(hostInfo, issuerKey, kid, ttl)` that sets `iat`, `exp`, and `iss` automatically. Useful for casual use but constrains operational policy and pushes complexity into the library that belongs in the issuing authority. Rejected.

**Consequences.** The caller must remember to populate `iat` and `exp` correctly. A buggy caller that submits an HBD with `iat=0, exp=0` will produce a signed but operationally-invalid HBD; the verifier will reject it (per FR-09). This is a footgun the spec partially mitigates by stating the contract clearly (FR-03) but does not eliminate. The library could add a sign-time sanity check rejecting `iat=0` or `exp=0`; this is captured as OI-08.

### KD-04 — v1 binding keys are software keys; vTPM is a future migration

**Decision.** The Host Binding Key in v1 is a software key — the existing host SSH key on Linux, a provisioning-generated EC P-256 key on Windows. vTPM-backed binding is planned as a future migration but is not part of v1.

**Rationale.** v1 prioritizes deployability over hardware-rooted attestation. Most of the fleet is virtualized, vTPM availability and configuration vary across hypervisors (vSphere, AWS Nitro, DigitalOcean's hypervisor), and adding a TPM-mediated key handling story to v1 would significantly delay v1 for a personal-use system whose threat model does not currently include attackers with arbitrary host-resident code execution that could exfiltrate software keys. The vTPM migration is real and worth doing eventually; v1 is not the time.

**Alternatives considered.** Skipping software-key binding entirely and going straight to vTPM. Rejected: the host-platform machinery for vTPM-backed keys (Linux tpm2-tss workflows, Windows CNG with the Platform Crypto Provider, AIK enrollment, attestation flows) is substantial work that doesn't pay off for v1's threat model.

**Consequences.** The HBD format is designed so the migration is invisible to verifiers — `cnf.pkthumb` is an SPKI thumbprint regardless of where the private key lives. Only host-side key management changes. The `ILocalKeyThumbprintProvider` interface accommodates a future `TpmThumbprintProvider` without requiring changes to the verifier or the document format. (See §6.6.)

### KD-05 — Bootstrap-once binding keys

**Decision.** A host's binding key is generated or designated at provisioning and persists for the host's lifetime. It is not rotated in normal operation; key compromise is handled by host re-imaging.

**Rationale.** Bootstrap-once is the simplest workable lifecycle. Rotation adds protocol complexity (renewal handshakes that update the cnf binding, transition windows where multiple binding keys are valid for the same host) for a security benefit that is small in the v1 threat model — a software binding key on a compromised host is exactly as compromised as everything else on that host. The simplicity dividend is real and immediate.

**Alternatives considered.** Periodic rotation (the binding key rolls every N days, with a renewal protocol that updates `cnf.pkthumb`). Useful for limiting the value of a leaked private key, but more expensive to design and implement than v1 warrants. Rotation can be added later as a v2 feature; the HBD format itself does not constrain the choice. Rejected for v1.

**Consequences.** Re-imaging a host is the standard recovery action for binding-key compromise. The HBK that goes with a host is part of the host's provisioning identity; replacing it requires re-bootstrapping. The spec assumes this is operationally acceptable, which it is for a personal-use fleet.

### KD-06 — `AllowedIssuers` permissive-by-default in the library; non-empty required by deployment convention

**Decision.** When `VerificationSettings.AllowedIssuers` is empty, the verifier skips the issuer check. Production deployments are required by convention to populate the list with at least one issuer URN.

**Rationale.** A non-empty default would require the library to know what issuers the caller trusts, which it cannot. A permissive default (skip the check) is the only neutral library behavior. The deployment-time requirement to populate the list is captured in this spec and is the responsibility of every consumer.

**Alternatives considered.** A required-non-empty contract enforced at construction time (the library throws or returns an error if `Verify` is called with an empty list). Closer to fail-safe but conflates "explicitly skip the check" (legitimate use case for tooling that just wants to validate signature) with "forgot to populate the list" (the dangerous case). Rejected as overly prescriptive.

A separate `RequireIssuerCheck` boolean (default true) that gates the empty-allowed behavior. Stronger than convention; implementable. Captured as a possible v2 enhancement but not adopted at v1.

**Consequences.** Reviewers of consumer code (HCS, groundcontrol, diagnostic tools) need to confirm that production code paths populate `AllowedIssuers`. The spec makes this convention explicit (NFR-07, this KD); future reviewers can reference it.

### KD-07 — Library is silent on issuer-identifier structure

**Decision.** The library treats the HBD `iss` claim as an opaque string. It performs no parsing, no grammar validation, and imposes no structural convention on issuer identifiers. Issuer matching during verification is exact-string comparison against `VerificationSettings.AllowedIssuers`.

**Rationale.** The choice of how to name issuers — URN, URL, hostname, or other — is a concern of the issuing system (groundcontrol) and the operator running it. Pushing that convention into the HBD library entangles two concerns that benefit from being separate: the document format, which is stable, versus the issuer-naming convention, which is fluid and may evolve as the fleet evolves. Earlier drafts of this spec contained a detailed URN grammar (closed env enum, regex-defined segments, sentinel values for non-cloud issuers); on reflection, that level of structural commitment did not belong in the library spec, because the library doesn't enforce or use the structure.

**Alternatives considered.** Documenting a URN grammar in this spec and having the library validate `iss` against it on verification. Rejected: this would require the library to either bundle the grammar in code (making it a compile-time concern) or accept it as configuration (making the library more complex for marginal benefit). Either way, the library would acquire opinions about issuer naming that it has no operational reason to hold.

A briefer alternative — documenting the convention informationally in the spec without validating it in code — was also considered and rejected. The risk is that future readers treat informational spec content as authoritative, leading to drift between the documented convention and the convention actually used by groundcontrol. Cleaner to keep the convention where it is used (the issuing system, plus the operator's own documentation) and let the HBD spec say only what the library does.

**Consequences.** Operators are responsible for using consistent, meaningful issuer identifiers and for populating `AllowedIssuers` accurately. The library cannot help catch typos or formatting drift. This is acceptable given the operational shape of the fleet (single owner, manageable number of issuers). If a future reader of HBDs from outside the fleet ever needs to make sense of issuer strings, they consult whatever documentation describes the operator's chosen convention — not this spec.

### KD-08 — Multi-target build (NET 5/6/7)

**Decision.** The library is built and shipped as a NuGet package targeting .NET 5, 6, and 7, with `linux-any` and `win-any` runtimes. Newer .NET versions are added when consumer needs them.

**Rationale.** The library has a small surface and uses only stable .NET cryptographic APIs that are available on every supported target. Multi-targeting via shared projects is essentially free in source maintenance and gives consumers flexibility.

**Alternatives considered.** Targeting only the latest LTS. Cleaner build configuration but pushes consumers to upgrade .NET in lockstep with the library. Rejected.

Targeting only `netstandard2.1`. Simpler still, would reach the broadest audience, but loses access to some newer cryptographic conveniences (e.g., `SHA256.HashData` static method). Marginal call; not adopted.

**Consequences.** The build pipeline maintains per-target wrapper csproj files. Adding NET 8/9 is a new wrapper csproj and a build configuration change. Captured as a known follow-up with no immediate trigger.

### KD-09 — HBD version 1 is rigidly enforced; v2 is a coordinated upgrade

**Decision.** The verifier accepts only HBDs declaring `version=1`. Version 2 (when needed) is introduced via a library version that explicitly handles it; verifiers running an older library will reject v2 documents rather than silently downgrading.

**Rationale.** Silent version downgrade is a footgun. Forcing a version mismatch to fail loudly catches deployment errors immediately. v1→v2 transitions are coordinated upgrades: groundcontrol begins minting v2 only when all relevant verifiers have been updated to a library version that supports it.

**Alternatives considered.** Version-tolerant parsing that accepts any version it understands and ignores fields it doesn't. Standard advice for many forward-evolving formats but inappropriate here: HBDs are security-critical, and silently ignoring an unrecognized field could mean ignoring a security control introduced in a later version. Rejected.

**Consequences.** v1→v2 migrations require a planned rollout. The strategy is captured in OI for when it becomes relevant: see future spec revisions.

### KD-10 — No revocation in v1; short HBD lifetimes as the mitigation

**Decision.** v1 has no HBD revocation mechanism. HBDs become invalid by expiry; compromised HBDs stay valid until their `exp` timestamp. The TTL is set short enough (e.g., 24 hours, as in the existing test fixture) that the worst-case exposure window is bounded.

**Rationale.** Revocation lists, OCSP-like endpoints, and revocation status caching are substantial infrastructure for a personal-use system whose worst-case compromise window is a day. The simpler mitigation — make HBDs short-lived and renew them frequently — covers the threat at acceptable operational cost.

**Alternatives considered.** A revocation endpoint queried by verifiers on each verification. Adds network dependency to verification, which is otherwise pure-local. Rejected at v1.

A bloom-filter or denylist of revoked HBDs distributed to verifiers. Tractable but adds distribution complexity. Rejected at v1.

**Consequences.** HBD TTLs are an operational decision made by the issuer (groundcontrol, in production); short TTLs require the renewal protocol to be reliable. If renewal is broken for longer than the TTL, hosts cannot operate. This is a real coupling between renewal availability and operational continuity, captured here for visibility. The renewal protocol's spec — when written — must address this.

### KD-11 — JSON serialization preserves C# property names exactly

**Decision.** The signer serializes HBDs with `PropertyNamingPolicy = null` (no rename) and `DefaultIgnoreCondition = JsonIgnoreCondition.Never` (all properties present including null/default). Wire format property names match C# property names verbatim — `docType` (camelCase as written), `version`, `iss`, `iat`, `exp`, `hostInfo`, `cnf`.

**Rationale.** JSON canonicalization issues are a recurring source of JOSE bugs. Two implementations that produce semantically-equivalent JSON but byte-different strings produce different signatures, which break verification. By writing C# property names in the desired wire format and disabling all JSON-ser-time renaming, the library makes the wire format trivially predictable: it is the literal property names of the C# types. A second implementation in another language can match this format by giving its types the same property names, with no JSON-mapping layer to misconfigure.

**Alternatives considered.** Standard PascalCase C# names with `[JsonPropertyName]` attributes mapping to camelCase. More idiomatic C# but introduces a place for the wire format and the in-memory format to diverge. Rejected.

A canonicalizing serializer (sort keys lexicographically before signing). Stronger guarantee but more code and more places for bugs. Rejected; the simpler "exact-name, no rename" approach is sufficient.

**Consequences.** C# property names look slightly non-idiomatic (`docType` instead of `DocType`). This is acceptable. Future readers should understand the deliberate departure; this KD makes the reasoning visible.

### KD-12 — Parallel callback delegate types maintained deliberately

**Decision.** The library defines two callback delegate types for key retrieval: `VerificationSettings.dKeyRetrievalCallback` (used by the verifier) and `PublicKeyCache.dKeyRetrieval` (used by the optional public-key cache helper). The two have identical signatures at this revision but are not consolidated into a single type.

**Rationale.** The verifier and the cache helper serve different consumers and may evolve along different trajectories — for example, a future revision of the verifier callback might accept additional context (a hint about the expected algorithm, or a trace identifier), while the cache callback might remain a simple kid-to-key lookup. Keeping the types separate gives each surface independent freedom to evolve without breaking the other.

**Alternatives considered.** Consolidate to one shared delegate type. Simpler in the short term but couples the evolution of two distinct API surfaces. Rejected.

**Consequences.** Readers of the library encounter two delegate types that look identical at this revision. The duplication is intentional and documented; it is not a code-hygiene defect to be removed. This KD subsumes the original OI-06, which was withdrawn when this decision was made.

---

## 13. Open Items

### OI-01 — Cnf enforcement modes are stubbed [resolved: scoped to implementation]

The library's verifier currently fails fast with `"Verification level set to check cnf.jkt, but logic is not yet defined."` whenever it is asked to operate in `VerifySignatureAndCnfWarn` or `EnforceAll` mode. The dead code below the guard sketches the intended logic; this OI tracked the decision to either close the gap or accept it.

**Resolution.** Implement the cnf evaluation logic, replacing the stub guard and refining the dead-code sketch. The behavior across all branches is specified in §6.5 and FR-17 / FR-18, with the exception-handling behavior covered by what was previously OI-02 (now subsumed; see below). The Warn-mode exception branch in particular returns `Ok=true` with a populated `FailureReason` and `CnfMatched=false`, reflecting the deliberate operational meaning of Warn mode (warn, do not break operation).

Implementation work is described in the implementation directive accompanying this spec revision. A congruency-check OI (OI-12) is planted to verify the implementation against §6.5 and FR-17 / FR-18 once the work lands.

### OI-02 — (withdrawn, subsumed into OI-01)

Originally tracked the question of how Warn mode should behave when the local thumbprint provider throws. Closed by subsumption: the answer is part of OI-01's resolution and the specified behavior is documented in §6.5. The original framing characterized the existing placeholder code as "silently permissive" and a bug; the more accurate characterization is that the existing code is an unfinished sketch by the project owner that they had not yet worked through. The spec now specifies the intended behavior, which the implementer will write to.

### OI-03 — Minting protocol must verify HBK possession at issuance [deferred to groundcontrol spec]

The HBD format depends on the minting protocol verifying that the requesting host actually possesses the binding key whose thumbprint goes into `cnf.pkthumb`. If the minting protocol simply records a thumbprint the host claims, an attacker can claim someone else's thumbprint and obtain an HBD that nominally binds to a key the attacker doesn't control.

The HBD library cannot enforce this property — it is strictly a property of the minting protocol, which is implemented by a separate process (the future groundcontrol service) and specified in that service's own spec. This OI is deliberately kept open in this spec as a deferred design dependency: the HBD format's security model holds only if the minting protocol satisfies this property, and the future groundcontrol spec must satisfy it.

**When this closes.** When the groundcontrol spec exists and specifies a minting protocol that proves binding-key possession at issuance time (challenge-response, sign-the-request, or other equivalent mechanism), the resolution of this OI is to reference that protocol from this spec.

### OI-04 — Windows binding-key storage and provider location [resolved]

Two questions were rolled into this item: where the Windows binding-key material is stored on a Windows host, and where the code that reads it (the cert-store provider) lives.

**Resolution.** Storage: the Windows Certificate Store (`LocalMachine\My`), with the private key marked non-exportable and ACLs set appropriately by the provisioning script. Provider location: the Windows-specific provider implementation lives in the Windows HCS (or HCS bootstrap) library, not in this library. This library ships only `SpkiFileThumbprintProvider`, which handles the PEM-file case (used by Linux for SSH-derived binding keys, and usable by any platform that can produce a PEM file).

Rationale: keeping platform-specific code in consuming projects keeps this library cross-platform without pulling Windows-only dependencies into it. The `ILocalKeyThumbprintProvider` interface accommodates providers written outside this library.

The implementation directive includes a small task to add doc-comments on `ILocalKeyThumbprintProvider` and `SpkiFileThumbprintProvider` pointing readers to the Windows cert-store provider's location, so the asymmetry is documented at the point of use rather than only in the spec.

The full provisioning-script-level details of Windows binding-key generation, ACL setup, and cert-store population are deferred to the future provisioning script spec.

### OI-05 — (withdrawn, no longer applicable)

Originally tracked the question of closing the enumeration of valid `authority` values in the issuer URN grammar. Withdrawn because the library no longer takes a position on issuer-identifier structure at all; see KD-07 (revised). The URN grammar moved out of the library spec; the authority enum question moves with it, to whichever document eventually defines the operator's issuer-naming convention (the future groundcontrol spec or the operator's project wiki).

### OI-06 — (withdrawn, converted to KD-12)

Originally tracked the cosmetic question of consolidating the two parallel callback delegate types (`VerificationSettings.dKeyRetrievalCallback` and `PublicKeyCache.dKeyRetrieval`). The project owner decided to keep them separate, deliberately, to allow each delegate to evolve independently of the other. This is no longer an open item; it is a deliberate design choice and is documented as KD-12.

### OI-07 — `cnf.jkt` field name vs. SPKI hashing [resolved]

The field was originally named `jkt`, the standard JOSE name for an RFC 7638 JWK thumbprint, but the library uses SPKI-SHA256 hashing per KD-01. The mismatch was a footgun for any future reimplementer who followed the field name to RFC 7638 and computed the wrong value.

**Resolution.** Rename the field from `jkt` to `pkthumb` ("public key thumbprint"). The new name is honest about the role — it's a thumbprint of a public key — without invoking RFC 7638 or any other standard the library doesn't follow. The implementation directive covers the wire-format change, the C# property rename, the helper-method rename (`ComputeJktFromSpkiPem` → `ComputePkthumbFromSpkiPem`, `GetLocalJktThumbprint` → `GetLocalPkthumb`), and the comment updates that go with them.

This decision interacts with KD-01: the rename is what makes KD-01's choice of SPKI-over-RFC-7638 stop being a footgun. KD-01's revised text reflects this.

### OI-08 — Signer should validate non-zero `iat` and `exp` [resolved: scoped to implementation]

KD-03 and FR-03 commit to the signer rejecting HBDs with zero or missing `iat`/`exp`. The current implementation does not enforce this — it will sign whatever is submitted.

**Resolution.** Add a sign-time validation step in `HBD_Signer.CreateBootstrapJws` that returns an error result (without signing) when:
- `iat` is zero or negative
- `exp` is zero or negative
- `exp <= iat`

A congruency-check OI (OI-13) is planted to verify the implementation once the work lands.

### OI-09 — (withdrawn, resolved by project owner)

Originally tracked the stale test fixture in `Test_TestBase.cs` that did not populate `gcBaseUrl`. The project owner has updated the fixture; the change is pushed to the repository. No implementer action required.

### OI-10 — Stale comment in `ConfirmationInfo.cs` [resolved: scoped to implementation]

The XML doc comment on `ConfirmationInfo.jkt` cites RFC 7638 and includes a leftover `chatgpt.com` URL. Per KD-01, the actual hashing is not RFC 7638. Combined with the OI-07 rename, the field is now `ConfirmationInfo.Pkthumb`.

**Resolution.** As part of the rename pass described in the implementation directive, rewrite the XML doc comment to: (a) describe the SPKI-SHA256 hashing accurately, (b) cite RFC 7800 for the cnf-claim shape only (without referencing RFC 7638), (c) remove the chatgpt URL, (d) cross-reference KD-01 in this spec for the design rationale.

### OI-11 — (withdrawn, resolved by project owner)

Originally tracked the filename `PublicKeyRing.cs` containing class `PublicKeyCache`. The project owner has renamed the file; the change is pushed to the repository. No implementer action required.

### OI-12 — Congruency check: cnf evaluation matches §6.5 [resolved]

**Resolution.** The cnf evaluation implementation pass landed in `[commit: 5277af7]` and was verified against §6.5 and FR-17 / FR-18. The verifier's behavior across all branches of cnf evaluation — match, mismatch in Warn, mismatch in Enforce, missing cnf in Warn/Enforce, local-thumbprint-provider exception in Warn, local-thumbprint-provider exception in Enforce — matches the spec. Test coverage exercises each branch. The project owner confirmed test results on a development VM (the implementer did not have the credential infrastructure to run the full test suite directly).

### OI-13 — Congruency check: `pkthumb` rename is complete [resolved]

**Resolution.** The rename pass landed in `[commit: 5277af7]`. The wire format uses `pkthumb`; the C# property is `ConfirmationInfo.pkthumb`; helper methods are `ComputePkthumbFromSpkiPem` and `GetLocalPkthumb`; the `ILocalKeyThumbprintProvider` interface method is renamed; the XML doc comment on `ConfirmationInfo.pkthumb` is rewritten per OI-10; the doc comments on `ILocalKeyThumbprintProvider` and `SpkiFileThumbprintProvider` point to the Windows cert-store provider's location per OI-04; test fixtures are updated. No stale `"jkt"` strings remain in production code paths.

### OI-14 — Congruency check: signer iat/exp validation [resolved]

**Resolution.** The signer-validation pass landed in `[commit: 5277af7]`. `HBD_Signer.CreateBootstrapJws` rejects HBDs whose `iat` is zero or negative, whose `exp` is zero or negative, or whose `exp` is not strictly greater than `iat`. Tests exercise each rejection path.

### OI-15 — Migrate verifier from `JsonWebTokenHandler.ValidateToken` to `ValidateTokenAsync` [resolved: scoped to implementation]

Microsoft.IdentityModel.JsonWebTokens has marked the synchronous `ValidateToken(string, TokenValidationParameters)` overload as deprecated, with a `[System.Obsolete]` attribute and a "will be removed in a future release" notice. The verifier calls it at `HBD_ContextVerifier.cs:249` and triggers a CS0618 warning at compile time. As of Microsoft.IdentityModel.JsonWebTokens v8.x the removal version is not announced; the deprecation is real but the timeline is not.

The async replacement, `ValidateTokenAsync`, returns `Task<TokenValidationResult>`. There is no safe sync-over-async pattern available at the call site — `.Result` and `.GetAwaiter().GetResult()` are well-known antipatterns that risk deadlock in some hosting contexts. Migrating the call therefore forces the public verifier surface to become async.

**Resolution.** Convert `HBD_ContextVerifier.Verify` in place to `HBD_ContextVerifier.VerifyAsync`, returning `Task<BootstrapDocResult>`. The sync `Verify` method is removed, not preserved as a wrapper. The library has few enough consumers (HCS, HCS bootstrap, tests) that the migration cost is small, and the in-place option avoids carrying a deprecated path indefinitely. Tests are updated to await the new method. The README's quick-start example is updated to async form. Cross-references in this spec to `Verify` are updated to `VerifyAsync` (§9.2, §10, FR-04).

**Alternatives considered.** Adding `VerifyAsync` alongside the existing sync `Verify`. Rejected: the sync method would either disappear when Microsoft removes `ValidateToken` (now-breaking) or become a sync-over-async wrapper (which has the deadlock risk we're trying to avoid). The in-place migration is the eventual destination regardless; doing it now closes the gap once.

**Note for future revisions.** Going async at the verifier level opens the door to making the key-retrieval callback async, which would be a future-friendly change if/when callbacks need I/O (e.g., fetching a JWKS over HTTP). That is not part of this resolution and is left for a future spec revision if/when the need arises. The current callback signature (`dKeyRetrievalCallback`, returning `(int, SecurityKey?)` synchronously) is unchanged in this pass.

A congruency-check OI (OI-18) is planted to verify the implementation once the work lands.

### OI-16 — Standardize on a single base64url encoder [resolved]

The signer and verifier compute the same logical value (`base64url(SHA-256(SPKI_DER))` — the `pkthumb`) using two different libraries: `HBD_Signer.ComputePkthumbFromSpkiPem` uses `Jose.Base64Url.Encode`, while `SpkiFileThumbprintProvider.GetLocalPkthumb` uses `Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode`. The two encoders produce identical output today, but the signer side and verifier side computing the same `pkthumb` via different encoder libraries is a subtle interop risk if either library ever changes its padding or encoding behavior in a future version.

**Resolution.** Standardize on `Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode` throughout the library. The signer switches its import. Reasons:
- The verifier already depends on Microsoft.IdentityModel.Tokens for its validation pipeline; aligning the encoder with the validation library keeps the verifier's encoding behavior synchronized with the library it most tightly depends on.
- Microsoft.IdentityModel is the more load-bearing of the library's two JOSE dependencies; aligning on the more-load-bearing library reduces the surface area where divergence could happen.
- jose-jwt remains a dependency for `JWT.Encode` (the actual JWS encoding step in the signer); this change touches only the thumbprint computation.

**Alternatives considered.** Standardizing on `Jose.Base64Url` instead. Equivalent cost (one import change) but aligns with the less load-bearing library; rejected. Writing a custom base64url encoder in the library to eliminate both library dependencies for this operation. Tempting given how small base64url is, but introduces a small amount of crypto-adjacent code we'd be responsible for, with the failure mode of producing self-consistent-but-ecosystem-incompatible output if there's any bug. Rejected; the libraries are stable enough that standardizing on one is the safer practical choice.

A congruency-check OI (OI-19) is planted to verify the implementation once the work lands.

### OI-17 — Document signer/verifier result codes [resolved]

The signer's `CreateBootstrapJws` returns an `(int res, string val)` tuple where `res == 1` indicates success and negative values indicate failure modes. After the iat/exp validation work added by OI-08, three negative failure codes exist: `-1` for null/blank arguments, `-2` for caught exceptions, `-3` for invalid iat/exp. A caller can distinguish success from failure but cannot distinguish failure modes without reading source. The verifier's `BootstrapDocResult` is richer (carries `Ok`, `FailureReason`, and other diagnostic fields) and does not have this issue, but several signer-side methods follow the same magic-number convention.

**Resolution.** Add XML doc comment tables on signer methods that return multi-value result codes, enumerating each code and what it means. The lightweight approach preserves the existing API (no breaking changes for callers) while making the codes self-documenting in IntelliSense.

Methods to be documented:
- `HBD_Signer.CreateBootstrapJws` — codes `1` (success), `-1` (null/blank argument), `-2` (caught exception), `-3` (invalid iat/exp).
- Any other signer/helper methods that use the same convention with multiple failure codes. The implementer should audit and document any found.

**Alternatives considered.** Introducing a strongly-typed result enum (`HbdSignResult.Success`, `.NullOrBlankArgument`, etc.) and changing the return type. Cleaner but breaks every caller of the signer. Deferred to a hypothetical future API revision where the broader signer surface might be reworked at the same time.

A congruency-check OI (OI-20) is planted to verify the documentation once the work lands.

### OI-18 — Congruency check: async migration is complete [resolved]

**Resolution.** The async migration landed in `[commit: 4a6d2b6]`. `HBD_ContextVerifier.VerifyAsync` exists with return type `Task<BootstrapDocResult>`; the legacy sync `Verify` is removed (no wrapper, no sync-over-async shim). The call site uses `await handler.ValidateTokenAsync(...)`. No CS0618 warnings related to `ValidateToken` remain at build time. Existing tests were updated to `await VerifyAsync` and pass on the project owner's development VM. A reflection-based test (`Test_VerifyAsync_ReturnsTask` in `AsyncVerifierApi_Tests.cs`) asserts the signature and the absence of the sync method, preventing accidental regressions. The README quick-start update is handled by the project owner in a separate commit, per the implementation directive's note.

### OI-19 — Congruency check: single base64url encoder [resolved]

**Resolution.** The encoder standardization landed in `[commit: 4a6d2b6]`. `HBD_Signer.ComputePkthumbFromSpkiPem` uses `Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode`. The audit found and migrated additional sites that fell under the "or equivalent" qualifier — the hand-rolled `Base64Url` helper in `ES256_Issuer` (used for kid computation, a thumbprint) was removed, and the kid + JWK x/y encoding now also route through `Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode`. The jose-jwt NuGet reference is retained for `JWT.Encode` in the signer; its role narrows to JWS encoding only. A regression test (`Test_SignerAndVerifier_AgreeOnPkthumb` in `EncoderAgreement_Tests.cs`) generates fresh EC P-256 keypairs, computes the thumbprint of each via both the signer's `ComputePkthumbFromSpkiPem` and the verifier's `SpkiFileThumbprintProvider`, and asserts byte-for-byte equality.

### OI-20 — Congruency check: result-code documentation [resolved]

**Resolution.** The result-code documentation work landed in `[commit: 4a6d2b6]`. `HBD_Signer.CreateBootstrapJws` carries an XML doc `<returns>` block enumerating each return-code value (`1`, `-1`, `-2`, `-3`) and its meaning. The implementer's audit identified three additional public signer-side helper methods in `OGA.HBD.Helpers.ES256_Issuer` that use the same multi-return-code convention; each has been documented similarly: `Get_PrivKeyPKCS8_from_ECDsaInstance` (codes `1`, `-1`, `-2`), `CreateIssuer_fromPrivatePKCS8` (codes `1`, `-2`), and `LoadIssuer_fromPrivateKeyPEMPkcs8` (codes `1`, `-1`, where `-1` collapses several underlying failure modes from its delegated calls). Lower-level helpers in `PEMConverter` and the verifier-side `HostInfo_V1.RecoverHostInfo_fromPayload` were considered and deliberately left undocumented for this pass; they fall outside the "signer-side" scope of OI-17 and a future revision may pick them up.

---

## 14. Revision Log

### 2026-05-11T06:15:07Z

Bookkeeping revision. The second implementation pass (the OI-15 / OI-16 / OI-17 work) landed in `[commit: 4a6d2b6]` and closes cleanly:

- **OI-18** (async migration congruency): resolved. `VerifyAsync` returns `Task<BootstrapDocResult>`; sync `Verify` is removed; no CS0618 warnings remain.
- **OI-19** (single base64url encoder congruency): resolved. The audit pulled in the hand-rolled `Base64Url` in `ES256_Issuer` as an "or equivalent" candidate and migrated it too; `Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode` is the single thumbprint encoder. A regression test exercises signer/verifier agreement.
- **OI-20** (result-code documentation congruency): resolved. `HBD_Signer.CreateBootstrapJws` documents its four return codes; the audit identified three additional signer-side `ES256_Issuer` methods that were documented in the same pass.

The `[commit: TBD]` placeholders in OI-12/13/14 (the congruency checks for the first implementation pass) have been replaced with `[commit: 5277af7]`, the actual landing commit for that pass.

Both implementation directives are archived: `docs/archive/IMPLEMENTATION_DIRECTIVE_2026-05-11.md` (the first pass) and `docs/archive/IMPLEMENTATION_DIRECTIVE_2026-05-11-r2.md` (this pass). Each carries a "Status: Archived" banner at the top.

No new Open Items, FRs, or KDs are added in this revision; only resolutions, commit-hash backfills, and the archival housekeeping.

### 2026-05-11T05:55:38Z

Third revision. Closes the congruency-check OIs from the previous implementation pass and plants three new resolutions (OI-15, OI-16, OI-17) with their own congruency checks (OI-18, OI-19, OI-20). Adds a small wording correction to §6.2.

Substantive changes:

- **§6.2 (HostInfo schema):** softened the `environment` field description. Previously stated the field shall be "one of `dev`, `test`, `stage`, `val`, `prod` (case-sensitive, lowercase)." Now describes those values as the operator's convention rather than a library-enforced constraint, consistent with the library's posture toward opaque string claims (see KD-07). The library does not validate this field; conformance to the convention is the operator's responsibility.

- **§9.2 (Verification flow):** updated the narrative to describe the verifier as an awaited async call rather than a synchronous one. This anticipates the OI-15 async migration.

- **§10 (API Surface):** `HBD_ContextVerifier.Verify` reference updated to `VerifyAsync` with `Task<BootstrapDocResult>` return type, per OI-15.

- **FR-04:** rewritten to specify the verifier is asynchronous. Cross-reference to OI-15 added for context.

Open Item dispositions:

- **OI-12** (cnf evaluation congruency): resolved by the prior implementation pass. Commit hash to be filled in.
- **OI-13** (`pkthumb` rename congruency): resolved by the prior implementation pass. Commit hash to be filled in.
- **OI-14** (signer iat/exp validation congruency): resolved by the prior implementation pass. Commit hash to be filled in.
- **OI-15** (async migration): planted and resolved. Scoped to implementation in the accompanying directive.
- **OI-16** (single base64url encoder): planted and resolved. Standardize on `Microsoft.IdentityModel.Tokens.Base64UrlEncoder`.
- **OI-17** (document signer result codes): planted and resolved. Add XML-doc tables on multi-return-code methods.
- **OI-18** (async migration congruency): planted, awaiting implementation.
- **OI-19** (single encoder congruency): planted, awaiting implementation.
- **OI-20** (result-code documentation congruency): planted, awaiting implementation.

A separate implementation directive document accompanies this revision and instructs the CLI implementer on the OI-15/16/17 code work. After that pass lands, OI-18/19/20 will close in a subsequent revision. *(That subsequent revision is the 2026-05-11T06:15:07Z entry above; OI-12/13/14 commit hashes were filled in at the same time.)*

### 2026-05-11T04:24:31Z

Second revision. Resolved every Open Item carried over from the initial draft except OI-03, which is deliberately deferred to the future groundcontrol spec.

Substantive changes:

- **§4.1 (Tech Stack), §6.6 (Host Binding Key):** revised the library-posture statements. The library is "cross-platform" rather than "platform-agnostic"; the file-based `SpkiFileThumbprintProvider` ships with the library, but Windows-specific providers (notably the Windows Certificate Store provider) live in consuming projects, not in this library. Windows v1 binding-key storage is the Windows Certificate Store; this is now stated directly rather than left open.

- **§6.4 (cnf claim):** field renamed from `jkt` to `pkthumb`. The cnf claim still follows RFC 7800's shape but populates a single field, `pkthumb`, carrying the SPKI-SHA256 thumbprint of the host binding key. The name is intentionally neutral about computation technique and does not invoke RFC 7638 or any other standard.

- **§6.7 (Issuer Identifier):** previous URN grammar removed. The library now treats `iss` as an opaque string and performs no structural validation. Issuer-naming conventions belong to the issuing system (the future groundcontrol service) and to the operator, not to this library.

- **§8.1 (Internal Interfaces):** `ILocalKeyThumbprintProvider` method renamed from `GetLocalJktThumbprint` to `GetLocalPkthumb`. Doc-comment requirement added: both the interface and `SpkiFileThumbprintProvider` must carry comments pointing to the Windows cert-store provider's location.

- **FRs:** FR-14, FR-15, FR-17, FR-18, FR-19 updated to reference `cnf.pkthumb` rather than `cnf.jkt`. No FR added or withdrawn.

- **§6.5 (Verification Modes):** Warn-mode exception behavior specified — on local-thumbprint-provider exception, return `Ok=true` with `FailureReason` populated, reflecting Warn mode's purpose of surfacing signals without breaking operation. Enforce mode fails on the same exception with `FailureReason` populated.

- **KD-01:** updated to reflect the field rename. The consequences section no longer describes the field name as a footgun (the rename closed that); it now describes what a future reimplementer must reproduce.

- **KD-07:** rewritten substantially. Was "Six-segment fixed URN for issuer identity"; is now "Library is silent on issuer-identifier structure." Reflects the decision to move the URN grammar out of this spec.

- **KD-12:** new. Documents the deliberate separation of `dKeyRetrievalCallback` and `dKeyRetrieval` (the previous OI-06's resolution).

Open Item dispositions:

- **OI-01** (cnf enforcement modes stubbed): resolved, scoped to implementation. Replaced with directive content describing the full intended behavior. Implementation pending; OI-12 planted as congruency check.
- **OI-02** (Warn-mode silent permissiveness): withdrawn, subsumed into OI-01.
- **OI-03** (minting protocol verifies HBK possession): kept open, deferred to future groundcontrol spec.
- **OI-04** (Windows binding-key storage): resolved. Cert store as the storage facility; Windows-specific provider lives in the Windows HCS library, not in this one.
- **OI-05** (closed authority enum): withdrawn, no longer applicable given KD-07's revision.
- **OI-06** (duplicate delegate types): withdrawn, converted to KD-12.
- **OI-07** (field name): resolved. Rename `jkt` → `pkthumb`. OI-13 planted as congruency check.
- **OI-08** (signer iat/exp validation): resolved, scoped to implementation. OI-14 planted as congruency check.
- **OI-09** (stale test fixture): withdrawn, resolved by project owner.
- **OI-10** (stale comment): resolved, scoped to implementation as part of the rename pass.
- **OI-11** (filename mismatch): withdrawn, resolved by project owner.

New items: KD-12, OI-12, OI-13, OI-14.

A separate implementation directive document accompanies this revision and instructs a CLI implementer on the work needed to bring the codebase into alignment with this spec.

### 2026-05-10T09:05:32Z

Initial draft. Created retrospectively from the existing OGA.HBD.Lib codebase and the design conversation with Claude that produced this document.

Items created:
- UR-01 through UR-08
- FR-01 through FR-23
- NFR-01 through NFR-08
- KD-01 through KD-11
- OI-01 through OI-11

Notable items: KD-01 (SPKI thumbprint vs RFC 7638) is the most consequential design choice surfaced by the spec exercise; OI-01 (cnf enforcement modes are stubbed) is the most consequential implementation gap; OI-07 (field naming) is the principal cleanup decision needed before further components depend on the library.

---

*End of specification.*
