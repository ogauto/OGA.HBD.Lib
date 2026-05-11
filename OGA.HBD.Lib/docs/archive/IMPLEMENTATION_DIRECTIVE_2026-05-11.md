# OGA.HBD: Implementation Directive — Spec Alignment Pass

**Target Spec:** `SPEC.md`, revision `2026-05-11T04:24:31Z`
**Repository:** `https://github.com/ogauto/OGA.HBD.Lib`
**Purpose:** Bring the codebase into alignment with the spec. This document is consumed by an implementing agent; after the work lands and the congruency-check OIs are resolved, this document is archived.

---

## Reading this document

This directive describes the implementation work needed to bring OGA.HBD.Lib into alignment with the current spec revision. It is *not* the spec — the spec is authoritative. This directive is a worklist derived from the spec.

For each work item below:

- The **what** describes the code change to make.
- The **why** points to the spec item(s) that motivate the change. Read those spec sections before making the change.
- The **acceptance criteria** describes what "done" looks like, including tests.

Several work items overlap (they touch the same files). They are presented as separate items for clarity, but the implementer SHOULD make all changes in a single coordinated pass, with a single coherent commit (or a small number of logically-grouped commits), to avoid intermediate broken states.

When this work is complete, the implementer SHOULD revise the spec by closing the planted congruency-check OIs (OI-12, OI-13, OI-14) with a note of the commit that resolved them.

---

## Work Item 1: Rename `cnf.jkt` to `cnf.pkthumb`

### What

Rename the cnf-claim field from `jkt` to `pkthumb` everywhere it appears:

1. **C# property** in `OGA.HBD.Lib_SP/Model/ConfirmationInfo.cs`: `public string? jkt { get; set; }` → `public string? pkthumb { get; set; }`. Preserve the property's casing convention (lowercase first letter, matching the wire format — see KD-11).

2. **Wire format JSON property**: implicitly handled by the C# property rename (KD-11: wire format matches C# property names verbatim with `PropertyNamingPolicy = null`). Verify by inspection that no `[JsonPropertyName("jkt")]` attribute or equivalent override exists anywhere.

3. **Helper method on `HBD_Signer`**: `ComputeJktFromSpkiPem` → `ComputePkthumbFromSpkiPem`. Update all callers (test code, anywhere else in the library that references it).

4. **Interface method on `ILocalKeyThumbprintProvider`**: `GetLocalJktThumbprint` → `GetLocalPkthumb`. Update the interface definition in `OGA.HBD.Lib_SP/Helpers/SpkiFileThumbprintProvider.cs`, update the `SpkiFileThumbprintProvider` implementation, and update all callers including the verifier.

5. **Local variable names** in the verifier (`HBD_ContextVerifier.cs`): the local `jkt` extracted from the payload and `localJkt` from the provider become `pkthumb` and `localPkthumb` respectively. (Or whatever names you prefer; consistency with the field name is what matters.)

6. **Error message strings** in the verifier: any user-facing message mentioning `jkt` becomes the corresponding `pkthumb` message. The specific message `"Verification level set to check cnf.jkt, but logic is not yet defined."` goes away entirely when the cnf logic is implemented (Work Item 2); other messages get updated.

7. **Test code**: `OGA.HBD.Lib_Tests_SP/Helpers/Test_TestBase.cs` and all test files. Search for `jkt`, `Jkt`, `JKT` and rename appropriately.

8. **XML doc comments** that reference the old name. (Combined with Work Item 4, the comment rewrite.)

### Why

- Spec §6.4 specifies the field as `pkthumb`, not `jkt`.
- KD-01 explains the rationale: the field uses SPKI-SHA256 hashing rather than RFC 7638; the new name avoids implying RFC 7638 semantics.
- OI-07 captures this decision; OI-13 is the congruency check planted for verification after this work lands.

### Acceptance criteria

- Build clean on all targets (NET 5, 6, 7).
- All existing tests pass.
- No string `"jkt"` appears anywhere in the source under `OGA.HBD.Lib_SP/` or `OGA.HBD.Lib_Tests_SP/` except in:
  - Comments that historically reference the old name (these get rewritten in Work Item 4, not retained).
  - Text describing RFC 7800 or RFC 7638 in spec/doc context.
- A new test, `Test_PkthumbField_OnWire`, confirms a signed HBD's decoded JSON payload has a `cnf.pkthumb` key (not `cnf.jkt`).

---

## Work Item 2: Implement cnf evaluation modes (Warn and Enforce)

### What

In `OGA.HBD.Lib_SP/Service/HBD_ContextVerifier.cs`, in the `Verify` method, replace the stub guard:

```csharp
if(versettings.Mode == VerificationMode.VerifySignatureAndCnfWarn ||
    versettings.Mode == VerificationMode.EnforceAll)
{
    return Fail("Verification level set to check cnf.jkt, but logic is not yet defined.");
}
```

…with full cnf evaluation logic. The existing dead code below the guard sketches the right shape but is not authoritative; write the logic to match §6.5 of the spec exactly. The behavior across all branches:

1. **`cnf.pkthumb` is absent or empty in the HBD** (already handled correctly above the guard; preserve the existing check). Return `Fail("cnf.pkthumb not found.")` regardless of Warn or Enforce.

2. **Call `versettings.LocalThumbprintProvider.GetLocalPkthumb()`.** Wrap in try/catch.

3. **Provider throws an exception**:
   - **Warn mode**: return result with `Ok=true`, `CnfChecked=true`, `CnfMatched=false`, `FailureReason="local thumbprint unavailable: {ex.Message}"`, `SignatureVerified=true`, plus the other diagnostic fields. Verification *succeeds* with a populated diagnostic.
   - **Enforce mode**: return `Fail($"local thumbprint unavailable: {ex.Message}")`. Verification *fails*.

4. **Provider returns a thumbprint** — compare to `cnf.pkthumb` using `TimingSafeEquals`.

5. **Thumbprints match**: return result with `Ok=true`, `CnfChecked=true`, `CnfMatched=true`, `FailureReason=""`, `SignatureVerified=true`. Verification succeeds.

6. **Thumbprints do not match**:
   - **Warn mode**: return `Ok=true`, `CnfChecked=true`, `CnfMatched=false`, `FailureReason=$"cnf.pkthumb mismatch (local {localPkthumb}, hbd {hbdPkthumb})"`, `SignatureVerified=true`. Verification *succeeds* with a populated diagnostic.
   - **Enforce mode**: return `Ok=false`, `CnfChecked=true`, `CnfMatched=false`, `FailureReason=$"cnf.pkthumb mismatch (local {localPkthumb}, hbd {hbdPkthumb})"`, `SignatureVerified=true`. Verification *fails*.

Add a guard at the top of the cnf-evaluation block: if `versettings.LocalThumbprintProvider == null` and mode is Warn or Enforce, return `Fail("Verification mode requires a LocalThumbprintProvider, but none was supplied.")`. (This catches caller misuse before the null-dereference would occur.)

Remove the redundant "FROM HERE DOWN, WE HAVE NOT YET REFINED THE LOGIC..." banners in comments — they're no longer accurate after this work.

### Why

- Spec §6.5 specifies the four-mode ladder. Currently the library implements only modes 0 and 1; this work closes the gap.
- FR-17 and FR-18 specify the Warn-mode and Enforce-mode behaviors.
- KD-01 motivates the cnf-binding role of the field.
- OI-01 captures this work; OI-12 is the congruency check planted for verification after this work lands.

### Acceptance criteria

- Build clean on all targets.
- New tests covering each branch of the cnf evaluation:
  - `Test_VerifySignatureAndCnfWarn_Match` — HBD with matching cnf, Warn mode, expects `Ok=true, CnfChecked=true, CnfMatched=true`.
  - `Test_VerifySignatureAndCnfWarn_Mismatch` — HBD with non-matching cnf, Warn mode, expects `Ok=true, CnfChecked=true, CnfMatched=false`, populated `FailureReason`.
  - `Test_VerifySignatureAndCnfWarn_ProviderThrows` — provider implementation that throws, Warn mode, expects `Ok=true, CnfChecked=true, CnfMatched=false`, populated `FailureReason` mentioning the exception.
  - `Test_VerifySignatureAndCnfWarn_MissingCnf` — HBD without populated `cnf.pkthumb`, Warn mode, expects `Ok=false, FailureReason` containing "cnf.pkthumb not found".
  - `Test_VerifySignatureAndCnfWarn_NullProvider` — Warn mode with `LocalThumbprintProvider == null`, expects `Ok=false, FailureReason` mentioning the missing provider.
  - `Test_EnforceAll_Match` — match case, expects success.
  - `Test_EnforceAll_Mismatch` — expects `Ok=false` (fail).
  - `Test_EnforceAll_ProviderThrows` — expects `Ok=false` (fail) with populated `FailureReason`.
  - `Test_EnforceAll_MissingCnf` — expects `Ok=false`.
  - `Test_EnforceAll_NullProvider` — expects `Ok=false`.
- Existing `Test_1_1_1` (which uses `VerifySignature` mode) continues to pass unchanged.

---

## Work Item 3: Add signer iat/exp validation

### What

In `OGA.HBD.Lib_SP/Service/HBD_Signer.cs`, in `CreateBootstrapJws`, add a pre-signing validation step that returns an error result (without signing) when:

- `payload.iat <= 0`
- `payload.exp <= 0`
- `payload.exp <= payload.iat`

The error result should follow the same shape as other errors returned by the signer (`res != 1`, populated reason string).

Place the validation early in the method, before any signing work. Keep the validation concise; this is sanity-checking, not deep policy enforcement.

### Why

- FR-03 and KD-03 commit to the signer enforcing caller-provided iat/exp.
- OI-08 captures this work; OI-14 is the congruency check planted for verification.

### Acceptance criteria

- Build clean.
- New tests:
  - `Test_Sign_RejectsZeroIat` — submit HBD with `iat=0`, expect error result without signing.
  - `Test_Sign_RejectsZeroExp` — `exp=0`, expect error.
  - `Test_Sign_RejectsNegativeIat` — `iat=-1`, expect error.
  - `Test_Sign_RejectsNegativeExp` — `exp=-1`, expect error.
  - `Test_Sign_RejectsExpBeforeIat` — `exp <= iat`, expect error.
- Existing `Test_1_1_1` (which submits valid iat/exp) continues to pass unchanged.

---

## Work Item 4: Rewrite the `ConfirmationInfo.Pkthumb` doc comment

### What

In `OGA.HBD.Lib_SP/Model/ConfirmationInfo.cs`, rewrite the XML doc comment on the renamed `pkthumb` property (post-Work-Item-1):

- Describe the actual computation: `base64url(SHA-256(SPKI_DER_bytes))` of the host binding key's public-key SPKI.
- Cite RFC 7800 for the cnf-claim shape only. Do NOT cite RFC 7638 — the computation is not RFC 7638.
- Remove the leftover `chatgpt.com` URL from the existing comment.
- Cross-reference the spec by section: `<see>` or prose reference to "KD-01 in SPEC.md" for the design rationale.

While you're in the file, audit other XML doc comments on `ConfirmationInfo` for accuracy. The class-level comment, if it references RFC 7638 or jkt, gets the same treatment.

### Why

- KD-01 specifies the actual hashing technique.
- OI-10 captures this work.
- This is bundled with Work Item 1 (the rename) because the field name and the comment both change for the same reason.

### Acceptance criteria

- The doc comment accurately describes the SPKI-SHA256 hashing.
- No reference to RFC 7638 remains in the file.
- No chatgpt URL remains in the file.
- A reference to KD-01 (or to the spec generally) is present in the comment.

---

## Work Item 5: Cross-reference the Windows cert-store provider

### What

In `OGA.HBD.Lib_SP/Helpers/SpkiFileThumbprintProvider.cs`, add (or update) doc comments on:

1. **The `ILocalKeyThumbprintProvider` interface**. Add a `<remarks>` section explaining that this library ships one default implementation (`SpkiFileThumbprintProvider`) for the PEM-file case, and that platform-specific implementations — notably the Windows Certificate Store provider — live in consuming projects rather than in this library. State that the Windows cert-store implementation is located in the Windows HCS (or HCS bootstrap) library. Cross-reference §4.1 and §6.6 of SPEC.md.

2. **The `SpkiFileThumbprintProvider` class itself**. Add a class-level `<remarks>` section noting that this is the default file-based implementation, suitable for Linux SSH-derived binding keys (after SPKI conversion at provisioning) and any other case where binding-key material is available as a PEM file. Point readers to the Windows cert-store provider in the Windows HCS library for Windows binding-key support.

Both doc-comment additions should be brief but specific enough that a reader navigating the codebase can find the Windows implementation without confusion.

### Why

- Spec §4.1 and §6.6 specify the cross-platform posture: PEM file provider here, Windows-specific provider elsewhere.
- OI-04 resolution requires the cross-reference comments to make the asymmetry visible at the point of use.

### Acceptance criteria

- Doc comments are present on both the interface and the class.
- Comments mention the Windows HCS library location of the cert-store provider.
- Comments cross-reference the spec.

---

## Work Item 6: Clean up the verifier's dead-code banners

### What

In `OGA.HBD.Lib_SP/Service/HBD_ContextVerifier.cs`, after Work Item 2 lands, remove the three lines of repeated comments:

```
// FROM HERE DOWN, WE HAVE NOT YET REFINED THE LOGIC TO EVALUATE THE CNF.JKT PROPERTY.
// FROM HERE DOWN, WE HAVE NOT YET REFINED THE LOGIC TO EVALUATE THE CNF.JKT PROPERTY.
// FROM HERE DOWN, WE HAVE NOT YET REFINED THE LOGIC TO EVALUATE THE CNF.JKT PROPERTY.
```

…along with the stub-guard `if` block above them. The logic that *was* below them is now the authoritative implementation (after rewriting per Work Item 2), so the warning is no longer accurate.

### Why

After Work Item 2, the comments would be misleading: the logic has now been refined to spec.

### Acceptance criteria

- The repeated banner comments are gone.
- The stub-guard `if` is gone.
- The "End of verification only" boundary comment may stay or be reworded for clarity.

---

## Out of scope for this pass

The following are *not* part of this implementation pass:

- **The minting protocol** (how groundcontrol issues HBDs). OI-03 is deliberately deferred to the future groundcontrol spec.
- **A Windows Certificate Store provider implementation.** It belongs in the Windows HCS (or HCS bootstrap) library, not this one. Adding cross-reference doc comments (Work Item 5) is in scope; writing the actual cert-store provider is not.
- **Multi-version HBD support.** The library stays HBD-v1-only per KD-09.
- **Revocation infrastructure.** Stays absent per KD-10.
- **API surface refactoring** that goes beyond the renames specified above.

---

## Spec revision after this work lands

After this implementation pass is complete and all tests pass, the implementer SHOULD revise SPEC.md to close the planted congruency-check OIs (OI-12, OI-13, OI-14) with notes pointing to the commit(s) that resolved them. The revision log entry for that spec update is a single short paragraph stating the implementation pass landed and the congruency-check items closed.

Per the methodology, this implementation directive document is then archived (kept in the repository at `docs/IMPLEMENTATION_DIRECTIVE_2026-05-11.md` or similar, but not actively maintained going forward). Future implementation work produces a new directive document.

---

*End of directive.*