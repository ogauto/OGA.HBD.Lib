# OGA.HBD.Lib

A C# library for creating, signing, and verifying **Host Bootstrap Documents (HBDs)** — signed identity documents used by hosts and a central authority to attest host identity and bootstrap host management.

## What is an HBD?

A Host Bootstrap Document is similar in spirit to an AWS Instance Identity Document, but cloud-agnostic and bound to a host-owned key via RFC 7800 proof-of-possession.

Each HBD is a JWS-encoded document that carries:

- Host metadata — region, availability zone, instance identifier, tenant, cluster identity, environment, image name, and the base URL of the host's assigned controller.
- An issuer identifier and a signature, so any holder of the issuer's public key can verify the document's authenticity.
- A `cnf.pkthumb` proof-of-possession binding — the SPKI-SHA256 thumbprint of the public half of the host's binding key — so the document can only be effectively used by the host that controls the matching private key.

HBDs are signed using ES256 (ECDSA P-256 with SHA-256). The library is the canonical implementation of the document format and provides the primitives any consumer needs to mint, verify, and read HBDs.

## Used by

- **groundcontrol** — the central authority that mints HBDs for hosts in the fleet (forthcoming).
- **Host Control Service (HCS)** and **HCS bootstrap** — the host-resident agent and its loader, which read their HBD from local storage and verify it to authenticate to groundcontrol.
- Diagnostic and operational tooling that needs to parse or inspect HBDs.

## Documentation

The authoritative design document for this library is **[`docs/SPEC.md`](docs/SPEC.md)**. The spec covers the HBD document format, the verification mode ladder, the issuer-key lifecycle, the proof-of-possession binding contract, and every Key Decision behind the library's shape. New contributors and integrators should read the spec before extending or depending on the library; the README is intentionally brief.

## Quick start

### Signing an HBD (issuer side)

```csharp
// Generate or load an issuer key
var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

// Construct the document
var hbd = new Host_BootstrapDoc {
    iss = "urn:my-org:hbd:bootstrap-ca:my-tenant:prod:us-east-1",
    iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
    exp = DateTimeOffset.UtcNow.AddHours(24).ToUnixTimeSeconds(),
    cnf = new ConfirmationInfo {
        pkthumb = HBD_Signer.ComputePkthumbFromSpkiPem("/path/to/host-binding-key.pub.pem")
    }
};
hbd.hostInfo.tenant       = "my-tenant";
hbd.hostInfo.clusterId    = "...";
hbd.hostInfo.clusterName  = "vault02-prod";
hbd.hostInfo.environment  = "prod";
hbd.hostInfo.gcBaseUrl    = "https://groundcontrol.example.com/v1/channels/abc";
// ...populate other hostInfo fields...

// Sign it
var result = HBD_Signer.CreateBootstrapJws(hbd, issuerKey, kid);
string hbdJws = result.val;  // JWS compact serialization
```

### Verifying an HBD (host side)

```csharp
var settings = new VerificationSettings {
    Mode = VerificationMode.EnforceAll,
    AllowedIssuers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
        "urn:my-org:hbd:bootstrap-ca:my-tenant:prod:us-east-1"
    },
    LocalThumbprintProvider = new SpkiFileThumbprintProvider("/etc/oga/host-binding-key.pub.pem"),
    KeyRetrievalCallback = (kid) => /* return (1, publicKey) for known kids */,
    ValidateLifetime = true
};

var verification = await HBD_ContextVerifier.VerifyAsync(hbdJws, settings);
if (verification.Ok) {
    var (recRes, hostInfo) = HostInfo_V1.RecoverHostInfo_fromPayload(verification.Payload);
    // hostInfo.clusterName, hostInfo.environment, hostInfo.gcBaseUrl, etc.
}
```

For verification mode semantics (ParseOnly / VerifySignature / VerifySignatureAndCnfWarn / EnforceAll), see SPEC.md §6.5.

## Platform support

The library is cross-platform. It targets:

- .NET 5, .NET 6, .NET 7
- `linux-any` and `win-any` runtimes

The library ships one default `ILocalKeyThumbprintProvider` implementation, `SpkiFileThumbprintProvider`, which reads a PEM-encoded SPKI public key from a configured path. This works for Linux host SSH keys (after SPKI conversion at provisioning time) and for any other case where binding-key material is available as a PEM file.

Platform-specific providers — notably a Windows Certificate Store provider for Windows hosts — live in consuming projects (HCS, HCS bootstrap), not in this library. This keeps the library cross-platform without pulling Windows-only dependencies into a library that also targets Linux.

## Installation

OGA.HBD.Lib is available via private NuGet:

- NuGet Official Releases: [![NuGet](https://buildtools.ogsofttech.com:8079/packages/oga.hbd.lib)](https://buildtools.ogsofttech.com:8079/packages/oga.hbd.lib)

## Dependencies

- [Microsoft.IdentityModel.JsonWebTokens](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet)
- [Microsoft.IdentityModel.Tokens](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet)
- [jose-jwt](https://github.com/dvsekhvalnov/jose-jwt)

See SPEC.md §4.2 for the rationale behind each dependency choice.

## Building

This library is built with the new SDK-style projects, organized as a Shared Project (`OGA.HBD.Lib_SP`) with thin per-framework wrapper csproj files. The output NuGet package supports the framework versions and runtimes listed above. If you need additional framework support, open an issue.

This library is currently built using Visual Studio 2022 17.6.3.

## License

See [LICENSE](LICENSE).
