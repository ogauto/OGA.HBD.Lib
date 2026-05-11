using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace OGA.HBD.Helpers
{
    /// <summary>
    /// Interface implemented by a provider that knows how to compute the local host's
    /// Host Binding Key thumbprint (the value that must match an HBD's cnf.pkthumb).
    /// </summary>
    /// <remarks>
    /// This library ships one default implementation, <see cref="SpkiFileThumbprintProvider"/>,
    /// that reads an SPKI/PEM file from a configured path. Platform-specific implementations live
    /// in consuming projects rather than in this library, so the library can target both Linux
    /// and Windows without pulling in platform-specific dependencies.
    /// In particular, the Windows Certificate Store implementation of this interface lives in the
    /// Windows HCS (or HCS bootstrap) library, NOT in this library. A reader looking for Windows
    /// binding-key support should consult that library.
    /// See SPEC.md §4.1 (Tech Stack) and §6.6 (Host Binding Key) for the design rationale.
    /// </remarks>
    public interface ILocalKeyThumbprintProvider
    {
        /// <summary>
        /// Returns base64url(SHA-256(SPKI)) of the local Host Binding Key (the public half).
        /// The returned value is compared against the HBD's cnf.pkthumb claim during verification.
        /// </summary>
        string GetLocalPkthumb();
    }

    /// <summary>
    /// Default file-based implementation of <see cref="ILocalKeyThumbprintProvider"/>.
    /// Reads a PEM-encoded SPKI public key from a configured path and computes
    /// base64url(SHA-256(SPKI_DER_bytes)).
    /// </summary>
    /// <remarks>
    /// Suitable for the v1 Linux binding case (the host SSH key's public half, converted to
    /// SPKI/PEM at provisioning time) and for any other case where binding-key public-key material
    /// is available as a PEM file at a known path on disk.
    /// For Windows, the binding key lives in the Windows Certificate Store and is read by a
    /// platform-specific provider that lives in the Windows HCS (or HCS bootstrap) library, NOT
    /// in this library. See SPEC.md §6.6 for the cross-platform posture and rationale.
    /// </remarks>
    public sealed class SpkiFileThumbprintProvider : ILocalKeyThumbprintProvider
    {
        private readonly string _spkiPemPath;

        public SpkiFileThumbprintProvider(string spkiPemPath) => _spkiPemPath = spkiPemPath;

        public string GetLocalPkthumb()
        {
            // Expecting SubjectPublicKeyInfo (SPKI) PEM
            var pem = File.ReadAllText(_spkiPemPath);
            var spki = PEMConverter.ExtractKey_fromPem(pem, "PUBLIC KEY");
            var hash = SHA256.HashData(spki);
            return Base64UrlEncoder.Encode(hash);
        }
    }
}
