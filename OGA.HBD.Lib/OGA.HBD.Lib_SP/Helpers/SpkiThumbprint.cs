using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace OGA.HBD.Helpers
{
    /// <summary>
    /// Canonical, stateless, platform-neutral computation of an SPKI thumbprint:
    /// base64url(SHA-256(SPKI_DER)).
    /// This is the single source of truth for the thumbprint scheme the library uses for both
    /// issuer key identification (the JWS header <c>kid</c>) and host-binding-key proof-of-possession
    /// (the HBD's <c>cnf.pkthumb</c> claim). See SPEC.md §6.4, §6.6, and KD-01.
    /// </summary>
    /// <remarks>
    /// This type operates purely on SPKI bytes or in-memory public-key material; it pulls in no
    /// platform-specific dependency (no Windows Certificate Store, no file system), consistent with
    /// the library's cross-platform posture. A remote verifier (e.g. the GCS during proof-of-possession
    /// verification) computes the same thumbprint from a key it receives over the wire by calling
    /// <see cref="ComputeFromPublicKey(AsymmetricAlgorithm)"/>, so the binding formula cannot drift
    /// between issuer, host verifier, and remote verifier.
    /// </remarks>
    static public class SpkiThumbprint
    {
        /// <summary>
        /// Computes base64url(SHA-256(spkiDer)) over a DER-encoded SubjectPublicKeyInfo.
        /// This is the canonical formula; all other overloads funnel into it.
        /// </summary>
        /// <param name="spkiDer">DER-encoded SubjectPublicKeyInfo bytes.</param>
        static public string Compute(ReadOnlySpan<byte> spkiDer)
        {
            var hash = SHA256.HashData(spkiDer);
            return Base64UrlEncoder.Encode(hash);
        }

        /// <summary>
        /// Computes the SPKI thumbprint of an in-memory public key by exporting its
        /// SubjectPublicKeyInfo and hashing it. Suitable for key material already held in memory
        /// (e.g. a public key received over the wire), with no file or platform dependency.
        /// </summary>
        /// <param name="publicKey">
        /// A key whose public half is exportable as SPKI (e.g. <see cref="ECDsa"/>, <see cref="RSA"/>).
        /// </param>
        static public string ComputeFromPublicKey(AsymmetricAlgorithm publicKey)
        {
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));

            var spki = publicKey.ExportSubjectPublicKeyInfo();
            return Compute(spki);
        }

        /// <summary>
        /// Computes the SPKI thumbprint of a PEM-encoded "PUBLIC KEY" (SubjectPublicKeyInfo) string.
        /// </summary>
        /// <param name="spkiPem">A PEM string containing a "-----BEGIN PUBLIC KEY-----" (SPKI) block.</param>
        static public string ComputeFromPem(string spkiPem)
        {
            // Expecting SubjectPublicKeyInfo (SPKI) PEM.
            var spki = PEMConverter.ExtractKey_fromPem(spkiPem, "PUBLIC KEY");
            return Compute(spki);
        }
    }
}
