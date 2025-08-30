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
    public interface ILocalKeyThumbprintProvider
    {
        /// <summary>
        /// Returns base64url(SHA256(SPKI)) of the local binding key the VM owns.
        /// </summary>
        string GetLocalJktThumbprint();
    }

    /// <summary>
    /// Reads a PEM/SPKI public key file and computes base64url(SHA256(SPKI)).
    /// Useful when your local key is provisioned separately (e.g., /var/lib/hostctl/vm.pub).
    /// </summary>
    public sealed class SpkiFileThumbprintProvider : ILocalKeyThumbprintProvider
    {
        private readonly string _spkiPemPath;

        public SpkiFileThumbprintProvider(string spkiPemPath) => _spkiPemPath = spkiPemPath;

        public string GetLocalJktThumbprint()
        {
            // Expecting SubjectPublicKeyInfo (SPKI) PEM
            var pem = File.ReadAllText(_spkiPemPath);
            var spki = PEMConverter.ExtractKey_fromPem(pem, "PUBLIC KEY");
            var hash = SHA256.HashData(spki);
            return Base64UrlEncoder.Encode(hash);
        }
    }
}
