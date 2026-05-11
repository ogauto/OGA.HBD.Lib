using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace OGA.HBD.Model
{
    /// <summary>
    /// Holds the confirmation claim for a Host Bootstrap Doc.
    /// Carries proof-of-possession data binding the HBD to the host's binding key.
    /// The cnf-claim shape follows RFC 7800 (Proof-of-Possession Key Semantics for JWTs):
    /// https://datatracker.ietf.org/doc/html/rfc7800
    /// The thumbprint computation is library-specific (SPKI-SHA256), not RFC 7638; see KD-01 in SPEC.md.
    /// </summary>
    public class ConfirmationInfo
    {
        /// <summary>
        /// Public-key thumbprint of the Host Binding Key.
        /// Value: base64url(SHA-256(SPKI_DER_bytes)) of the binding key's public half.
        /// This is intentionally NOT an RFC 7638 JWK thumbprint; the SPKI-SHA256 scheme is used
        /// uniformly for both issuer kids and host-binding proof-of-possession in this library.
        /// See KD-01 in SPEC.md for the design rationale, and §6.4 for the wire shape of the cnf claim.
        /// </summary>
        public string pkthumb { get; set; }


        /// <summary>
        /// Public constructor, that baselines all values.
        /// </summary>
        public ConfirmationInfo()
        {
            this.pkthumb = string.Empty;
        }
    }
}
