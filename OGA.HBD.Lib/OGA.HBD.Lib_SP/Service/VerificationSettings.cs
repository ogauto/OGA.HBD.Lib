using Microsoft.IdentityModel.Tokens;
using OGA.HBD.Helpers;
using OGA.HBD.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OGA.HBD.Service
{
    /// <summary>
    /// Populate an instance with the settings and callbacks needed to verify a token.
    /// At a minimum, you will need to define a verification level (mode).
    /// If set to Verification, assign a key retrieval callback, and optional issuers list.
    /// If verifying cnf.jkt, pass in a thumbprint provider.
    /// </summary>
    public sealed class VerificationSettings
    {
        /// <summary>
        /// This property defines the level of verification to be performed on a received JWS.
        /// </summary>
        public VerificationMode Mode { get; init; } = VerificationMode.VerifySignature;

        /// <summary>
        /// Allowed issuers; if empty, issuer check is skipped.
        /// </summary>
        public HashSet<string> AllowedIssuers { get; init; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Optional local thumbprint provider for cnf.jkt binding.
        /// This is only required if mode checks CNF.jkt.
        /// </summary>
        public ILocalKeyThumbprintProvider? LocalThumbprintProvider { get; init; }

        /// <summary>
        /// Key Retrieval Callback signature.
        /// </summary>
        /// <param name="kid"></param>
        /// <returns></returns>
        public delegate (int res, SecurityKey? data) dKeyRetrievalCallback(string kid);
        /// <summary>
        /// Assign a delegate to this, so the verification method can retrieve keys as needed.
        /// </summary>
        public dKeyRetrievalCallback? KeyRetrievalCallback { get; init; }

        /// <summary>
        /// Optional lifetime validation (uses iat/exp if present)
        /// </summary>
        public bool ValidateLifetime { get; init; } = false;

        /// <summary>
        /// Set this to the allowed tolerance of the issue and expiry timestamps.
        /// </summary>
        public TimeSpan? ClockSkew { get; init; } = TimeSpan.FromMinutes(2);
    }
}
