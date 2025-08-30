using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace OGA.HBD.Model
{
    /// <summary>
    /// Returned from a Verify() call (that checks the validity of an HBD).
    /// </summary>
    public sealed class BootstrapDocResult
    {
        /// <summary>
        /// Indicates if the verification was successful.
        /// </summary>
        public bool Ok { get; init; }
        /// <summary>
        /// If the verification failed, this is a description of the reason.
        /// </summary>
        public string? FailureReason { get; init; }
        /// <summary>
        /// This contains the key id of the signing key for the token.
        /// observed kid (for logs)
        /// </summary>
        public string? Kid { get; init; }
        /// <summary>
        /// This is the token issuer name.
        /// observed iss (for logs)
        /// </summary>
        public string? Iss { get; init; }
        /// <summary>
        /// This contains the recovered Host Bootstrap Document, in JsonDocument format.
        /// </summary>
        public JsonDocument? Payload { get; init; }
        /// <summary>
        /// Indicates if the token signature was verified.
        /// </summary>
        public bool SignatureVerified { get; init; }
        /// <summary>
        /// Indicates if the CNF.JKT was checked.
        /// </summary>
        public bool CnfChecked { get; init; }
        /// <summary>
        /// Indicates if the CNF.JKT matched the host/instance.
        /// When trues, the host is verified as being the correct owner of the HBD.
        /// </summary>
        public bool CnfMatched { get; init; }
    }
}
