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
    /// This contains data about the key-pair that was given to the VM/host/instance, that proves the VM is associated with the HBD.
    /// See: RFC 7800 – Proof-of-Possession Key Semantics for JWTs - https://datatracker.ietf.org/doc/html/rfc7800
    /// </summary>
    public class ConfirmationInfo
    {
        /// <summary>
        /// JWK Thumbprint.
        /// This is the fixed-length hash identifying a specific public key.
        /// From: RFC 7638 – JSON Web Key (JWK) Thumbprint - https://chatgpt.com/c/689f93dd-b46c-8331-b74f-0fd0f0955f37#:~:text=RFC%207638%20%E2%80%93%20JSON%20Web%20Key%20(JWK)%20Thumbprint
        /// </summary>
        public string jkt { get; set; }


        /// <summary>
        /// Public constructor, that baselines all values.
        /// </summary>
        public ConfirmationInfo()
        {
            this.jkt = string.Empty;
        }
    }
}
