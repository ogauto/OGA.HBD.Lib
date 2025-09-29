using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace OGA.HBD.Model
{
    /// <summary>
    /// Represents a Host Bootstrap Document.
    /// These are used to attest an instance/host within a cluster.
    /// </summary>
    public class Host_BootstrapDoc
    {
        /// <summary>
        /// Names the type of Host Bootstrap Document doc.
        /// Usually, 'hbd'
        /// This is identified as a top-level property, so deserialization can identify the needed class type.
        /// </summary>
        public string docType { get; set; }
        /// <summary>
        /// Identifies the version of the doc type.
        /// This is identified as a top-level property, so deserialization can identify the needed class type.
        /// </summary>
        public int version { get; set; }

        /// <summary>
        /// Full name of the issuer that signed the HBD.
        /// </summary>
        public string iss { get; set; }
        /// <summary>
        /// Unix timestamp when the HBD was signed.
        /// </summary>
        public long iat { get; set; }
        /// <summary>
        /// Unix timestamp when the HBD expires.
        /// </summary>
        public long exp { get; set; }

        /// <summary>
        /// Stores the host/instance data of the document.
        /// </summary>
        public HostInfo_V1 hostInfo { get; set; }

        /// <summary>
        /// Holds the confirmation info for the document signature.
        /// This contains any JWK thumbprint that authenticates the VM as the instance the HBD belongs to.
        /// </summary>
        public ConfirmationInfo? cnf { get; set; }


        /// <summary>
        /// Public constructor, that baselines all values.
        /// </summary>
        public Host_BootstrapDoc()
        {
            this.docType = "hbd";
            this.version = 1;

            this.iss = string.Empty;
            this.iat = 0;
            this.exp = 0;

            this.hostInfo = new HostInfo_V1();
            this.cnf = null;
        }
    }
}
