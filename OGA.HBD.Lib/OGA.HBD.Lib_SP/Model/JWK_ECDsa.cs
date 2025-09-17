using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;

namespace OGA.HBD.Model
{
    /// <summary>
    /// Holds the information for a single Json Web Key of an ECDsa.
    /// Normally, you will see instances of this in a keyring called JWKS.
    /// </summary>
    public class JWK_ECDsa
    {
        /// <summary>
        /// Key type name.
        /// </summary>
        public string kty { get; set; }
        /// <summary>
        /// This is the name of the curve used by the key.
        /// </summary>
        public string crv { get; set; }
        /// <summary>
        /// Holds the x-component of the public key's Q parameter.
        /// </summary>
        public string x { get; set; }
        /// <summary>
        /// Holds the y-component of the public key's Q parameter.
        /// </summary>
        public string y { get; set; }
        /// <summary>
        /// Defines the usage for the key.
        /// </summary>
        public string use { get; set; }
        /// <summary>
        /// Holds the algorithm name of the key.
        /// </summary>
        public string alg { get; set; }
        /// <summary>
        /// Key Id, used to lookup a public key, or to track a signing key.
        /// </summary>
        public string kid { get; set; }

        /// <summary>
        /// Public Contstructor
        /// </summary>
        public JWK_ECDsa()
        {
            kty = string.Empty;
            crv = string.Empty;
            x = string.Empty;
            y = string.Empty;
            use = string.Empty;
            alg = string.Empty;
            kid = string.Empty;
        }
    }
}
