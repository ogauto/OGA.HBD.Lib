using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OGA.HBD.Model
{
    /// <summary>
    /// Simple POCO used when retrieving data from a JWS.
    /// This is not used for generation... just for retrieval.
    /// </summary>
    public class JWS_Header
    {
        /// <summary>
        /// Algorithm used to sign.
        /// </summary>
        public string alg { get; set; }

        /// <summary>
        /// Key id used for sigining.
        /// </summary>
        public string kid { get; set; }

        /// <summary>
        /// Token type: JWS, JWT, etc...
        /// </summary>
        public string typ { get; set; }

        /// <summary>
        /// Public Constructor
        /// </summary>
        public JWS_Header()
        {
            this.alg = string.Empty;
            this.kid = string.Empty;
            this.typ = string.Empty;
        }
    }
}
