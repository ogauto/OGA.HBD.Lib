using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OGA.HBD.Model
{
    /// <summary>
    /// Determines the level of verification to be performed.
    /// </summary>
    public enum VerificationMode
    {
        ParseOnly = 0,
        VerifySignature = 1,
        VerifySignatureAndCnfWarn = 2,
        EnforceAll = 3
    }
}
