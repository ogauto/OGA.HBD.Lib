using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OGA.HBD.Helpers
{
    /// <summary>
    /// This class consolidates the PEM conversion methods that are used across signing, verification, and handling.
    /// </summary>
    static public class PEMConverter
    {
        /// <summary>
        /// Extract key from PEM
        /// </summary>
        /// <param name="pem"></param>
        /// <param name="label"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        static public byte[] ExtractKey_fromPem(string pem, string label)
        {
            var header = $"-----BEGIN {label}-----";
            var footer = $"-----END {label}-----";

            var start = pem.IndexOf(header, StringComparison.Ordinal);

            var end = pem.IndexOf(footer, StringComparison.Ordinal);

            if (start < 0 || end < 0 || end <= start)
                throw new InvalidOperationException("Invalid PEM");

            var b64 = pem.Substring(start + header.Length, end - (start + header.Length))
                        .Replace("\r", "").Replace("\n", "").Trim();

            return Convert.FromBase64String(b64);
        }

        /// <summary>
        /// Convert the given key to PEM format...
        /// </summary>
        /// <param name="label"></param>
        /// <param name="der"></param>
        /// <returns></returns>
        static public string CreatePem(string label, byte[] der)
        {
            var res = $"-----BEGIN {label}-----\n{Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)}\n-----END {label}-----\n";
            return res;
        }

        /// <summary>
        /// Attempts to load a private key pem file, and return the pkcs#8 content as byte[].
        /// </summary>
        /// <param name="pemfilepath"></param>
        /// <returns></returns>
        static public (int res, byte[]? pkcs8) Load_PrivatePEMFile_toPKCS8(string pemfilepath)
        {
            string data = "";

            // Load the file...
            try
            {
                data = System.IO.File.ReadAllText(pemfilepath);
                if (string.IsNullOrWhiteSpace(data))
                    return (-1, null);
            }
            catch(Exception e)
            {
                return (-2, null);
            }

            // Fix the content...
            var scrubbed = "";
            try
            {
                scrubbed = System.Text.RegularExpressions.Regex.Replace(data, "-----(BEGIN|END) PRIVATE KEY-----|\\s", "");
                if (string.IsNullOrWhiteSpace(scrubbed))
                    return (-1, null);
            }
            catch(Exception e)
            {
                return (-2, null);
            }

            // Convert and return...
            try
            {
                var pkcs8 = Convert.FromBase64String(scrubbed);
                return (1, pkcs8);
            }
            catch(Exception e)
            {
                return (-2, null);
            }
        }
    }
}
