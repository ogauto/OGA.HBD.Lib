using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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

        /// <summary>
        /// Convert a *string* PEM to unencrypted PKCS#8 DER (byte[]) when possible.
        /// Supports:
        ///   - BEGIN PRIVATE KEY                (PKCS#8, returned as-is)
        ///   - BEGIN ENCRYPTED PRIVATE KEY      (PKCS#8, decrypts if passphrase provided)
        ///   - BEGIN EC PRIVATE KEY             (SEC1, converts to PKCS#8)
        ///   - BEGIN RSA PRIVATE KEY            (PKCS#1, converts to PKCS#8)
        /// Returns:
        ///   ( 1, pkcs8 ) on success
        ///   (-1, null)  invalid/empty input or unsupported PEM label
        ///   (-2, null)  general parse/import/export failure
        ///   (-3, null)  OpenSSH private key (not supported here)
        ///   (-4, null)  Encrypted PKCS#8 but no passphrase provided
        /// </summary>
        static public (int res, byte[]? pkcs8) Load_PrivatePEMString_toPKCS8(string pem, string? passphrase = null)
        {
            if (string.IsNullOrWhiteSpace(pem))
                return (-1, null);

            // Normalize for detection
            string p = pem;

            bool Has(string label) => p.IndexOf($"-----BEGIN {label}-----", StringComparison.Ordinal) >= 0;

            try
            {
                // 1) Already PKCS#8 (unencrypted)
                if (Has("PRIVATE KEY") && !Has("ENCRYPTED PRIVATE KEY"))
                {
                    var der = ExtractKey_fromPem(pem, "PRIVATE KEY"); // PKCS#8
                    return (1, der);
                }

                // 2) Encrypted PKCS#8
                if (Has("ENCRYPTED PRIVATE KEY"))
                {
                    var encDer = ExtractKey_fromPem(pem, "ENCRYPTED PRIVATE KEY");
                    if (string.IsNullOrEmpty(passphrase))
                        return (-4, null);

                    // Try ECDSA first, then RSA
                    ReadOnlySpan<byte> pwd = Encoding.UTF8.GetBytes(passphrase);
                    // ECDSA
                    try
                    {
                        using var ecdsa = ECDsa.Create();
                        ecdsa.ImportEncryptedPkcs8PrivateKey(pwd, encDer, out _);
                        var pkcs8 = ecdsa.ExportPkcs8PrivateKey();
                        return (1, pkcs8);
                    }
                    catch { /* fall through */ }

                    // RSA
                    try
                    {
                        using var rsa = RSA.Create();
                        rsa.ImportEncryptedPkcs8PrivateKey(pwd, encDer, out _);
                        var pkcs8 = rsa.ExportPkcs8PrivateKey();
                        return (1, pkcs8);
                    }
                    catch { /* fall through */ }

                    return (-2, null);
                }

                // 3) SEC1 EC private key
                if (Has("EC PRIVATE KEY"))
                {
                    var sec1 = ExtractKey_fromPem(pem, "EC PRIVATE KEY");
                    using var ecdsa = ECDsa.Create();
                    ecdsa.ImportECPrivateKey(sec1, out _); // SEC1
                    var pkcs8 = ecdsa.ExportPkcs8PrivateKey();
                    return (1, pkcs8);
                }

                // 4) PKCS#1 RSA private key
                if (Has("RSA PRIVATE KEY"))
                {
                    var pkcs1 = ExtractKey_fromPem(pem, "RSA PRIVATE KEY");
                    using var rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(pkcs1, out _); // PKCS#1
                    var pkcs8 = rsa.ExportPkcs8PrivateKey();
                    return (1, pkcs8);
                }

                // 5) OpenSSH private key (unsupported here)
                if (Has("OPENSSH PRIVATE KEY"))
                {
                    // Convert externally: ssh-keygen -p -m PEM -f <keyfile>
                    return (-3, null);
                }

                // Unknown/unsupported PEM label
                return (-1, null);
            }
            catch
            {
                return (-2, null);
            }
        }

        /// <summary>
        /// Attempts to load a private key PEM file and return PKCS#8 DER.
        /// Now delegates to the string method above.
        /// </summary>
        static public (int res, byte[]? pkcs8) Load_PrivatePEMFile_toPKCS8(string pemfilepath, string? passphrase = null)
        {
            string data;
            try
            {
                data = System.IO.File.ReadAllText(pemfilepath);
                if (string.IsNullOrWhiteSpace(data))
                    return (-1, null);
            }
            catch
            {
                return (-2, null);
            }

            return Load_PrivatePEMString_toPKCS8(data, passphrase);
        }

        /// <summary>
        /// Convert a *string* public-key PEM to SPKI DER (byte[]).
        /// Supports:
        ///   - BEGIN PUBLIC KEY          (already SPKI) -> returned as-is
        ///   - BEGIN RSA PUBLIC KEY      (PKCS#1)       -> converted to SPKI
        /// Returns:
        ///   ( 1, spki ) on success
        ///   (-1, null) invalid/empty/unsupported
        ///   (-2, null) parse/import/export failure
        /// </summary>
        public static (int res, byte[]? spki) Load_PublicPEMString_toSPKI(string pem)
        {
            if (string.IsNullOrWhiteSpace(pem)) return (-1, null);

            bool Has(string label) => pem.IndexOf($"-----BEGIN {label}-----", StringComparison.Ordinal) >= 0;

            try
            {
                // Common case: already SubjectPublicKeyInfo
                if (Has("PUBLIC KEY") && !Has("RSA PUBLIC KEY"))
                {
                    var der = ExtractKey_fromPem(pem, "PUBLIC KEY"); // SPKI
                    return (1, der);
                }

                // Legacy RSA (PKCS#1) -> wrap to SPKI via RSA import/export
                if (Has("RSA PUBLIC KEY"))
                {
                    var pkcs1 = ExtractKey_fromPem(pem, "RSA PUBLIC KEY");
                    using var rsa = RSA.Create();
                    rsa.ImportRSAPublicKey(pkcs1, out _);
                    var spki = rsa.ExportSubjectPublicKeyInfo();
                    return (1, spki);
                }

                // Not a recognized public PEM (e.g., OpenSSH one-line "ssh-ed25519 AAAA...")
                // Convert those first with: ssh-keygen -e -m PKCS8 -f key.pub > key_spki.pem
                return (-1, null);
            }
            catch
            {
                return (-2, null);
            }
        }

        /// <summary>
        /// Read a public-key PEM file and return SPKI DER (byte[]).
        /// </summary>
        public static (int res, byte[]? spki) Load_PublicPEMFile_toSPKI(string path)
        {
            string data;
            try
            {
                data = System.IO.File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(data)) return (-1, null);
            }
            catch
            {
                return (-2, null);
            }
            return Load_PublicPEMString_toSPKI(data);
        }

    }
}
