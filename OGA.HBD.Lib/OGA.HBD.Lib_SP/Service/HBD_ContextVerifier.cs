using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OGA.HBD.Helpers;
using OGA.HBD.Model;

namespace OGA.HBD.Service
{
    /// <summary>
    /// Client-side logic for verifying and reading a Host Bootstrap Document.
    /// dotnet add package Microsoft.IdentityModel.JsonWebTokens
    /// dotnet add package Microsoft.IdentityModel.Tokens
    /// </summary>
    static public class HBD_ContextVerifier
    {
        /// <summary>
        /// Name that the JWS token header type should be.
        /// </summary>
        static public string JWS_Header_TypeName { get; set; } = "JWT";

        /// <summary>
        /// Document name for a Host Bootstrap Document.
        /// </summary>
        static public string RequiredDocType { get; set; } = "hbd";


        #region Public Methods

        /// <summary>
        /// Verifies (per mode) and returns the parsed payload JSON.
        /// This will perform the following checks of the token:
        ///     Contains a header (with algo, token type, and kid)
        ///     Token Type is correct
        ///     Contains an algorithm that we can use to verify
        ///     Contains 
        /// It must be passed a key retrieval callback, to retrieve the required key for verification (if needed).
        /// </summary>
        /// <param name="jwsCompact"></param>
        /// <param name="versettings"></param>
        /// <returns></returns>
        static public BootstrapDocResult Verify(string jwsCompact, VerificationSettings versettings)
        {
            if(string.IsNullOrWhiteSpace(jwsCompact))
            {
                return Fail("Given JWS is blank.");
            }

            var trimmed = jwsCompact.Trim();

            var handler = new JsonWebTokenHandler();
            JsonWebToken? token = null;
            string? iss = null;

            // Convert the received JWS to a token...
            try
            {
                token = handler.ReadJsonWebToken(trimmed);
                if(token == null)
                {
                    return Fail("Failed to recover token from JWS.");
                }
            }
            catch(Exception e)
            {
                if (versettings.Mode == VerificationMode.ParseOnly)
                    return Fail("ParseOnly: unable to parse JWS: " + e.Message);

                return Fail("Unable to parse JWS: " + e.Message);
            }


            // Extract any JWS header data...
            var reshdr = Extract_TokenHeader(token);
            if(reshdr.res != 1 || reshdr.data == null)
            {
                // Failed to extract token header.
                // Must be malformed.
                return Fail("Failed to recover token header.");
            }
            
            // Check that it's a JWS...
            if(reshdr.data.typ != JWS_Header_TypeName)
            {
                return Fail("Incorrect Token type.");
            }

            // Convert the payload to a JsonDocument...
            var respayload = ParsePayload(token!);
            if(respayload.res != 1 || respayload.data == null)
            {
                return Fail("Invalid Payload.");
            }

            // Extract the doc type from its payload...
            var respyld = Extract_DocInfo(respayload.data);
            if(respyld.res != 1 || string.IsNullOrWhiteSpace(respyld.doctype) || respyld.ver < 0)
            {
                // Failed to extract doctype and version.
                // Must be malformed.
                return Fail("Failed to recover payload doctype and version.");
            }


            // Check if it's an HBD...
            if(!StringEquals(respyld.doctype, RequiredDocType))
            {
                // Payload is not an HBD.
                return Fail("Token payload is not an HBD.");
            }


            // Verify its version is compatible...
            if(!HBDVersion_IsValid(respyld.ver))
            {
                // HBD version is not valid.
                return Fail("Invalid HBD version.");
            }

            // Retrieve issuer...
            try
            {
                // Get the issuer name...
                // may be null
                iss = token.Issuer;

                if(string.IsNullOrWhiteSpace(iss))
                {
                    return Fail("Invalid Issuer.");
                }
            }
            catch(Exception e)
            {
                return Fail("Failed to get issuer.");
            }

            // Regardless of verification level, we always check the sanity of the issuance and expiry times.
            var resbpc = BasicPayloadChecks(respayload.data, versettings);
            if(resbpc.res != 1)
            {
                return Fail("Failed to check timestamps.");
            }

            // END OF OBLIGATORY CHECKS.


            // If we are to only parse the token, we can stop here...
            // ParseOnly: just decode payload (no signature validation).
            if (versettings.Mode == VerificationMode.ParseOnly)
            {
                return new BootstrapDocResult
                {
                    Ok = true,
                    FailureReason = "",
                    Kid = reshdr.data.kid ?? "",
                    Iss = iss,
                    Payload = respayload.data,
                    SignatureVerified = false,
                    CnfChecked = false,
                    CnfMatched = false
                };
            }
            
            // END OF PARSE ONLY.
            // From here down, the token must be verified.


            // Check that it was signed...
            try
            {
                if(!token.IsSigned)
                {
                    // The token was not signed.
                    // We cannot verify its signature.
                    return Fail("Token is not signed.");
                }
            }
            catch (Exception)
            {
                return Fail("Token is not signed.");
            }
            // The token was signed.
            // We will attempt to verify its signature.


            // Check the token is signed by an algo that we can verify...
            if(!CanUse_Algo(reshdr.data.alg))
            {
                // The algorithm is not one we can verify.
                return Fail($"Unknown signing algorithm {(reshdr.data.alg ?? "")}.");
            }


            // To verify the token, identify and retrieve the public key...
            // For this, we leverage the given callback.
            if(versettings.KeyRetrievalCallback == null)
            {
                // The key retrieval callback was not set.
                return Fail($"Key retrieval callback was not set.");
            }

            // Attempt to get the verification key...
            // Wrap the call in a try-catch, in case the delegate throws.
            SecurityKey? vkey = null;
            try
            {
                // Call the key retrieval callback from settings...
                var reskrc = versettings.KeyRetrievalCallback(reshdr.data.kid);
                if(reskrc.res != 1 || reskrc.data == null)
                {
                    // Failed to retrieve verification key.
                    return Fail($"Failed to retrieve verification key.");
                }

                vkey = reskrc.data;
            }
            catch (Exception e)
            {
                // The key retrieval callback threw an exception.
                return Fail($"The key retrieval callback threw an exception.");
            }
            // If here, we have the verification key.


            // Attempt to verify the token...
            {
                // Create the val parameter instance...
                var tvp = new TokenValidationParameters
                {
                    // Fail if not signed...
                    RequireSignedTokens = true,
                    // Don't worry about audience checks...
                    ValidateAudience = false,
                    // We expect to validate the issuer if a list was given...
                    ValidateIssuer = versettings.AllowedIssuers.Count > 0,
                    ValidIssuers = versettings.AllowedIssuers,
                    // We validate the issue and expiry timestamps if needed...
                    ValidateLifetime = versettings.ValidateLifetime,
                    // Pass in the signing key to verify with...
                    IssuerSigningKey = vkey
                };

                // Now, attempt to verify the token...
                var validation = handler.ValidateToken(trimmed, tvp);
                if (!validation.IsValid)
                {
                    return Fail("Signature validation failed: " + (validation.Exception?.Message ?? "invalid"));
                }
            }
            // If here, the token signature was verified.


            // Stop processing, if we were just to verify the signature...
            if (versettings.Mode == VerificationMode.VerifySignature)
            {
                return new BootstrapDocResult
                {
                    Ok = true,
                    FailureReason = "",
                    Kid = reshdr.data.kid ?? "",
                    Iss = iss,
                    Payload = respayload.data,
                    SignatureVerified = true,
                    CnfChecked = false,
                    CnfMatched = false
                };
            }
            // END OF VERIFICATION ONLY.
            // From here down, the CNF must be interrogated, to warn or enforce.


            // Attempt to recover the CNF property from the token...
            var (hasCnf, jkt) = TryReadCnfJkt(respayload.data);
            if (!hasCnf || string.IsNullOrWhiteSpace(jkt))
            {
                // Failed to get cnf or the jkt is empty.
                // For warn or enforce modes, we need the cnf.jkt.
                // So, we must fail, here.

                return Fail("cnf.jkt not found.");
            }
            // We have the jkt from the cnf property.
            // We can act to warn, or enforce its value.


            // Fail immediately, if checks require cnf warning or enforcement...
            // We're doing this, to know that we need to revisit the following block of code, to make it functional.
            if(versettings.Mode == VerificationMode.VerifySignatureAndCnfWarn ||
                versettings.Mode == VerificationMode.EnforceAll)
            {
                return Fail("Verification level set to check cnf.jkt, but logic is not yet defined.");
            }
            // FROM HERE DOWN, WE HAVE NOT YET REFINED THE LOGIC TO EVALUATE THE CNF.JKT PROPERTY.
            // FROM HERE DOWN, WE HAVE NOT YET REFINED THE LOGIC TO EVALUATE THE CNF.JKT PROPERTY.
            // FROM HERE DOWN, WE HAVE NOT YET REFINED THE LOGIC TO EVALUATE THE CNF.JKT PROPERTY.
            // FROM HERE DOWN, WE HAVE NOT YET REFINED THE LOGIC TO EVALUATE THE CNF.JKT PROPERTY.

            string localJkt;
            try { localJkt = versettings.LocalThumbprintProvider.GetLocalJktThumbprint(); }
            catch (Exception ex)
            {
                var warnOk = versettings.Mode == VerificationMode.VerifySignatureAndCnfWarn;
                return new BootstrapDocResult
                {
                    Ok = warnOk,
                    FailureReason = warnOk ? null : "Failed to compute local jkt: " + ex.Message,
                    Kid = reshdr.data.kid ?? "",
                    Iss = iss,
                    Payload = respayload.data,
                    SignatureVerified = true,
                    CnfChecked = true,
                    CnfMatched = false
                };
            }

            var matches = TimingSafeEquals(jkt!, localJkt);
            var finalOk = matches || versettings.Mode != VerificationMode.EnforceAll;

            return new BootstrapDocResult
            {
                Ok = finalOk,
                FailureReason = finalOk ? null : $"cnf.jkt mismatch (expected local {localJkt}, got {jkt})",
                Kid = reshdr.data.kid ?? "",
                Iss = iss,
                Payload = respayload.data,
                SignatureVerified = true,
                CnfChecked = true,
                CnfMatched = matches
            };
        }

        #endregion


        #region Private Methods

        /// <summary>
        /// Checks the given algorithm name, to make sure we can verify it.
        /// </summary>
        /// <param name="alg"></param>
        /// <returns></returns>
        static private bool CanUse_Algo(string alg)
        {
            if(string.IsNullOrWhiteSpace(alg)) return false;

            // Sanitize it...
            var algsanitized = alg.Trim().ToLower();

            // Check if it's ES256...
            if (algsanitized == "es256")
                return true;

            // Algorithm was not found.
            return false;
        }

        /// <summary>
        /// Creates a quick failure response.
        /// </summary>
        /// <param name="why"></param>
        /// <param name="sigOk"></param>
        /// <returns></returns>
        static BootstrapDocResult Fail(string why, bool sigOk = false)
        {
            var bd = new BootstrapDocResult()
            {
                Ok = false, FailureReason = why,
                SignatureVerified = sigOk, CnfChecked = false, CnfMatched = false
            };

            return bd;
        }

        /// <summary>
        /// Checks that the given HBD version is in range.
        /// </summary>
        /// <param name="ver"></param>
        /// <returns></returns>
        static private bool HBDVersion_IsValid(int ver)
        {
            // Lowest we can handle...
            if(ver < 1)
                return false;

            // Highest we can handle...
            if(ver > 1)
                return false;

            // Must be good.
            return true;
        }

        /// <summary>
        /// Retrieves the token header from a received JWS.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        private static (int res, JWS_Header? data) Extract_TokenHeader(JsonWebToken token)
        {
            // Get token header data...
            string? tokentype = null;
            string? alg = null;
            string? kid = null;

            try
            {
                // Get the token type...
                tokentype = token.Typ;
            }
            catch(Exception e)
            {
                return (-2, null);
            }
            try
            {
                // Get the algorithm used to sign it...
                alg = token.Alg;
            }
            catch(Exception e)
            {
                return (-2, null);
            }
            try
            {
                // Get the kid of the signing key...
                // may be null
                kid = token.Kid;
            }
            catch(Exception e)
            {
                return (-2, null);
            }

            // Return what we found...
            var data = new JWS_Header();
            data.typ = tokentype;
            data.alg = alg;
            data.kid = kid;
            return (1, data);
        }

        /// <summary>
        /// Retrieves the doctype and version from a given payload, in JsonDocument form.
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        private static (int res, string? doctype, int ver) Extract_DocInfo(JsonDocument payload)
        {
            var root = payload.RootElement;

            // docType (or doc_type)...
            if (!JsonDocument_Helpers.TryGetString(root, "docType", out string doctype))
            {
                // Failed to get doctype...
                return (-1, null, 0);
            }

            // Get the version...
            if (!JsonDocument_Helpers.TryGetInt32(root, "version", out int val))
            {
                // Failed to get version...
                return (-1, null, 0);
            }

            return (1, doctype, val);
        }

        /// <summary>
        /// Attempts to recover the JSON payload section of a JWS.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        static private (int res, JsonDocument? data) ParsePayload(JsonWebToken token)
        {
            try
            {
                var bytes = Base64UrlEncoder.DecodeBytes(token.EncodedPayload);

                var jd = JsonDocument.Parse(bytes);

                return (1, jd);
            }
            catch(Exception e)
            {
                return (-1, null);
            }
        }

        /// <summary>
        /// Performs basic timestamp checks on the document's issue and expiry times.
        /// Will verify the issue and expiry times, if settings demand it.
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="versettings"></param>
        /// <returns></returns>
        static private (int res, long iat, long exp, string why) BasicPayloadChecks(JsonDocument payload, VerificationSettings versettings)
        {
            var why = "";
            long iat = 0;
            long exp = 0;

            try
            {
                var root = payload.RootElement;

                // Retrieve the issue and expiry times, so the caller has them...
                if(!JsonDocument_Helpers.TryGetLong(root, "iat", out iat))
                {
                    why = $"Issue time not set.";
                    return (-1, 0, 0, why);
                }
                if(!JsonDocument_Helpers.TryGetLong(root, "exp", out exp))
                {
                    why = $"Expiry time not set.";
                    return (-1, 0, 0, why);
                }

                // Optional lifetime checks (iat/exp)...
                if (versettings.ValidateLifetime)
                {
                    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    var skew = (long)(versettings.ClockSkew?.TotalSeconds ?? 0);

                    if (now + skew < iat)
                    {
                        why = $"token not yet valid (now={now}, iat={iat})";
                        return (-1, 0, 0, why);
                    }
                    if (now - skew >= exp)
                    {
                        why = $"token expired (now={now}, exp={exp})";
                        return (-1, 0, 0, why);
                    }
                }

                return (1, iat, exp, "");
            }
            catch(Exception e)
            {
                why = "Failed to perform basic time checks";
                return (-2, 0, 0, why);
            }
        }

        static private (bool has, string? jkt) TryReadCnfJkt(JsonDocument payload)
        {
            var root = payload.RootElement;

            if (!root.TryGetProperty("cnf", out var cnf) || cnf.ValueKind == JsonValueKind.Null)
                return (false, null);

            if (!cnf.TryGetProperty("jkt", out var jktEl)) return (false, null);

            var jkt = jktEl.ValueKind == JsonValueKind.String ? jktEl.GetString() : null;

            return (jkt is { Length: > 0 }, jkt);
        }

        static private bool TimingSafeEquals(string a, string b)
        {
            var ab = System.Text.Encoding.ASCII.GetBytes(a);
            var bb = System.Text.Encoding.ASCII.GetBytes(b);
            if (ab.Length != bb.Length) return false;
            int diff = 0;
            for (int i = 0; i < ab.Length; i++) diff |= ab[i] ^ bb[i];
            return diff == 0;
        }

        static private bool StringEquals(string? a, string b) =>
            string.Equals(a, b, StringComparison.Ordinal);

        #endregion
    }
}

