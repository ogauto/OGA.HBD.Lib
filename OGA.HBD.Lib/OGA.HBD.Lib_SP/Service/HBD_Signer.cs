using Jose;
using Microsoft.IdentityModel.Tokens;
using OGA.HBD.Helpers;
using OGA.HBD.Model;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OGA.HBD.Service
{
    /// <summary>
    /// This is the signing logic for a Host Bootstrap Document.
    /// It will create the JWS from a given HBD instance.
    /// Using this class, requires the Nuget package: dotnet add package jose-jwt
    /// </summary>
    public class HBD_Signer
    {
        #region Private Fields

        static private readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = null, // keep your exact names
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never
        };

        #endregion


        #region Public Methods

        /// <summary>
        /// Create a compact JWS (ES256) for the given Host Bootstrap Document; header includes alg/kid/typ.
        /// The caller is responsible for populating iat and exp on the payload; the signer rejects
        /// HBDs whose iat or exp is zero/negative, or whose exp is not strictly greater than iat.
        /// (See FR-03 and KD-03 in SPEC.md.)
        /// </summary>
        /// <param name="payload">The HBD to sign. <c>iat</c> and <c>exp</c> must be populated; see KD-03.</param>
        /// <param name="issuerPrivateKey">The issuer's ECDsa private key.</param>
        /// <param name="kid">The kid to embed in the JWS header.</param>
        /// <returns>
        /// A tuple of (res, val) where val is the JWS compact serialization when successful.
        /// Result codes:
        ///   <list type="bullet">
        ///     <item><description><c>1</c> — success; val contains the signed JWS.</description></item>
        ///     <item><description><c>-1</c> — null or blank required argument (payload, issuerPrivateKey, or kid).</description></item>
        ///     <item><description><c>-2</c> — caught exception during signing; val is null.</description></item>
        ///     <item><description><c>-3</c> — invalid iat or exp (zero, negative, or exp not strictly greater than iat).</description></item>
        ///   </list>
        /// </returns>
        static public (int res, string? val) CreateBootstrapJws(Host_BootstrapDoc payload, ECDsa issuerPrivateKey, string kid)
        {
            try
            {
                // Validate givens...
                if(payload == null)
                {
                    return (-1, null);
                }
                if(issuerPrivateKey == null)
                {
                    return (-1, null);
                }
                if(string.IsNullOrWhiteSpace(kid))
                {
                    return (-1, null);
                }

                // Sanity-check the caller-provided lifetime claims (FR-03 / KD-03)...
                if(payload.iat <= 0)
                {
                    return (-3, null);
                }
                if(payload.exp <= 0)
                {
                    return (-3, null);
                }
                if(payload.exp <= payload.iat)
                {
                    return (-3, null);
                }

                // Compose the jws header...
                var header = new Dictionary<string, object>
                {
                    ["alg"] = "ES256",
                    ["kid"] = kid,
                    ["typ"] = "JWT"
                };

                // We serialize ourselves, to ensure the same bytes are signed that you’d expect...
                var json = JsonSerializer.Serialize(payload, JsonOptions);

                // Sign the jws...
                var dat = JWT.Encode(json, issuerPrivateKey, JwsAlgorithm.ES256, extraHeaders: header);

                // Return the signed jws...
                return (1, dat);
            }
            catch(Exception e)
            {
                return (-2, null);
            }
        }

        /// <summary>
        /// Compute base64url(SHA-256(SPKI)) from a PEM "PUBLIC KEY" file (SubjectPublicKeyInfo).
        /// Use this to fill cnf.pkthumb when binding an HBD to a host's binding key
        /// (dev: software/SSH-derived key; prod: vTPM-backed key).
        /// </summary>
        static public string ComputePkthumbFromSpkiPem(string spkiPemPath)
        {
            var pem = File.ReadAllText(spkiPemPath);
            var spki = PEMConverter.ExtractKey_fromPem(pem, "PUBLIC KEY");
            var hash = SHA256.HashData(spki);
            return Base64UrlEncoder.Encode(hash);
        }

        /// <summary>
        /// Produce a minimal ES256 JWKS entry for distribution to verifiers.
        /// </summary>
        static public string ExportJwks(ECDsa issuerPrivateKey, string kid)
        {
            // Build JWK (public only). Parameters come from the curve key.
            var pubParams = issuerPrivateKey.ExportParameters(false);
            var x = Base64UrlEncoder.Encode(pubParams.Q.X);
            var y = Base64UrlEncoder.Encode(pubParams.Q.Y);

            var jwk = new
            {
                keys = new object[]
                {
                    new Dictionary<string, object>
                    {
                        ["kty"] = "EC",
                        ["crv"] = "P-256",
                        ["x"]   = x,
                        ["y"]   = y,
                        ["use"] = "sig",
                        ["alg"] = "ES256",
                        ["kid"] = kid
                    }
                }
            };
            return JsonSerializer.Serialize(jwk, JsonOptions);
        }

        #endregion
    }
}
