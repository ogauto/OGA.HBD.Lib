using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OGA.HBD.Helpers
{
    /// <summary>
    /// Simple class that will manage an in-memory ES256 issuer.
    /// This can be used to generate a new key instance, and all the ancillary parts (public key, kid, etc).
    /// This class can create an issuer from a stored private key, stored as pem file.
    /// </summary>
    static public class ES256_Issuer
    {
        /// <summary>
        /// Call this method to generate a net-new issuer.
        /// The following things are returned by this call:
        ///    keyinstance - is the in-memory ECDSA object, that the caller may use, to work with the key.
        ///    Kid - is the identifier that you'll put in a JWS header.
        ///    JWKSJson - is the JWKS in JSON format, containing the public key and its kid.
        ///    PublicPem - the public portion of the key, derived from the private key.
        ///    PrivatePem - the only secret (PKCS#8 private key).
        /// If you want to persist the generated key, save the privatePEM and the kid (as metadata of the private key).
        /// </summary>
        /// <returns></returns>
        static public (ECDsa keyinstance, string Kid, string JWKSJson, string PublicPem, string PrivatePem) Create_NewIssuer()
        {
            // Create a new ES256 key...
            using var tmp = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            // Clone the key, so the caller can dispose of it, independently...
            var ecdsa = ECDsa.Create();
            ecdsa.ImportParameters(tmp.ExportParameters(true));

            // Get properties for the issuer instance...
            var props = Get_IssuerProperties(ecdsa);

            // Return everything to the caller...
            return (ecdsa, props.Kid, props.Jwks, props.PublicPem, props.PrivatePem);
        }

        /// <summary>
        /// Retrieve properties of the given issuer instance.
        /// The following things are returned by this call:
        ///    kid - is the identifier that you'll put in a JWS header.
        ///    jwks - is a JSON wrapper of the public key and its kid.
        ///    publicPEM - the public portion of the key, derived from the private key.
        ///    privatePEM - the only secret (PKCS#8 private key).
        /// </summary>
        /// <param name="ecdsa"></param>
        /// <returns></returns>
        static public (string Kid, string Jwks, string PublicPem, string PrivatePem) Get_IssuerProperties(ECDsa ecdsa)
        {
            // Get the public key data...
            byte[] spki = ecdsa.ExportSubjectPublicKeyInfo();
            // Get the private key data...
            byte[] pkcs8 = ecdsa.ExportPkcs8PrivateKey();

            // Create a URL-safe hash of the public key, that will be the key id...
            var kid = Base64Url(SHA256.HashData(spki));

            // Retrieve the public key material...
            var p = ecdsa.ExportParameters(false);

            // Create the key output...
            var jwks = System.Text.Json.JsonSerializer.Serialize(
                new {
                        keys = new[] { new { kty="EC", crv="P-256", x=Base64Url(p.Q.X), y=Base64Url(p.Q.Y), use="sig", alg="ES256", kid } }
                    });

            // Return properties to the caller...
            return (kid, jwks, PEMConverter.CreatePem("PUBLIC KEY", spki), PEMConverter.CreatePem("PRIVATE KEY", pkcs8));
        }

        /// <summary>
        /// Attempts to retrieve the private key of an ECDsa instance, in PKCS#8 format.
        /// </summary>
        /// <param name="ecdsa"></param>
        /// <returns></returns>
        static public (int res, byte[]? pkcs8) Get_PrivKeyPKCS8_from_ECDsaInstance(ECDsa ecdsa)
        {
            try
            {
                if (ecdsa == null)
                    return (-1, null);

                var bb = ecdsa.ExportPkcs8PrivateKey();

                return (1, bb);
            }
            catch(Exception)
            {
                return (-2, null);
            }
        }

        /// <summary>
        /// Attempts to create an ECDsa instance from the bytes of a pkcs#8 private key.
        /// </summary>
        /// <param name="pkcs8"></param>
        /// <returns></returns>
        static public (int res, ECDsa? keyinstance) CreateIssuer_fromPrivatePKCS8(byte[] pkcs8)
        {
            bool success = false;

            ECDsa instance = null;
            try
            {
                instance = ECDsa.Create();
                instance.ImportPkcs8PrivateKey(pkcs8, out _);

                success = true;
                return (1, instance);
            }
            catch(Exception e)
            {
                return (-2, null);
            }
            finally
            {
                if(!success)
                {
                    try
                    {
                        instance?.Dispose();
                    }
                    catch (Exception) { }
                }
            }
        }

        /// <summary>
        /// Load an ES256 issuer private key from PKCS#8 PEM.
        /// </summary>
        static public (int res, ECDsa? issuer) LoadIssuer_fromPrivateKeyPEMPkcs8(string pemPath)
        {
            var resload = PEMConverter.Load_PrivatePEMFile_toPKCS8(pemPath);
            if(resload.res != 1 || resload.pkcs8 == null)
                return (-1, null);

            var rescreate = CreateIssuer_fromPrivatePKCS8(resload.pkcs8);
            if(rescreate.res != 1 || rescreate.keyinstance == null)
                return (-1, null);

            return (1, rescreate.keyinstance);
        }

        /// <summary>
        /// Helper method that will create the base64 output of an ES256 key...
        /// </summary>
        /// <param name="b"></param>
        /// <returns></returns>
        static private string Base64Url(byte[] b)
        {
            var s = Convert.ToBase64String(b).TrimEnd('=').Replace('+','-').Replace('/','_');
            return s;
        }
    }
}
