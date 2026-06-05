using Microsoft.VisualStudio.TestTools.UnitTesting;
using OGA.HBD.Helpers;
using OGA.HBD.Lib_Tests.Helpers;
using OGA.HBD.Service;
using System;
using System.IO;
using System.Security.Cryptography;

namespace OGA.HBD.Lib_Tests
{
    /// <summary>
    /// Regression tests for OI-16 / OI-19 — the signer-side and verifier-side base64url encoders
    /// must produce byte-identical thumbprints for the same SPKI input.
    /// </summary>
    [TestClass]
    public class EncoderAgreement_Tests : Test_TestBase
    {
        #region Setup

        [ClassInitialize]
        static public void TestClass_Setup(TestContext context)
        {
            TestClassBase_Setup(context);
        }

        [ClassCleanup]
        static public void TestClass_Cleanup()
        {
            TestClassBase_Cleanup();
        }

        [TestInitialize]
        override public void Setup()
        {
            base.Setup();
        }

        [TestCleanup]
        override public void TearDown()
        {
        }

        #endregion


        /// <summary>
        /// For a representative set of EC P-256 keypairs, confirm that every SPKI-thumbprint code path
        /// in the library produces byte-identical output for the same key. This locks the
        /// single-source-of-truth invariant: the canonical <see cref="SpkiThumbprint"/> utility, the
        /// signer-side <c>HBD_Signer.ComputePkthumbFromSpkiPem</c>, the verifier-side
        /// <c>SpkiFileThumbprintProvider.GetLocalPkthumb</c>, and the issuer <c>kid</c> from
        /// <c>ES256_Issuer.Get_IssuerProperties</c> must all agree.
        /// </summary>
        [TestMethod]
        public void Test_SignerAndVerifier_AgreeOnPkthumb()
        {
            // Generate a handful of fresh keys so the test exercises real variation in SPKI bytes.
            const int sampleCount = 5;

            for(int i = 0; i < sampleCount; i++)
            {
                // Materialize a fresh EC P-256 keypair...
                using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                byte[] spki = ecdsa.ExportSubjectPublicKeyInfo();
                string pem = PEMConverter.CreatePem("PUBLIC KEY", spki);

                // Write the PEM to a temp file so the file-based code paths read it identically...
                string tempPath = Path.Combine(this._testfolder, $"spki-{Guid.NewGuid()}.pem");
                File.WriteAllText(tempPath, pem);

                // Canonical utility — the single source of truth, exercised via each overload...
                string canonicalBytes = SpkiThumbprint.Compute(spki);
                string canonicalKey   = SpkiThumbprint.ComputeFromPublicKey(ecdsa);
                string canonicalPem   = SpkiThumbprint.ComputeFromPem(pem);

                // Signer-side computation...
                string signerSide = HBD_Signer.ComputePkthumbFromSpkiPem(tempPath);

                // Verifier-side computation...
                var provider = new SpkiFileThumbprintProvider(tempPath);
                string verifierSide = provider.GetLocalPkthumb();

                // Issuer kid — also an SPKI thumbprint, must share the same formula...
                string issuerKid = ES256_Issuer.Get_IssuerProperties(ecdsa).Kid;

                // The canonical value is the reference all other paths must match...
                string expected = canonicalBytes;

                if(string.IsNullOrWhiteSpace(expected))
                    Assert.Fail($"Canonical thumbprint was blank for sample {i}.");

                var paths = new (string name, string value)[]
                {
                    ("SpkiThumbprint.ComputeFromPublicKey", canonicalKey),
                    ("SpkiThumbprint.ComputeFromPem",       canonicalPem),
                    ("HBD_Signer.ComputePkthumbFromSpkiPem", signerSide),
                    ("SpkiFileThumbprintProvider.GetLocalPkthumb", verifierSide),
                    ("ES256_Issuer.kid", issuerKid),
                };

                foreach(var (name, value) in paths)
                {
                    if(string.IsNullOrWhiteSpace(value))
                        Assert.Fail($"Thumbprint from {name} was blank for sample {i}.");
                    if(!string.Equals(expected, value, StringComparison.Ordinal))
                        Assert.Fail($"Thumbprint disagreement on sample {i}: canonical='{expected}', {name}='{value}'.");
                }
            }
        }
    }
}
