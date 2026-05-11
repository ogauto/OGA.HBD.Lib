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
        /// For a representative set of EC P-256 keypairs, confirm that
        ///   HBD_Signer.ComputePkthumbFromSpkiPem(spkiPemPath)
        /// and
        ///   SpkiFileThumbprintProvider(spkiPemPath).GetLocalPkthumb()
        /// produce byte-identical thumbprints.
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

                // Write the PEM to a temp file so both code paths read it identically...
                string tempPath = Path.Combine(this._testfolder, $"spki-{Guid.NewGuid()}.pem");
                File.WriteAllText(tempPath, pem);

                // Signer-side computation...
                string signerSide = HBD_Signer.ComputePkthumbFromSpkiPem(tempPath);

                // Verifier-side computation...
                var provider = new SpkiFileThumbprintProvider(tempPath);
                string verifierSide = provider.GetLocalPkthumb();

                if(string.IsNullOrWhiteSpace(signerSide))
                    Assert.Fail($"Signer-side thumbprint was blank for sample {i}.");
                if(string.IsNullOrWhiteSpace(verifierSide))
                    Assert.Fail($"Verifier-side thumbprint was blank for sample {i}.");
                if(!string.Equals(signerSide, verifierSide, StringComparison.Ordinal))
                    Assert.Fail($"Encoder disagreement on sample {i}: signer='{signerSide}', verifier='{verifierSide}'.");
            }
        }
    }
}
