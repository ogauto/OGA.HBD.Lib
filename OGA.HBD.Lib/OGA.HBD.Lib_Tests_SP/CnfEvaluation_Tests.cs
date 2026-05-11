using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OGA.HBD.Helpers;
using OGA.HBD.Lib_Tests.Helpers;
using OGA.HBD.Model;
using OGA.HBD.Service;
using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using static OGA.HBD.Service.VerificationSettings;

namespace OGA.HBD.Lib_Tests
{
    /// <summary>
    /// Tests for the cnf.pkthumb evaluation branches in HBD_ContextVerifier (Work Item 2),
    /// and the on-wire field-name check for the cnf.pkthumb rename (Work Item 1).
    /// </summary>
    [TestClass]
    public class CnfEvaluation_Tests : Test_TestBase
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


        #region Helpers

        /// <summary>
        /// Stub provider that returns a configured thumbprint.
        /// </summary>
        private sealed class FixedThumbprintProvider : ILocalKeyThumbprintProvider
        {
            private readonly string _thumb;
            public FixedThumbprintProvider(string thumb) => _thumb = thumb;
            public string GetLocalPkthumb() => _thumb;
        }

        /// <summary>
        /// Stub provider that always throws.
        /// </summary>
        private sealed class ThrowingThumbprintProvider : ILocalKeyThumbprintProvider
        {
            private readonly string _message;
            public ThrowingThumbprintProvider(string message) => _message = message;
            public string GetLocalPkthumb() => throw new InvalidOperationException(_message);
        }

        /// <summary>
        /// Convenience tuple: signs a fresh HBD with the given pkthumb (or null for none) and returns
        /// the JWS string plus a key-retrieval callback and issuer name suitable for verification.
        /// </summary>
        private (string jws, dKeyRetrievalCallback krcb, string iss) SignHbdWithPkthumb(string? pkthumb)
        {
            var (issuerKey, kid, jwksjson, _, _) = ES256_Issuer.Create_NewIssuer();

            var jwkset = new JsonWebKeySet(jwksjson);
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);

            var hbd = this.Generate_ValidHostBootstrapDocument();
            if(pkthumb != null)
            {
                hbd.cnf = new ConfirmationInfo { pkthumb = pkthumb };
            }

            var ressign = HBD_Signer.CreateBootstrapJws(hbd, issuerKey, kid);
            if(ressign.res != 1 || string.IsNullOrWhiteSpace(ressign.val))
                Assert.Fail("Signing failed.");

            dKeyRetrievalCallback krcb = (k) =>
            {
                if(!trustedpublickeys.TryGetValue(kid, out var key))
                    return (-1, null);
                return (1, key);
            };

            return (ressign.val!, krcb, hbd.iss);
        }

        #endregion


        #region Wire Format Tests (Work Item 1)

        /// <summary>
        /// Confirms a signed HBD's decoded JSON payload uses the "pkthumb" key (not "jkt").
        /// </summary>
        [TestMethod]
        public void Test_PkthumbField_OnWire()
        {
            var (jws, _, _) = this.SignHbdWithPkthumb("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

            // JWS compact form: header.payload.signature -- decode the middle part.
            var parts = jws.Split('.');
            if(parts.Length != 3)
                Assert.Fail("JWS did not have three compact-serialization parts.");

            var payloadBytes = Base64UrlEncoder.DecodeBytes(parts[1]);
            using var jd = JsonDocument.Parse(payloadBytes);

            if(!jd.RootElement.TryGetProperty("cnf", out var cnfEl))
                Assert.Fail("Decoded payload missing 'cnf'.");

            if(!cnfEl.TryGetProperty("pkthumb", out _))
                Assert.Fail("Decoded payload's 'cnf' is missing 'pkthumb'.");

            if(cnfEl.TryGetProperty("jkt", out _))
                Assert.Fail("Decoded payload still carries the legacy 'jkt' field.");
        }

        #endregion


        #region Warn Mode Tests (Work Item 2)

        [TestMethod]
        public void Test_VerifySignatureAndCnfWarn_Match()
        {
            var thumb = "MATCHEDTHUMB____________________________0";
            var (jws, krcb, iss) = this.SignHbdWithPkthumb(thumb);

            var settings = new VerificationSettings
            {
                Mode = VerificationMode.VerifySignatureAndCnfWarn,
                AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { iss },
                LocalThumbprintProvider = new FixedThumbprintProvider(thumb),
                KeyRetrievalCallback = krcb,
                ValidateLifetime = false,
            };

            var res = HBD_ContextVerifier.Verify(jws, settings);
            if(res == null) Assert.Fail("Null result.");
            if(!res.Ok) Assert.Fail("Expected Ok=true on match.");
            if(!res.CnfChecked) Assert.Fail("Expected CnfChecked=true.");
            if(!res.CnfMatched) Assert.Fail("Expected CnfMatched=true.");
            if(!res.SignatureVerified) Assert.Fail("Expected SignatureVerified=true.");
        }

        [TestMethod]
        public void Test_VerifySignatureAndCnfWarn_Mismatch()
        {
            var hbdThumb = "HBDTHUMB________________________________0";
            var localThumb = "LOCALTHUMB______________________________0";
            var (jws, krcb, iss) = this.SignHbdWithPkthumb(hbdThumb);

            var settings = new VerificationSettings
            {
                Mode = VerificationMode.VerifySignatureAndCnfWarn,
                AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { iss },
                LocalThumbprintProvider = new FixedThumbprintProvider(localThumb),
                KeyRetrievalCallback = krcb,
                ValidateLifetime = false,
            };

            var res = HBD_ContextVerifier.Verify(jws, settings);
            if(res == null) Assert.Fail("Null result.");
            if(!res.Ok) Assert.Fail("Warn mode should return Ok=true even on mismatch.");
            if(!res.CnfChecked) Assert.Fail("Expected CnfChecked=true.");
            if(res.CnfMatched) Assert.Fail("Expected CnfMatched=false.");
            if(string.IsNullOrWhiteSpace(res.FailureReason))
                Assert.Fail("Expected FailureReason populated on mismatch.");
            if(!res.FailureReason!.Contains("pkthumb"))
                Assert.Fail("Expected FailureReason to mention pkthumb.");
        }

        [TestMethod]
        public void Test_VerifySignatureAndCnfWarn_ProviderThrows()
        {
            var (jws, krcb, iss) = this.SignHbdWithPkthumb("THUMB___________________________________0");

            var settings = new VerificationSettings
            {
                Mode = VerificationMode.VerifySignatureAndCnfWarn,
                AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { iss },
                LocalThumbprintProvider = new ThrowingThumbprintProvider("disk-unreadable"),
                KeyRetrievalCallback = krcb,
                ValidateLifetime = false,
            };

            var res = HBD_ContextVerifier.Verify(jws, settings);
            if(res == null) Assert.Fail("Null result.");
            if(!res.Ok) Assert.Fail("Warn mode should return Ok=true even when the provider throws.");
            if(!res.CnfChecked) Assert.Fail("Expected CnfChecked=true.");
            if(res.CnfMatched) Assert.Fail("Expected CnfMatched=false.");
            if(string.IsNullOrWhiteSpace(res.FailureReason))
                Assert.Fail("Expected FailureReason populated when provider throws.");
            if(!res.FailureReason!.Contains("disk-unreadable"))
                Assert.Fail("Expected FailureReason to surface the exception message.");
        }

        [TestMethod]
        public void Test_VerifySignatureAndCnfWarn_MissingCnf()
        {
            // No cnf populated on the HBD...
            var (jws, krcb, iss) = this.SignHbdWithPkthumb(null);

            var settings = new VerificationSettings
            {
                Mode = VerificationMode.VerifySignatureAndCnfWarn,
                AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { iss },
                LocalThumbprintProvider = new FixedThumbprintProvider("any"),
                KeyRetrievalCallback = krcb,
                ValidateLifetime = false,
            };

            var res = HBD_ContextVerifier.Verify(jws, settings);
            if(res == null) Assert.Fail("Null result.");
            if(res.Ok) Assert.Fail("Missing cnf should fail in Warn mode.");
            if(string.IsNullOrWhiteSpace(res.FailureReason)) Assert.Fail("Expected FailureReason.");
            if(!res.FailureReason!.Contains("cnf.pkthumb"))
                Assert.Fail("Expected FailureReason to mention cnf.pkthumb.");
        }

        [TestMethod]
        public void Test_VerifySignatureAndCnfWarn_NullProvider()
        {
            var (jws, krcb, iss) = this.SignHbdWithPkthumb("THUMB___________________________________0");

            var settings = new VerificationSettings
            {
                Mode = VerificationMode.VerifySignatureAndCnfWarn,
                AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { iss },
                LocalThumbprintProvider = null,
                KeyRetrievalCallback = krcb,
                ValidateLifetime = false,
            };

            var res = HBD_ContextVerifier.Verify(jws, settings);
            if(res == null) Assert.Fail("Null result.");
            if(res.Ok) Assert.Fail("Null provider should fail in Warn mode.");
            if(string.IsNullOrWhiteSpace(res.FailureReason)) Assert.Fail("Expected FailureReason.");
            if(!res.FailureReason!.Contains("LocalThumbprintProvider"))
                Assert.Fail("Expected FailureReason to mention LocalThumbprintProvider.");
        }

        #endregion


        #region Enforce Mode Tests (Work Item 2)

        [TestMethod]
        public void Test_EnforceAll_Match()
        {
            var thumb = "ENFORCEMATCH____________________________0";
            var (jws, krcb, iss) = this.SignHbdWithPkthumb(thumb);

            var settings = new VerificationSettings
            {
                Mode = VerificationMode.EnforceAll,
                AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { iss },
                LocalThumbprintProvider = new FixedThumbprintProvider(thumb),
                KeyRetrievalCallback = krcb,
                ValidateLifetime = false,
            };

            var res = HBD_ContextVerifier.Verify(jws, settings);
            if(res == null) Assert.Fail("Null result.");
            if(!res.Ok) Assert.Fail("Expected Ok=true on match.");
            if(!res.CnfChecked) Assert.Fail("Expected CnfChecked=true.");
            if(!res.CnfMatched) Assert.Fail("Expected CnfMatched=true.");
        }

        [TestMethod]
        public void Test_EnforceAll_Mismatch()
        {
            var (jws, krcb, iss) = this.SignHbdWithPkthumb("HBDTHUMB________________________________0");

            var settings = new VerificationSettings
            {
                Mode = VerificationMode.EnforceAll,
                AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { iss },
                LocalThumbprintProvider = new FixedThumbprintProvider("LOCALTHUMB______________________________0"),
                KeyRetrievalCallback = krcb,
                ValidateLifetime = false,
            };

            var res = HBD_ContextVerifier.Verify(jws, settings);
            if(res == null) Assert.Fail("Null result.");
            if(res.Ok) Assert.Fail("Enforce mode should fail on mismatch.");
            if(!res.CnfChecked) Assert.Fail("Expected CnfChecked=true.");
            if(res.CnfMatched) Assert.Fail("Expected CnfMatched=false.");
            if(string.IsNullOrWhiteSpace(res.FailureReason)) Assert.Fail("Expected FailureReason.");
            if(!res.FailureReason!.Contains("pkthumb"))
                Assert.Fail("Expected FailureReason to mention pkthumb.");
        }

        [TestMethod]
        public void Test_EnforceAll_ProviderThrows()
        {
            var (jws, krcb, iss) = this.SignHbdWithPkthumb("THUMB___________________________________0");

            var settings = new VerificationSettings
            {
                Mode = VerificationMode.EnforceAll,
                AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { iss },
                LocalThumbprintProvider = new ThrowingThumbprintProvider("tpm-broken"),
                KeyRetrievalCallback = krcb,
                ValidateLifetime = false,
            };

            var res = HBD_ContextVerifier.Verify(jws, settings);
            if(res == null) Assert.Fail("Null result.");
            if(res.Ok) Assert.Fail("Enforce mode should fail when provider throws.");
            if(string.IsNullOrWhiteSpace(res.FailureReason)) Assert.Fail("Expected FailureReason.");
            if(!res.FailureReason!.Contains("tpm-broken"))
                Assert.Fail("Expected FailureReason to surface the exception message.");
        }

        [TestMethod]
        public void Test_EnforceAll_MissingCnf()
        {
            var (jws, krcb, iss) = this.SignHbdWithPkthumb(null);

            var settings = new VerificationSettings
            {
                Mode = VerificationMode.EnforceAll,
                AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { iss },
                LocalThumbprintProvider = new FixedThumbprintProvider("any"),
                KeyRetrievalCallback = krcb,
                ValidateLifetime = false,
            };

            var res = HBD_ContextVerifier.Verify(jws, settings);
            if(res == null) Assert.Fail("Null result.");
            if(res.Ok) Assert.Fail("Missing cnf should fail in Enforce mode.");
            if(string.IsNullOrWhiteSpace(res.FailureReason)) Assert.Fail("Expected FailureReason.");
            if(!res.FailureReason!.Contains("cnf.pkthumb"))
                Assert.Fail("Expected FailureReason to mention cnf.pkthumb.");
        }

        [TestMethod]
        public void Test_EnforceAll_NullProvider()
        {
            var (jws, krcb, iss) = this.SignHbdWithPkthumb("THUMB___________________________________0");

            var settings = new VerificationSettings
            {
                Mode = VerificationMode.EnforceAll,
                AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { iss },
                LocalThumbprintProvider = null,
                KeyRetrievalCallback = krcb,
                ValidateLifetime = false,
            };

            var res = HBD_ContextVerifier.Verify(jws, settings);
            if(res == null) Assert.Fail("Null result.");
            if(res.Ok) Assert.Fail("Null provider should fail in Enforce mode.");
            if(string.IsNullOrWhiteSpace(res.FailureReason)) Assert.Fail("Expected FailureReason.");
            if(!res.FailureReason!.Contains("LocalThumbprintProvider"))
                Assert.Fail("Expected FailureReason to mention LocalThumbprintProvider.");
        }

        #endregion
    }
}
