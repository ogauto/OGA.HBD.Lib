using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OGA.HBD.Helpers;
using OGA.HBD.Lib_Tests.Helpers;
using OGA.HBD.Model;
using OGA.HBD.Service;
using System;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using static OGA.HBD.Service.VerificationSettings;

namespace OGA.HBD.Lib_Tests
{
    /// <summary>
    /// Congruency tests for the async migration (OI-15 / OI-18).
    /// </summary>
    [TestClass]
    public class AsyncVerifierApi_Tests : Test_TestBase
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
        /// Reflection-based check that VerifyAsync exists with the expected async signature,
        /// and that the legacy sync Verify has been removed.
        /// </summary>
        [TestMethod]
        public void Test_VerifyAsync_ReturnsTask()
        {
            var t = typeof(HBD_ContextVerifier);

            var asyncMethod = t.GetMethod("VerifyAsync", BindingFlags.Public | BindingFlags.Static);
            if(asyncMethod == null)
                Assert.Fail("HBD_ContextVerifier.VerifyAsync (public static) was not found.");
            if(asyncMethod!.ReturnType != typeof(Task<BootstrapDocResult>))
                Assert.Fail($"VerifyAsync must return Task<BootstrapDocResult>; got {asyncMethod.ReturnType}.");

            var syncMethod = t.GetMethod("Verify", BindingFlags.Public | BindingFlags.Static);
            if(syncMethod != null)
                Assert.Fail("Legacy sync HBD_ContextVerifier.Verify must be removed; it was found on the type.");
        }

        /// <summary>
        /// End-to-end smoke test that VerifyAsync resolves to a BootstrapDocResult and succeeds against
        /// a fresh issuer-signed HBD.
        /// </summary>
        [TestMethod]
        public async Task Test_VerifyAsync_SmokeTest()
        {
            var (issuerKey, kid, jwksjson, _, _) = ES256_Issuer.Create_NewIssuer();
            var jwkset = new JsonWebKeySet(jwksjson);
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);

            var hbd = this.Generate_ValidHostBootstrapDocument();
            var ressign = HBD_Signer.CreateBootstrapJws(hbd, issuerKey, kid);
            if(ressign.res != 1 || string.IsNullOrWhiteSpace(ressign.val))
                Assert.Fail("Signing failed.");

            dKeyRetrievalCallback krcb = (k) =>
            {
                if(!trustedpublickeys.TryGetValue(kid, out var key)) return (-1, null);
                return (1, key);
            };

            var settings = new VerificationSettings
            {
                Mode = VerificationMode.VerifySignature,
                AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { hbd.iss },
                KeyRetrievalCallback = krcb,
                ValidateLifetime = false,
            };

            BootstrapDocResult res = await HBD_ContextVerifier.VerifyAsync(ressign.val!, settings);
            if(res == null || !res.Ok || res.Payload == null)
                Assert.Fail("VerifyAsync did not produce a successful BootstrapDocResult.");
        }
    }
}
