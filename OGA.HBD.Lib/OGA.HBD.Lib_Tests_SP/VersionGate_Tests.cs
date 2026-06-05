using Microsoft.VisualStudio.TestTools.UnitTesting;
using OGA.HBD.Helpers;
using OGA.HBD.Lib_Tests.Helpers;
using OGA.HBD.Model;
using OGA.HBD.Service;
using System.Threading.Tasks;

namespace OGA.HBD.Lib_Tests
{
    /// <summary>
    /// Tests for the supported-version range gate on the verifier.
    /// The gate accepts the inclusive range [MinSupportedVersion, MaxSupportedVersion] and loudly
    /// rejects anything outside it. Today Min == Max == 1, so only v1 is accepted. See SPEC.md KD-09.
    /// The version gate runs in the obligatory checks, before signature validation, so ParseOnly mode
    /// is sufficient to exercise it.
    /// </summary>
    [TestClass]
    public class VersionGate_Tests : Test_TestBase
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


        #region Tests

        /// <summary>
        /// The supported range is exposed publicly so consumers can reference it, and is fixed at v1
        /// today. These are the constants the range gate is built on.
        /// </summary>
        [TestMethod]
        public void Test_SupportedVersionRange_IsPublicAndFixedAtV1()
        {
            Assert.AreEqual(1, HBD_ContextVerifier.MinSupportedVersion);
            Assert.AreEqual(1, HBD_ContextVerifier.MaxSupportedVersion);
            Assert.IsTrue(HBD_ContextVerifier.MinSupportedVersion <= HBD_ContextVerifier.MaxSupportedVersion);
        }

        /// <summary>
        /// A v1 HBD passes the version gate; versions outside the supported range (0 and 2) are rejected.
        /// </summary>
        [TestMethod]
        public async Task Test_VersionGate_AcceptsInRange_RejectsOutOfRange()
        {
            // version 1 — in range, accepted.
            await Assert_VersionOutcome(1, expectOk: true);

            // version 0 — below MinSupportedVersion, rejected.
            await Assert_VersionOutcome(0, expectOk: false);

            // version 2 — above MaxSupportedVersion, rejected (no v2 handling exists).
            await Assert_VersionOutcome(2, expectOk: false);
        }

        #endregion


        #region Private Methods

        /// <summary>
        /// Mints an issuer, signs an HBD declaring the given version, and verifies it in ParseOnly mode
        /// (which still enforces the version gate but does not require signature/key material).
        /// </summary>
        private async Task Assert_VersionOutcome(int version, bool expectOk)
        {
            // Mint a test issuer to sign with...
            var (issuerKey, kid, _, _, _) = ES256_Issuer.Create_NewIssuer();

            // Build an otherwise-valid HBD and stamp the version under test...
            var hbd = this.Generate_ValidHostBootstrapDocument();
            hbd.version = version;

            // Sign it...
            var ressign = HBD_Signer.CreateBootstrapJws(hbd, issuerKey, kid);
            if (ressign.res != 1 || string.IsNullOrWhiteSpace(ressign.val))
                Assert.Fail($"Failed to sign HBD for version {version}.");

            // ParseOnly mode: the version gate runs, signature validation does not...
            var settings = new VerificationSettings
            {
                Mode = VerificationMode.ParseOnly,
                ValidateLifetime = false,
            };

            var res = await HBD_ContextVerifier.VerifyAsync(ressign.val, settings);

            Assert.IsNotNull(res, $"Null result for version {version}.");
            Assert.AreEqual(expectOk, res.Ok,
                $"Version {version}: expected Ok={expectOk} but got Ok={res.Ok} (reason: '{res.FailureReason}').");

            // Out-of-range rejections should fail specifically on the version gate...
            if (!expectOk)
                Assert.AreEqual("Invalid HBD version.", res.FailureReason,
                    $"Version {version}: rejected for the wrong reason.");
        }

        #endregion
    }
}
