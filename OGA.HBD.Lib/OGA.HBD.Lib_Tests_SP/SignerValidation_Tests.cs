using Microsoft.VisualStudio.TestTools.UnitTesting;
using OGA.HBD.Helpers;
using OGA.HBD.Lib_Tests.Helpers;
using OGA.HBD.Model;
using OGA.HBD.Service;
using System;

namespace OGA.HBD.Lib_Tests
{
    /// <summary>
    /// Tests for the iat/exp sanity-checks performed by HBD_Signer.CreateBootstrapJws (Work Item 3).
    /// </summary>
    [TestClass]
    public class SignerValidation_Tests : Test_TestBase
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

        [TestMethod]
        public void Test_Sign_RejectsZeroIat()
        {
            var (issuerKey, kid, _, _, _) = ES256_Issuer.Create_NewIssuer();
            var hbd = this.Generate_ValidHostBootstrapDocument();
            hbd.iat = 0;

            var res = HBD_Signer.CreateBootstrapJws(hbd, issuerKey, kid);
            if(res.res == 1) Assert.Fail("Signer should not sign an HBD with iat=0.");
            if(!string.IsNullOrEmpty(res.val)) Assert.Fail("Signer should not produce output on validation failure.");
        }

        [TestMethod]
        public void Test_Sign_RejectsZeroExp()
        {
            var (issuerKey, kid, _, _, _) = ES256_Issuer.Create_NewIssuer();
            var hbd = this.Generate_ValidHostBootstrapDocument();
            hbd.exp = 0;

            var res = HBD_Signer.CreateBootstrapJws(hbd, issuerKey, kid);
            if(res.res == 1) Assert.Fail("Signer should not sign an HBD with exp=0.");
            if(!string.IsNullOrEmpty(res.val)) Assert.Fail("Signer should not produce output on validation failure.");
        }

        [TestMethod]
        public void Test_Sign_RejectsNegativeIat()
        {
            var (issuerKey, kid, _, _, _) = ES256_Issuer.Create_NewIssuer();
            var hbd = this.Generate_ValidHostBootstrapDocument();
            hbd.iat = -1;

            var res = HBD_Signer.CreateBootstrapJws(hbd, issuerKey, kid);
            if(res.res == 1) Assert.Fail("Signer should not sign an HBD with negative iat.");
            if(!string.IsNullOrEmpty(res.val)) Assert.Fail("Signer should not produce output on validation failure.");
        }

        [TestMethod]
        public void Test_Sign_RejectsNegativeExp()
        {
            var (issuerKey, kid, _, _, _) = ES256_Issuer.Create_NewIssuer();
            var hbd = this.Generate_ValidHostBootstrapDocument();
            hbd.exp = -1;

            var res = HBD_Signer.CreateBootstrapJws(hbd, issuerKey, kid);
            if(res.res == 1) Assert.Fail("Signer should not sign an HBD with negative exp.");
            if(!string.IsNullOrEmpty(res.val)) Assert.Fail("Signer should not produce output on validation failure.");
        }

        [TestMethod]
        public void Test_Sign_RejectsExpBeforeIat()
        {
            var (issuerKey, kid, _, _, _) = ES256_Issuer.Create_NewIssuer();
            var hbd = this.Generate_ValidHostBootstrapDocument();
            // Force exp <= iat...
            hbd.exp = hbd.iat;

            var res = HBD_Signer.CreateBootstrapJws(hbd, issuerKey, kid);
            if(res.res == 1) Assert.Fail("Signer should not sign an HBD with exp <= iat.");
            if(!string.IsNullOrEmpty(res.val)) Assert.Fail("Signer should not produce output on validation failure.");

            // Also try strictly less...
            hbd.exp = hbd.iat - 100;
            var res2 = HBD_Signer.CreateBootstrapJws(hbd, issuerKey, kid);
            if(res2.res == 1) Assert.Fail("Signer should not sign an HBD with exp < iat.");
        }

        #endregion
    }
}
