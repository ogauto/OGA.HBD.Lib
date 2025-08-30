using Microsoft.VisualStudio.TestTools.UnitTesting;
using OGA.HBD.Helpers;
using OGA.HBD.Lib_Tests.Helpers;
using OGA.HBD.Model;
using OGA.HBD.Service;
using System.Threading.Tasks;

namespace OGA.HBD.Lib_Tests
{
    /*
        PEM Converter Tests

        //  Test_1_1_1  Create a test signing key.
        //              Convert its private PEM content to PKCS#8.
        //              Convert the PKCS#8 content back to PEM.
        //              Verify the two are equal.

     */


    [TestClass]
    public class PEMConverter_Tests : Test_TestBase
    {
        #region Setup

        /// <summary>
        /// This will perform any test setup before the first class tests start.
        /// This exists, because MSTest won't call the class setup method in a base class.
        /// Be sure this method exists in your top-level test class, and that it calls the corresponding test class setup method of the base.
        /// </summary>
        [ClassInitialize]
        static public void TestClass_Setup(TestContext context)
        {
            TestClassBase_Setup(context);
        }
        /// <summary>
        /// This will cleanup resources after all class tests have completed.
        /// This exists, because MSTest won't call the class cleanup method in a base class.
        /// Be sure this method exists in your top-level test class, and that it calls the corresponding test class cleanup method of the base.
        /// </summary>
        [ClassCleanup]
        static public void TestClass_Cleanup()
        {
            TestClassBase_Cleanup();
        }

        /// <summary>
        /// Called before each test runs.
        /// Be sure this method exists in your top-level test class, and that it calls the corresponding test setup method of the base.
        /// </summary>
        [TestInitialize]
        override public void Setup()
        {
            //// Push the TestContext instance that we received at the start of the current test, into the common property of the test base class...
            //Test_Base.TestContext = TestContext;

            base.Setup();

            // Runs before each test. (Optional)
        }

        /// <summary>
        /// Called after each test runs.
        /// Be sure this method exists in your top-level test class, and that it calls the corresponding test cleanup method of the base.
        /// </summary>
        [TestCleanup]
        override public void TearDown()
        {
            // Runs after each test. (Optional)
        }

        #endregion


        #region Tests

        //  Test_1_1_1  Create a test signing key.
        //              Convert its private PEM content to PKCS#8.
        //              Convert the PKCS#8 content back to PEM.
        //              Verify the two are equal.
        [TestMethod]
        public async Task Test_1_1_1()
        {
            // Create a test ES256 issuer instance...
            var (issuerKey, kid, jwks, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            var pem1 = privPem;


            // Convert the private key PEM to PKCS#8...
            var der = PEMConverter.ExtractKey_fromPem(pem1, "PRIVATE KEY");


            // Convert it into a private PEM...
            var pem2 = PEMConverter.CreatePem("PRIVATE KEY", der);


            // Compare the two PEM content strings...
            if(pem1 != pem2)
                Assert.Fail("Wrong Value");
        }

        #endregion


        #region Private Methods

        #endregion
    }
}
