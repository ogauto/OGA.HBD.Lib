using Jose;
using Microsoft.Extensions.Hosting;
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
    /*
        Host Bootstrap Document Verifier Tests

        //  Test_1_1_1  This test confirms that we can create a host bootstrap document, verify it, and retrieve its data.
        //              Create a HBD.
        //              Create a test issuer, and sign the HBD.
        //              Save it to disk, and load it back.
        //              verify the signature is authentic.
        //              Retrieve the contents.
        //              Verify the recovered HBD is the same as the original.

     */


    [TestClass]
    public class HBDVerifier_Tests : Test_TestBase
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

        //  Test_1_1_1  This test confirms that we can create a host bootstrap document, verify it, and retrieve its data.
        //              Create a HBD.
        //              Create a test issuer, and sign the HBD.
        //              Save it to disk, and load it back.
        //              verify the signature is authentic.
        //              Retrieve the contents.
        //              Verify the recovered HBD is the same as the original.
        [TestMethod]
        public async Task Test_1_1_1()
        {
            // Create a test ES256 issuer instance...
            // This is what the provisioning service does when creating a new issuing key.
            var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD for a host...
            var hbd = this.Generate_ValidHostBootstrapDocument();


            // Extract the test issuer name, so we can use it during verification...
            var testissuername = hbd.iss;


            // Sign the HBD...
            var ressign = HBD_Signer.CreateBootstrapJws(hbd, issuerKey, kid);
            if (ressign.res != 1 || string.IsNullOrWhiteSpace(ressign.val))
                Assert.Fail("Wrong Value");


            // Get the HBD content...
            var hbdcontent = ressign.val;


            // Create a folder for storing the HBD...
            var foldername = Guid.NewGuid().ToString();
            var folderpath = System.IO.Path.Combine(this._testfolder, foldername);
            System.IO.Directory.CreateDirectory(folderpath);


            // Save the HBD to disk...
            var hbdfilename = Guid.NewGuid().ToString() + ".hbd";
            var hbdfilepath = System.IO.Path.Combine(folderpath, hbdfilename);
            System.IO.File.WriteAllText(hbdfilepath, hbdcontent);


            // Verify the file exists...
            if (!System.IO.File.Exists(hbdfilepath))
                Assert.Fail("Wrong Value");


            // Load it from disk...
            var hbdcontent2 = System.IO.File.ReadAllText(hbdfilepath);
            if (string.IsNullOrWhiteSpace(hbdcontent2))
                Assert.Fail("Wrong Value");


            // Create a callback lambda that verification can use to retrieve the signing key...
            // This is what the client will call, to request verification key from a public key store.
            dKeyRetrievalCallback krcb = (k) =>
            {
                // Look through the keyset for the match...
                if(!trustedpublickeys.TryGetValue(kid, out var key))
                    return (-1, null);

                return (1, key);
            };


            // Define the verification settings...
            var settings = new VerificationSettings
            {
                Mode = VerificationMode.VerifySignature,
                //AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { "intca.somecompany.com", testissuername },
                AllowedIssuers = new(StringComparer.OrdinalIgnoreCase) { testissuername },
                // For verification-only, we don't need a thumbprint provider...
                LocalThumbprintProvider = null,
                // Set the key retrieval callback...
                KeyRetrievalCallback = krcb,
                // We want to verify the HBD lifetime...
                // Yes, if your doc has iat/exp; you can leave this off for �stationary� mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = await HBD_ContextVerifier.VerifyAsync(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo_V1.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }

        #endregion


        #region Private Methods

        #endregion
    }
}
