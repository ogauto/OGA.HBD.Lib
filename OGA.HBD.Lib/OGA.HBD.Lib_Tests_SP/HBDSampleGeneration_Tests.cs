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
        Host Bootstrap Document Sample Generation Tests

        //  Test_1_2_1  This test walks through the creation of a sample HBD for the dev desktop.
        //  Test_1_2_2  This test walks through the creation of a sample HBD for the build server 200.

        //  Test_1_3_1  This test walks through the creation of a sample HBD for bliss dev host 1.
        //  Test_1_3_2  This test walks through the creation of a sample HBD for bliss dev host 2.
        //  Test_1_3_3  This test walks through the creation of a sample HBD for bliss dev host 3.

        //  Test_1_4_1  This test walks through the creation of a sample HBD for vault0201.
        //  Test_1_4_2  This test walks through the creation of a sample HBD for vault0202.
        //  Test_1_4_3  This test walks through the creation of a sample HBD for vault0203.
        //  Test_1_4_4  This test walks through the creation of a sample HBD for vault0204.
        //  Test_1_4_5  This test walks through the creation of a sample HBD for vault0205.
        //  Test_1_4_6  This test walks through the creation of a sample HBD for vault0206.
        //  Test_1_4_7  This test walks through the creation of a sample HBD for vault02api.
*/


    [TestClass]
    public class HBDSampleGeneration_Tests : Test_TestBase
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

        //  Test_1_2_1  This test walks through the creation of a sample HBD for the dev desktop.
        [TestMethod]
        public async Task Test_1_2_1()
        {
            // Declare a test issuer key location...
            var pemfilepath = "D:\\Projects\\SecureShare git\\oga\\HBD\\ISSUERKEY.pem";
            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");

            // Copy over the issuer instance...
            var issuerKey = resload.issuer;

            // Get properties of the issuer...
            var (kid, jwksjson, pubPem, privPem) = ES256_Issuer.Get_IssuerProperties(issuerKey);

            //// Create a test ES256 issuer instance...
            //// This is what the provisioning service does when creating a new issuing key.
            //var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD...
            var hbd = this.Generate_HBD_forDesktop135();


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
                // Yes, if your doc has iat/exp; you can leave this off for “stationary” mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = HBD_ContextVerifier.Verify(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }

        //  Test_1_2_2  This test walks through the creation of a sample HBD for the build server 200.
        [TestMethod]
        public async Task Test_1_2_2()
        {
            // Declare a test issuer key location...
            var pemfilepath = "D:\\Projects\\SecureShare git\\oga\\HBD\\ISSUERKEY.pem";
            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");

            // Copy over the issuer instance...
            var issuerKey = resload.issuer;

            // Get properties of the issuer...
            var (kid, jwksjson, pubPem, privPem) = ES256_Issuer.Get_IssuerProperties(issuerKey);

            //// Create a test ES256 issuer instance...
            //// This is what the provisioning service does when creating a new issuing key.
            //var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD...
            var hbd = this.Generate_HBD_forBuildServer200();


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
                // Yes, if your doc has iat/exp; you can leave this off for “stationary” mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = HBD_ContextVerifier.Verify(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }

        //  Test_1_3_1  This test walks through the creation of a sample HBD for bliss dev host 1.
        [TestMethod]
        public async Task Test_1_3_1()
        {
            // Declare a test issuer key location...
            var pemfilepath = "D:\\Projects\\SecureShare git\\oga\\HBD\\ISSUERKEY.pem";
            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");

            // Copy over the issuer instance...
            var issuerKey = resload.issuer;

            // Get properties of the issuer...
            var (kid, jwksjson, pubPem, privPem) = ES256_Issuer.Get_IssuerProperties(issuerKey);

            //// Create a test ES256 issuer instance...
            //// This is what the provisioning service does when creating a new issuing key.
            //var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD...
            var hbd = this.Generate_HBD_forBlissDevHost1();


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
                // Yes, if your doc has iat/exp; you can leave this off for “stationary” mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = HBD_ContextVerifier.Verify(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }
        //  Test_1_3_2  This test walks through the creation of a sample HBD for bliss dev host 2.
        [TestMethod]
        public async Task Test_1_3_2()
        {
            // Declare a test issuer key location...
            var pemfilepath = "D:\\Projects\\SecureShare git\\oga\\HBD\\ISSUERKEY.pem";
            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");

            // Copy over the issuer instance...
            var issuerKey = resload.issuer;

            // Get properties of the issuer...
            var (kid, jwksjson, pubPem, privPem) = ES256_Issuer.Get_IssuerProperties(issuerKey);

            //// Create a test ES256 issuer instance...
            //// This is what the provisioning service does when creating a new issuing key.
            //var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD...
            var hbd = this.Generate_HBD_forBlissDevHost2();


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
                // Yes, if your doc has iat/exp; you can leave this off for “stationary” mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = HBD_ContextVerifier.Verify(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }
        //  Test_1_3_3  This test walks through the creation of a sample HBD for bliss dev host 3.
        [TestMethod]
        public async Task Test_1_3_3()
        {
            // Declare a test issuer key location...
            var pemfilepath = "D:\\Projects\\SecureShare git\\oga\\HBD\\ISSUERKEY.pem";
            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");

            // Copy over the issuer instance...
            var issuerKey = resload.issuer;

            // Get properties of the issuer...
            var (kid, jwksjson, pubPem, privPem) = ES256_Issuer.Get_IssuerProperties(issuerKey);

            //// Create a test ES256 issuer instance...
            //// This is what the provisioning service does when creating a new issuing key.
            //var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD...
            var hbd = this.Generate_HBD_forBlissDevHost3();


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
                // Yes, if your doc has iat/exp; you can leave this off for “stationary” mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = HBD_ContextVerifier.Verify(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }

        //  Test_1_4_1  This test walks through the creation of a sample HBD for vault0201.
        [TestMethod]
        public async Task Test_1_4_1()
        {
            // Declare a test issuer key location...
            var pemfilepath = "D:\\Projects\\SecureShare git\\oga\\HBD\\ISSUERKEY.pem";
            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");

            // Copy over the issuer instance...
            var issuerKey = resload.issuer;

            // Get properties of the issuer...
            var (kid, jwksjson, pubPem, privPem) = ES256_Issuer.Get_IssuerProperties(issuerKey);

            //// Create a test ES256 issuer instance...
            //// This is what the provisioning service does when creating a new issuing key.
            //var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD...
            var hbd = this.Generate_HBD_forVault0201();


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
                // Yes, if your doc has iat/exp; you can leave this off for “stationary” mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = HBD_ContextVerifier.Verify(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }
        //  Test_1_4_2  This test walks through the creation of a sample HBD for vault0202.
        [TestMethod]
        public async Task Test_1_4_2()
        {
            // Declare a test issuer key location...
            var pemfilepath = "D:\\Projects\\SecureShare git\\oga\\HBD\\ISSUERKEY.pem";
            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");

            // Copy over the issuer instance...
            var issuerKey = resload.issuer;

            // Get properties of the issuer...
            var (kid, jwksjson, pubPem, privPem) = ES256_Issuer.Get_IssuerProperties(issuerKey);

            //// Create a test ES256 issuer instance...
            //// This is what the provisioning service does when creating a new issuing key.
            //var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD...
            var hbd = this.Generate_HBD_forVault0202();


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
                // Yes, if your doc has iat/exp; you can leave this off for “stationary” mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = HBD_ContextVerifier.Verify(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }
        //  Test_1_4_3  This test walks through the creation of a sample HBD for vault0203.
        [TestMethod]
        public async Task Test_1_4_3()
        {
            // Declare a test issuer key location...
            var pemfilepath = "D:\\Projects\\SecureShare git\\oga\\HBD\\ISSUERKEY.pem";
            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");

            // Copy over the issuer instance...
            var issuerKey = resload.issuer;

            // Get properties of the issuer...
            var (kid, jwksjson, pubPem, privPem) = ES256_Issuer.Get_IssuerProperties(issuerKey);

            //// Create a test ES256 issuer instance...
            //// This is what the provisioning service does when creating a new issuing key.
            //var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD...
            var hbd = this.Generate_HBD_forVault0203();


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
                // Yes, if your doc has iat/exp; you can leave this off for “stationary” mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = HBD_ContextVerifier.Verify(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }
        //  Test_1_4_4  This test walks through the creation of a sample HBD for vault0204.
        [TestMethod]
        public async Task Test_1_4_4()
        {
            // Declare a test issuer key location...
            var pemfilepath = "D:\\Projects\\SecureShare git\\oga\\HBD\\ISSUERKEY.pem";
            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");

            // Copy over the issuer instance...
            var issuerKey = resload.issuer;

            // Get properties of the issuer...
            var (kid, jwksjson, pubPem, privPem) = ES256_Issuer.Get_IssuerProperties(issuerKey);

            //// Create a test ES256 issuer instance...
            //// This is what the provisioning service does when creating a new issuing key.
            //var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD...
            var hbd = this.Generate_HBD_forVault0204();


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
                // Yes, if your doc has iat/exp; you can leave this off for “stationary” mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = HBD_ContextVerifier.Verify(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }
        //  Test_1_4_5  This test walks through the creation of a sample HBD for vault0205.
        [TestMethod]
        public async Task Test_1_4_5()
        {
            // Declare a test issuer key location...
            var pemfilepath = "D:\\Projects\\SecureShare git\\oga\\HBD\\ISSUERKEY.pem";
            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");

            // Copy over the issuer instance...
            var issuerKey = resload.issuer;

            // Get properties of the issuer...
            var (kid, jwksjson, pubPem, privPem) = ES256_Issuer.Get_IssuerProperties(issuerKey);

            //// Create a test ES256 issuer instance...
            //// This is what the provisioning service does when creating a new issuing key.
            //var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD...
            var hbd = this.Generate_HBD_forVault0205();


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
                // Yes, if your doc has iat/exp; you can leave this off for “stationary” mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = HBD_ContextVerifier.Verify(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }
        //  Test_1_4_6  This test walks through the creation of a sample HBD for vault0206.
        [TestMethod]
        public async Task Test_1_4_6()
        {
            // Declare a test issuer key location...
            var pemfilepath = "D:\\Projects\\SecureShare git\\oga\\HBD\\ISSUERKEY.pem";
            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");

            // Copy over the issuer instance...
            var issuerKey = resload.issuer;

            // Get properties of the issuer...
            var (kid, jwksjson, pubPem, privPem) = ES256_Issuer.Get_IssuerProperties(issuerKey);

            //// Create a test ES256 issuer instance...
            //// This is what the provisioning service does when creating a new issuing key.
            //var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD...
            var hbd = this.Generate_HBD_forVault0206();


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
                // Yes, if your doc has iat/exp; you can leave this off for “stationary” mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = HBD_ContextVerifier.Verify(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }
        //  Test_1_4_7  This test walks through the creation of a sample HBD for vault02api.
        [TestMethod]
        public async Task Test_1_4_7()
        {
            // Declare a test issuer key location...
            var pemfilepath = "D:\\Projects\\SecureShare git\\oga\\HBD\\ISSUERKEY.pem";
            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");

            // Copy over the issuer instance...
            var issuerKey = resload.issuer;

            // Get properties of the issuer...
            var (kid, jwksjson, pubPem, privPem) = ES256_Issuer.Get_IssuerProperties(issuerKey);

            //// Create a test ES256 issuer instance...
            //// This is what the provisioning service does when creating a new issuing key.
            //var (issuerKey, kid, jwksjson, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();

            // Save the issuer key data, so it can be used for verifications...
            // First, create the keyset...
            var jwkset = new JsonWebKeySet(jwksjson);

            // Build the map kid -> SecurityKey for ALL keys in the JWKS...
            // This produces a list of public keys that we can use to verify signatures from the test issuer.
            var trustedpublickeys = jwkset.Keys.ToDictionary(k => k.Kid, k => (SecurityKey)k, StringComparer.Ordinal);


            // Create an HBD...
            var hbd = this.Generate_HBD_forVault02API();


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
                // Yes, if your doc has iat/exp; you can leave this off for “stationary” mode
                ValidateLifetime = false,
                // This already defaults to two minutes.
                // We will leave it at default...
                //ClockSkew =  TimeSpan.FromMinutes(2)
            };


            // Verify the HBD...
            var resver = HBD_ContextVerifier.Verify(hbdcontent2, settings);
            if (resver == null || !resver.Ok || resver.Payload == null)
                Assert.Fail("Wrong Value");


            // Recover the hostinfo...
            // We use a helper method on the HostInfo type, to recover data from the JsonDocument-formatted token payload.
            var resrec = HostInfo.RecoverHostInfo_fromPayload(resver.Payload);
            if(resrec.res != 1 || resrec.doc == null)
                Assert.Fail("Wrong Value");

            // Get the doc instance...
            var docinstance = resrec.doc;


            // Compare the recovered doc to the issued one...
            this.Compare_HostInfoInstances(hbd.hostInfo, docinstance);
        }

        #endregion


        #region Private Methods

        protected Host_BootstrapDoc Generate_HBD_forVault0201()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = GetIssuerName();
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "";
            hbd.hostInfo.clusterId = "D15DF6AD-27E4-4E0C-BD6B-5608F4448294";
            hbd.hostInfo.clusterName = "vault02-prod";
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "prod";
            hbd.hostInfo.imageName = "beelink-s12-ubuntu24.04";
            hbd.hostInfo.instanceId = "D58F7E43-AEBB-457C-B38F-B0F38A30F5CC";
            hbd.hostInfo.region = "lee-house";
            hbd.hostInfo.tenant = "oga";
            return hbd;
        }
        protected Host_BootstrapDoc Generate_HBD_forVault0202()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = GetIssuerName();
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "";
            hbd.hostInfo.clusterId = "D15DF6AD-27E4-4E0C-BD6B-5608F4448294";
            hbd.hostInfo.clusterName = "vault02-prod";
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "prod";
            hbd.hostInfo.imageName = "beelink-s12-ubuntu24.04";
            hbd.hostInfo.instanceId = "AA67A89A-724B-475D-B069-BA51694E2037";
            hbd.hostInfo.region = "lee-house";
            hbd.hostInfo.tenant = "oga";
            return hbd;
        }
        protected Host_BootstrapDoc Generate_HBD_forVault0203()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = GetIssuerName();
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "";
            hbd.hostInfo.clusterId = "D15DF6AD-27E4-4E0C-BD6B-5608F4448294";
            hbd.hostInfo.clusterName = "vault02-prod";
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "prod";
            hbd.hostInfo.imageName = "beelink-s12-ubuntu24.04";
            hbd.hostInfo.instanceId = "BE8E8491-CDBC-4881-8593-9F1888DB737F";
            hbd.hostInfo.region = "lee-house";
            hbd.hostInfo.tenant = "oga";
            return hbd;
        }
        protected Host_BootstrapDoc Generate_HBD_forVault0204()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = GetIssuerName();
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "";
            hbd.hostInfo.clusterId = "D15DF6AD-27E4-4E0C-BD6B-5608F4448294";
            hbd.hostInfo.clusterName = "vault02-prod";
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "prod";
            hbd.hostInfo.imageName = "vm-ubuntu24.04";
            hbd.hostInfo.instanceId = "6C13AD72-AE5C-4079-AB92-EAA3070A3008";
            hbd.hostInfo.region = "lee-house";
            hbd.hostInfo.tenant = "oga";
            return hbd;
        }
        protected Host_BootstrapDoc Generate_HBD_forVault0205()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = GetIssuerName();
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "";
            hbd.hostInfo.clusterId = "D15DF6AD-27E4-4E0C-BD6B-5608F4448294";
            hbd.hostInfo.clusterName = "vault02-prod";
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "prod";
            hbd.hostInfo.imageName = "vm-ubuntu24.04";
            hbd.hostInfo.instanceId = "9170AD1D-0251-4513-9F9C-66F39D303FB1";
            hbd.hostInfo.region = "lee-house";
            hbd.hostInfo.tenant = "oga";
            return hbd;
        }
        protected Host_BootstrapDoc Generate_HBD_forVault0206()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = GetIssuerName();
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "";
            hbd.hostInfo.clusterId = "D15DF6AD-27E4-4E0C-BD6B-5608F4448294";
            hbd.hostInfo.clusterName = "vault02-prod";
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "prod";
            hbd.hostInfo.imageName = "vm-ubuntu24.04";
            hbd.hostInfo.instanceId = "E22D5C4D-2A74-4CF8-8C28-687AA559AF9C";
            hbd.hostInfo.region = "lee-house";
            hbd.hostInfo.tenant = "oga";
            return hbd;
        }
        protected Host_BootstrapDoc Generate_HBD_forVault02API()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = GetIssuerName();
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "";
            hbd.hostInfo.clusterId = "D15DF6AD-27E4-4E0C-BD6B-5608F4448294";
            hbd.hostInfo.clusterName = "vault02-prod";
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "prod";
            hbd.hostInfo.imageName = "vm-ubuntu24.04";
            hbd.hostInfo.instanceId = "0E5101F7-B646-4D7C-95C1-99BEE957D003";
            hbd.hostInfo.region = "lee-house";
            hbd.hostInfo.tenant = "oga";
            return hbd;
        }

        protected Host_BootstrapDoc Generate_HBD_forDesktop135()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = GetIssuerName();
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "";
            hbd.hostInfo.clusterId = "";
            hbd.hostInfo.clusterName = "";
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "dev";
            hbd.hostInfo.imageName = "msi-Windows10";
            hbd.hostInfo.instanceId = "2A04B033-A9BA-42EB-8966-E274907CEB29";
            hbd.hostInfo.region = "lee-house";
            hbd.hostInfo.tenant = "oga";
            return hbd;
        }

        protected Host_BootstrapDoc Generate_HBD_forBuildServer200()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = GetIssuerName();
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "";
            hbd.hostInfo.clusterId = "5FFDEFE6-F85C-4FFF-9477-7AFDDFEE21A3";
            hbd.hostInfo.clusterName = "house-vshere";
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "dev";
            hbd.hostInfo.imageName = "vm-ubuntu22.10";
            hbd.hostInfo.instanceId = "A90869C4-88AF-4903-8734-14F5FC5801F1";
            hbd.hostInfo.region = "lee-house";
            hbd.hostInfo.tenant = "oga";
            return hbd;
        }
        protected Host_BootstrapDoc Generate_HBD_forBlissDevHost1()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = GetIssuerName();
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "";
            hbd.hostInfo.clusterId = "F64B7EDB-99A1-48E7-A056-3688057B7A26";
            hbd.hostInfo.clusterName = "bliss-dev-house";
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "dev";
            hbd.hostInfo.imageName = "vm-ubuntu22.10";
            hbd.hostInfo.instanceId = "5C7E9D57-290C-4EF2-A34E-7747A6FB9E24";
            hbd.hostInfo.region = "lee-house";
            hbd.hostInfo.tenant = "bliss";
            return hbd;
        }
        protected Host_BootstrapDoc Generate_HBD_forBlissDevHost2()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = GetIssuerName();
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "";
            hbd.hostInfo.clusterId = "F64B7EDB-99A1-48E7-A056-3688057B7A26";
            hbd.hostInfo.clusterName = "bliss-dev-house";
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "dev";
            hbd.hostInfo.imageName = "vm-ubuntu22.10";
            hbd.hostInfo.instanceId = "2076CC9E-BABE-466A-94D9-103CE6B9E222";
            hbd.hostInfo.region = "lee-house";
            hbd.hostInfo.tenant = "bliss";
            return hbd;
        }
        protected Host_BootstrapDoc Generate_HBD_forBlissDevHost3()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = GetIssuerName();
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "";
            hbd.hostInfo.clusterId = "F64B7EDB-99A1-48E7-A056-3688057B7A26";
            hbd.hostInfo.clusterName = "bliss-dev-house";
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "dev";
            hbd.hostInfo.imageName = "vm-ubuntu22.10";
            hbd.hostInfo.instanceId = "62D023E4-36F0-4643-8A14-A2B68BA332A3";
            hbd.hostInfo.region = "lee-house";
            hbd.hostInfo.tenant = "bliss";
            return hbd;
        }

        protected string GetIssuerName()
        {
            string iss = "urn:local:hbd:bootstrap-ca:oga:dev:local";
            return iss;
        }

        #endregion
    }
}
