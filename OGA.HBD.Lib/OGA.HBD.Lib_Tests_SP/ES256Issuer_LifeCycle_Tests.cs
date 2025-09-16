using Microsoft.VisualStudio.TestTools.UnitTesting;
using OGA.HBD.Helpers;
using OGA.HBD.Lib_Tests.Helpers;
using OGA.HBD.Model;
using OGA.HBD.Service;
using System;
using System.Threading.Tasks;

namespace OGA.HBD.Lib_Tests
{
    /*
        ES256 Issuer LifeCycle Tests

        //  Test_1_2_1  This test confirms that we can create an issuer instance, save its private key to disk, and load it back into a new instance.
        //              Create a test signing key.
        //              Convert it to a PEM.
        //              Convert the PEM back to a new key.
        //              Create a new key instance from the PEM.
        //              Verify the recovered key is the same as the original.
        //  Test_1_2_2  This test confirms that we can create an issuer instance, save its private key to disk, and load it back using the file to issuer method call.
        //              Create a test signing key.
        //              Convert it to a PEM.
        //              Convert the PEM back to a new key.
        //              Create a new key instance from the PEM.
        //              Verify the recovered key is the same as the original.
        //  Test_1_2_3  This test confirms that we can create an issuer instance, save its key data to a backing store, and load it back, to a new issuer.
        //              Create a test signing key.
        //              Convert it to a PEM.
        //              Simulate saving it in a backing store as a string.
        //              Simulate retrieving it from a backing store as a string.
        //              Convert the PEM back to a new key.
        //              Create a new key instance from the PEM.
        //              Verify the recovered key is the same as the original.

     */


    [TestClass]
    public class ES256Issuer_LifeCycle_Tests : Test_TestBase
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

        //  Test_1_2_1  Create a test signing key.
        //              Convert it to a PEM.
        //              Convert the PEM back to a new key.
        //              Create a new key instance from the PEM.
        //              Verify the recovered key is the same as the original.
        [TestMethod]
        public async Task Test_1_2_1()
        {
            // Create a test ES256 issuer instance...
            var (issuerKey, kid, jwks, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();


            // Get the private pem...
            var ppem = privPem;

            
            // Create a folder for storing the key...
            var foldername = Guid.NewGuid().ToString();
            var folderpath = System.IO.Path.Combine(this._testfolder, foldername);
            System.IO.Directory.CreateDirectory(folderpath);


            // Save the private pem file to disk...
            var ppemfilename = Guid.NewGuid().ToString() + ".pem";
            var pemfilepath = System.IO.Path.Combine(folderpath, ppemfilename);
            System.IO.File.WriteAllText(pemfilepath, ppem);


            // Verify the file exists...
            if(!System.IO.File.Exists(pemfilepath))
                Assert.Fail("Wrong Value");


            // Load it from disk into PKCS#8 format...
            var resload = PEMConverter.Load_PrivatePEMFile_toPKCS8(pemfilepath);
            if(resload.res != 1 || resload.pkcs8 == null)
                Assert.Fail("Wrong Value");


            // Create a new issuer from it...
            var newissuer = ES256_Issuer.CreateIssuer_fromPrivatePKCS8(resload.pkcs8);
            if(newissuer.res != 1 || newissuer.issuer == null)
                Assert.Fail("Wrong Value");


            // Extract properties of the new instance...
            var newprops = ES256_Issuer.Get_IssuerProperties(newissuer.issuer);


            // Check each property...
            if(kid != newprops.Kid)
                Assert.Fail("Wrong Value");
            if(jwks != newprops.Jwks)
                Assert.Fail("Wrong Value");
            if(pubPem != newprops.PublicPem)
                Assert.Fail("Wrong Value");
            if(privPem != newprops.PrivatePem)
                Assert.Fail("Wrong Value");
        }

        //  Test_1_2_2  This test confirms that we can create an issuer instance, save its private key to disk, and load it back using the file to issuer method call.
        //              Create a test signing key.
        //              Convert it to a PEM.
        //              Convert the PEM back to a new key.
        //              Create a new key instance from the PEM.
        //              Verify the recovered key is the same as the original.
        [TestMethod]
        public async Task Test_1_2_2()
        {
            // Create a test ES256 issuer instance...
            var (issuerKey, kid, jwks, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();


            // Get the private pem...
            var ppem = privPem;

            
            // Create a folder for storing the key...
            var foldername = Guid.NewGuid().ToString();
            var folderpath = System.IO.Path.Combine(this._testfolder, foldername);
            System.IO.Directory.CreateDirectory(folderpath);


            // Save the private pem file to disk...
            var ppemfilename = Guid.NewGuid().ToString() + ".pem";
            var pemfilepath = System.IO.Path.Combine(folderpath, ppemfilename);
            System.IO.File.WriteAllText(pemfilepath, ppem);


            // Verify the file exists...
            if(!System.IO.File.Exists(pemfilepath))
                Assert.Fail("Wrong Value");


            // Create a new issuer instance from the disk file data...
            var resload = ES256_Issuer.LoadIssuer_fromPrivateKeyPEMPkcs8(pemfilepath);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");


            // Extract properties of the new instance...
            var newprops = ES256_Issuer.Get_IssuerProperties(resload.issuer);


            // Check each property...
            if(kid != newprops.Kid)
                Assert.Fail("Wrong Value");
            if(jwks != newprops.Jwks)
                Assert.Fail("Wrong Value");
            if(pubPem != newprops.PublicPem)
                Assert.Fail("Wrong Value");
            if(privPem != newprops.PrivatePem)
                Assert.Fail("Wrong Value");
        }

        //  Test_1_2_3  This test confirms that we can create an issuer instance, save its key data to a backing store, and load it back, to a new issuer.
        //              Create a test signing key.
        //              Convert it to a PEM.
        //              Simulate saving it in a backing store as a string.
        //              Simulate retrieving it from a backing store as a string.
        //              Convert the PEM back to a new key.
        //              Create a new key instance from the PEM.
        //              Verify the recovered key is the same as the original.
        [TestMethod]
        public async Task Test_1_2_3()
        {
            // Create a test ES256 issuer instance...
            var (issuerKey, kid, jwks, pubPem, privPem) = ES256_Issuer.Create_NewIssuer();


            // Get the private pem...
            var ppem = privPem;


            // Simulate storing the private key as pem in a backing store...
            var bspem = ppem.ToString();


            // Simulate retrieval of the private key from PEM to pkcs8...
            var retrievedpem = bspem.ToString();


            var resload2 = PEMConverter.Load_PrivatePEMString_toPKCS8(retrievedpem);
            if(resload2.res != 1 || resload2.pkcs8 == null)
                Assert.Fail("Wrong Value");


            // Create a new issuer instance from the pkcs8...
            var resload = ES256_Issuer.CreateIssuer_fromPrivatePKCS8(resload2.pkcs8);
            if(resload.res != 1 || resload.issuer == null)
                Assert.Fail("Wrong Value");


            // Extract properties of the new instance...
            var newprops = ES256_Issuer.Get_IssuerProperties(resload.issuer);


            // Check each property...
            if(kid != newprops.Kid)
                Assert.Fail("Wrong Value");
            if(jwks != newprops.Jwks)
                Assert.Fail("Wrong Value");
            if(pubPem != newprops.PublicPem)
                Assert.Fail("Wrong Value");
            if(privPem != newprops.PrivatePem)
                Assert.Fail("Wrong Value");
        }

        #endregion


        #region Private Methods

        #endregion
    }
}
