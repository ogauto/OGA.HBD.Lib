using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OGA.HBD.Model;

namespace OGA.HBD.Lib_Tests.Helpers
{
    public class Test_TestBase : OGA.Testing.Lib.Test_Base_abstract
    {
        #region Private Methods

        /// <summary>
        /// This will generate a valid test HBD.
        /// </summary>
        /// <returns></returns>
        protected Host_BootstrapDoc Generate_ValidHostBootstrapDocument()
        {
            var ctime = DateTimeOffset.UtcNow;
            var etime = ctime.AddDays(1);

            var hbd = new Host_BootstrapDoc();
            hbd.version = 1;
            hbd.docType = "hbd";
            hbd.cnf = null;
            hbd.iss = "intca.companyname.com";
            hbd.iat = ctime.ToUnixTimeSeconds();
            hbd.exp = etime.ToUnixTimeSeconds();
            hbd.hostInfo.availZone = "availZone-" + Guid.NewGuid().ToString().ToLower();
            hbd.hostInfo.clusterId = "clusterId-" + Guid.NewGuid().ToString().ToLower();
            hbd.hostInfo.clusterName = "clusterName-" + Guid.NewGuid().ToString().ToLower();
            hbd.hostInfo.creationTime = ctime.ToUnixTimeSeconds();
            hbd.hostInfo.environment = "environment-" + Guid.NewGuid().ToString().ToLower();
            hbd.hostInfo.imageName = "imageName-" + Guid.NewGuid().ToString().ToLower();
            hbd.hostInfo.instanceId = "instanceId-" + Guid.NewGuid().ToString().ToLower();
            hbd.hostInfo.region = "region-" + Guid.NewGuid().ToString().ToLower();
            hbd.hostInfo.tenant = "tenant-" + Guid.NewGuid().ToString().ToLower();

            return hbd;
        }

        protected void Compare_HostInfoInstances(HostInfo_V1 hbd, HostInfo_V1 docinstance)
        {
            // Check each property...
            if (hbd.region != docinstance.region)
                Assert.Fail("Wrong Value");
            if (hbd.availZone != docinstance.availZone)
                Assert.Fail("Wrong Value");
            if (hbd.instanceId != docinstance.instanceId)
                Assert.Fail("Wrong Value");
            if (hbd.tenant != docinstance.tenant)
                Assert.Fail("Wrong Value");
            if (hbd.imageName != docinstance.imageName)
                Assert.Fail("Wrong Value");
            if (hbd.creationTime != docinstance.creationTime)
                Assert.Fail("Wrong Value");
            if (hbd.clusterId != docinstance.clusterId)
                Assert.Fail("Wrong Value");
            if (hbd.clusterName != docinstance.clusterName)
                Assert.Fail("Wrong Value");
            if (hbd.environment != docinstance.environment)
                Assert.Fail("Wrong Value");
        }

        #endregion
    }
}
