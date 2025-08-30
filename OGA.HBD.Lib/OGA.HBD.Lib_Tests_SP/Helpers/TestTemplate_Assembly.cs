using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TestTemplate
{
    /// <summary>
    /// Template Test Project's Test Assembly class.
    /// Create one of these in each of your testing projects, so that logging will be automatically setup.
    /// Have it inherit from OGA.Testing.Lib.TestAssembly_Base and call the initialize and cleanup methods.
    /// OR. If your testing project is small, you can simply call the static initialize and cleanup methods of OGA.Testing.Lib.TestAssembly_Base, with attribute-decorated methods.
    /// </summary>
    [TestClass]
    public class TestTemplate_Assembly : OGA.Testing.Lib.TestAssembly_Base
    {
        #region Test Assembly Setup / Teardown

        /// <summary>
        /// This initializer calls the base assembly initializer.
        /// </summary>
        /// <param name="context"></param>
        [AssemblyInitialize]
        static public void TestAssembly_Initialize(TestContext context)
        {
            TestAssemblyBase_Initialize(context);
        }

        /// <summary>
        /// This cleanup method calls the base assembly cleanup.
        /// </summary>
        [AssemblyCleanup]
        static public void TestAssembly_Cleanup()
        {
            TestAssemblyBase_Cleanup();
        }

        #endregion
    }
}
