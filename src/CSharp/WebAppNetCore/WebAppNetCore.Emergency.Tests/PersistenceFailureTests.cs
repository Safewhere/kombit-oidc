using System.IO;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebAppNetCore.EmergencyCredential;

namespace WebAppNetCore.Emergency.Tests
{
    [TestClass]
    public class PersistenceFailureTests
    {
        [TestMethod]
        public async Task StateWrite_Fails_DeniesCachedEmergencyAccess()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            LocalSession session = await fixture.Prove(await fixture.Active(), "login", null, 2);
            using var held = new FileStream(Path.Combine(fixture.Options.StorageDirectory, "state.bin"), FileMode.Open, FileAccess.Read, FileShare.Read);
            // Act
            Assert.ThrowsExactly<IOException>(() => fixture.Service.SignOut(session.Id));
            // Assert
            Assert.AreEqual(503, Assert.ThrowsExactly<EmergencyFault>(() => fixture.Service.Session(session.Id, fixture.Browser)).Status);
        }
    }
}
