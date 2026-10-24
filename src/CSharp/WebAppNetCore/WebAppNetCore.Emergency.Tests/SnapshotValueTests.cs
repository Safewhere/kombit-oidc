using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebAppNetCore.EmergencyCredential;

namespace WebAppNetCore.Emergency.Tests
{
    [TestClass]
    public class SnapshotValueTests
    {
        [DataTestMethod]
        [DataRow("")]
        [DataRow("first\nsecond")]
        public void Credential_ValidStringSnapshot_PreservesValue(string value)
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            fixture.AdditionalClaimValue = value;
            string token = fixture.Issue().GetProperty("emergency_credential").GetString();
            // Act
            VerifiedCredential verified = fixture.Verifier.Verify(token, fixture.Trust, fixture.Clock.Value);
            // Assert
            Assert.AreEqual(value, verified.Claims[verified.Claims.Count - 1].Value);
        }
    }
}
