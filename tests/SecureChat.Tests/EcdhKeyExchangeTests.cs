using SecureChat.Core.Security.Implementations;
using SecureChat.Core.Security.Interfaces;
using Xunit;

namespace SecureChat.Tests;

public class EcdhKeyExchangeTests
{
    [Fact]
    public async Task GenerateKeyPair_ProducesValidPublicKey()
    {
        // Arrange
        using var keyExchange = new EcdhKeyExchange();        
        // Act
        await keyExchange.GenerateKeyPairAsync();
        var publicKey = keyExchange.GetPublicKey();       
        // Assert
        Assert.NotNull(publicKey);
        Assert.NotEmpty(publicKey);
        Assert.True(keyExchange.ValidatePublicKey(publicKey));
    }
    [Fact]
    public void GetPublicKey_BeforeGeneration_ThrowsException()
    {
        // Arrange
        using var keyExchange = new EcdhKeyExchange();       
        // Act and Assert
        Assert.Throws<InvalidOperationException>(() => keyExchange.GetPublicKey());
    }
    [Fact]
    public async Task DeriveSharedSecret_BetweenTwoPeers_ProducesSameSecret()
    {
        // Arrange
        using var alice = new EcdhKeyExchange();
        using var bob = new EcdhKeyExchange();       
        await alice.GenerateKeyPairAsync();
        await bob.GenerateKeyPairAsync();        
        var alicePublic = alice.GetPublicKey();
        var bobPublic = bob.GetPublicKey();       
        // Act
        var aliceSecret = await alice.DeriveSharedSecretAsync(bobPublic);
        var bobSecret = await bob.DeriveSharedSecretAsync(alicePublic);       
        // Assert - Both sides should derive the same shared secret
        Assert.Equal(aliceSecret, bobSecret);
    }
    [Fact]
    public async Task DeriveSharedSecret_DifferentPeers_ProduceDifferentSecrets()
    {
        // Arrange
        using var alice = new EcdhKeyExchange();
        using var bob = new EcdhKeyExchange();
        using var charlie = new EcdhKeyExchange();        
        await alice.GenerateKeyPairAsync();
        await bob.GenerateKeyPairAsync();
        await charlie.GenerateKeyPairAsync();       
        // Act
        var aliceBobSecret = await alice.DeriveSharedSecretAsync(bob.GetPublicKey());
        var aliceCharlieSecret = await alice.DeriveSharedSecretAsync(charlie.GetPublicKey());       
        // Assert - Different peers should produce different secrets
        Assert.NotEqual(aliceBobSecret, aliceCharlieSecret);
    }
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-valid-base64!!!")]
    public void ValidatePublicKey_InvalidKeys_ReturnsFalse(string invalidKey)
    {
        // Arrange
        using var keyExchange = new EcdhKeyExchange();       
        // Act and Assert
        Assert.False(keyExchange.ValidatePublicKey(invalidKey));
    }
    [Fact]
    public void AlgorithmIdentifier_ReturnsExpectedValue()
    {
        // Arrange
        using var keyExchange = new EcdhKeyExchange();
        // Act and Assert
        Assert.Equal("ECDH-P256", keyExchange.AlgorithmIdentifier);
    }
}
