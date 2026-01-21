using System.Security.Cryptography;

namespace SecureChat.Core.Security.Implementations;

/// <summary>
/// ECDH key exchange implementation using P-256 curve
/// 
/// Security Design:
/// - Uses NIST P-256 curve
/// - Keys exported in SPKI format for interoperability
/// - Validates peer public keys before deriving shared secret
/// 
/// Usage:
/// 1. Call GenerateKeyPairAsync() to create local key pair
/// 2. Send GetPublicKey() to peer
/// 3. Receive peer's public key
/// 4. Call DeriveSharedSecretAsync(peerKey) to get shared secret
/// 5. Use HKDF to derive encryption keys from shared secret
/// </summary>
public sealed class EcdhKeyExchange : Interfaces.IKeyExchange, IDisposable
{
    private ECDiffieHellman? _ecdh;
    private byte[]? _publicKey;
    private bool _disposed;

    /// <inheritdoc />
    public string AlgorithmIdentifier => "ECDH-P256";

    /// <inheritdoc />
    public Task GenerateKeyPairAsync()
    {
        ThrowIfDisposed();
        
        // Dispose previous key pair if exists
        _ecdh?.Dispose();
        
        // Create new ECDH instance with P-256 curve
        _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        
        // Export public key in SPKI format for interoperability
        _publicKey = _ecdh.ExportSubjectPublicKeyInfo();
        
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public string GetPublicKey()
    {
        ThrowIfDisposed();
        
        if (_publicKey is null)
        {
            throw new InvalidOperationException(
                "Key pair not generated. Call GenerateKeyPairAsync first.");
        }
        
        return Convert.ToBase64String(_publicKey);
    }

    /// <inheritdoc />
    public Task<string> DeriveSharedSecretAsync(string peerPublicKey)
    {
        ThrowIfDisposed();
        
        if (_ecdh is null)
        {
            throw new InvalidOperationException(
                "Key pair not generated. Call GenerateKeyPairAsync first.");
        }

        if (!ValidatePublicKey(peerPublicKey))
        {
            throw new ArgumentException(
                "Invalid peer public key format or parameters", nameof(peerPublicKey));
        }

        // Import peer's public key
        var peerKeyBytes = Convert.FromBase64String(peerPublicKey);
        using var peerEcdh = ECDiffieHellman.Create();
        peerEcdh.ImportSubjectPublicKeyInfo(peerKeyBytes, out _);

        // Derive shared secret using ECDH
        // Security Note: This raw shared secret should be passed through HKDF
        // before being used as an encryption key
        var sharedSecret = _ecdh.DeriveKeyMaterial(peerEcdh.PublicKey);

        return Task.FromResult(Convert.ToBase64String(sharedSecret));
    }

    /// <inheritdoc />
    public bool ValidatePublicKey(string publicKey)
    {
        if (string.IsNullOrWhiteSpace(publicKey))
        {
            return false;
        }

        try
        {
            // Attempt to decode and parse the key
            var keyBytes = Convert.FromBase64String(publicKey);
            
            // Validate by attempting to import
            using var testEcdh = ECDiffieHellman.Create();
            testEcdh.ImportSubjectPublicKeyInfo(keyBytes, out int bytesRead);
            
            // Ensure all bytes were consumed
            if (bytesRead != keyBytes.Length)
            {
                return false;
            }

            // Verify the key is on P-256 curve
            var parameters = testEcdh.ExportParameters(includePrivateParameters: false);
            if (parameters.Curve.Oid?.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
            {
                // Allow if curve matches by name
                if (parameters.Curve.Oid?.FriendlyName != "nistP256" &&
                    parameters.Curve.Oid?.FriendlyName != "ECDSA_P256")
                {
                    return false;
                }
            }

            return true;
        }
        catch (FormatException)
        {
            // Invalid Base64
            return false;
        }
        catch (CryptographicException)
        {
            // Invalid key format or weak key
            return false;
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcdhKeyExchange));
        }
    }

    /// <summary>
    /// Disposes cryptographic resources securely
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        
        _ecdh?.Dispose();
        _ecdh = null;
        
        // Clear public key from memory
        if (_publicKey is not null)
        {
            CryptographicOperations.ZeroMemory(_publicKey);
            _publicKey = null;
        }
        
        _disposed = true;
    }
}
