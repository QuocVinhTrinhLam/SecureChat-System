# SecureChat-System

A secure client–server chat application implementing encrypted communication using modern cryptographic primitives for academic networking coursework.

## 🔒 Security Notice

> **Foundation Phase**: This is the architectural foundation of SecureChat. Encryption is NOT yet implemented.
> All communication is currently in plaintext. Phase 2 will implement AES-GCM encryption and ECDH key exchange.

## 📁 Project Structure

```
SecureChat-System/
├── SecureChat.sln                # Solution file
├── src/
│   ├── SecureChat.Core/          # Shared library
│   │   ├── Models/               # Message, User, MessageType
│   │   ├── Security/
│   │   │   ├── Interfaces/       # IKeyExchange, ISymmetricEncryption, IMessageSigner
│   │   │   └── Stubs/            # Placeholder implementations
│   │   ├── Networking/           # Message serialization
│   │   └── Utilities/            # Logging, SecureRandom
│   │
│   ├── SecureChat.Server/        # TCP chat server
│   │   ├── ChatServer.cs         # Main server, accepts connections
│   │   ├── ClientHandler.cs      # Per-client message handling
│   │   └── ClientManager.cs      # Client registry, broadcasting
│   │
│   └── SecureChat.Client/        # TCP chat client
│       ├── ChatClient.cs         # High-level chat operations
│       └── ServerConnection.cs   # TCP connection management
```

## 🚀 Quick Start

### Prerequisites
- .NET 8.0 SDK or later

### Build
```bash
dotnet build SecureChat.sln
```

### Run Server
```bash
dotnet run --project src/SecureChat.Server
# Or with custom port:
dotnet run --project src/SecureChat.Server -- 8080
```

### Run Client
```bash
# In a separate terminal
dotnet run --project src/SecureChat.Client
# Or connect to custom host/port:
dotnet run --project src/SecureChat.Client -- 192.168.1.100 8080
```

## 🔐 Security Architecture

### Design Principles
1. **Security by Design** - Interfaces designed for encryption from the start
2. **Defense in Depth** - Multiple layers of validation
3. **Fail Secure** - Errors don't compromise security
4. **No Hardcoded Credentials** - Configuration externalized

### Security Interfaces (Phase 2 Implementation)
| Interface | Purpose | Planned Algorithm |
|-----------|---------|-------------------|
| `IKeyExchange` | Session key establishment | ECDH (X25519) |
| `ISymmetricEncryption` | Message encryption | AES-256-GCM |
| `IMessageSigner` | Message integrity | HMAC-SHA256 |

### Current Security Measures
- ✅ Message size limits (DoS prevention)
- ✅ Input sanitization (XSS prevention)
- ✅ Timestamp validation (Replay attack mitigation)
- ✅ Length-prefixed framing (Injection prevention)
- ✅ Cryptographic random number generator
- ✅ Security event logging

### Known Risks (Phase 1)
| Risk | Status | Phase 2 Mitigation |
|------|--------|-------------------|
| Plaintext transmission | ⚠️ Vulnerable | AES-GCM encryption |
| No authentication | ⚠️ Vulnerable | Public key authentication |
| No key exchange | ⚠️ Vulnerable | ECDH implementation |
| Message tampering | ⚠️ Vulnerable | HMAC signatures |

## 📋 Message Protocol

### Wire Format
```
┌──────────────────┬─────────────────────────────────────┐
│ 4 bytes (Int32)  │         N bytes (UTF-8 JSON)        │
│   Message Length │           Message Payload           │
│   (Big-Endian)   │                                     │
└──────────────────┴─────────────────────────────────────┘
```

### Message Types
- `Text` - Regular chat message
- `Join` - User joining notification
- `Leave` - User leaving notification
- `KeyExchange` - Public key exchange (Phase 2)
- `Encrypted` - Encrypted payload (Phase 2)
- `Error` - Error notification
- `System` - Server announcements

## 🛠️ Development

### Adding New Features
1. Define interface in `SecureChat.Core`
2. Create stub implementation for testing
3. Implement in Server/Client as needed
4. Add appropriate logging

### Code Style
- XML documentation on all public members
- Security rationale in comments
- Warnings treated as errors
- Nullable reference types enabled

## 📄 License

This project is for academic purposes.

## 🤝 Contributing

This is an academic project. Contributions should focus on security improvements and cryptographic implementation.
