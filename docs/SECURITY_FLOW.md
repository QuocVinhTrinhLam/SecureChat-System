# Luồng Bảo Mật & Hạn Chế SecureChat

**Phiên bản**: 2.0  
**Trạng thái**: Đã triển khai  
**Cập nhật lần cuối**: 27/01/2026

---

## Tổng Quan

Tài liệu này mô tả luồng bảo mật end-to-end của SecureChat-System, cách các thành phần tương tác, và các hạn chế bảo mật đã biết.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Luồng Bảo Mật SecureChat                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Kết nối TCP  →  2. Trao đổi khóa  →  3. Nhắn tin/File  →  4. Server     │
│                        ECDH P-256         Mã hóa E2E          Relay         │
├─────────────────────────────────────────────────────────────────────────────┤
│  SecureSession điều phối: ECDH + HKDF + AES-256-GCM + HMAC-SHA256           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Mô Hình Bảo Mật

### Kiến Trúc Client-Server Hiện Tại

```mermaid
flowchart TB
    subgraph Client_A[Client A - Vinh]
        CA_Session[SecureSession A]
    end
    
    subgraph Server[Server]
        S_Session_A[SecureSession với A]
        S_Logic[Message Router]
        S_Session_B[SecureSession với B]
    end
    
    subgraph Client_B[Client B - Hoang]
        CB_Session[SecureSession B]
    end
    
    CA_Session <-->|"Encrypted (Key A-S)"| S_Session_A
    S_Session_A --> S_Logic
    S_Logic --> S_Session_B
    S_Session_B <-->|"Encrypted (Key B-S)"| CB_Session
```

> [!IMPORTANT]
> **Mô hình hiện tại**: Server đóng vai trò **relay trung gian**. Mỗi client thiết lập phiên bảo mật riêng với server. Khi client A gửi tin nhắn cho client B:
> 1. Server **giải mã** tin nhắn với khóa A-Server
> 2. Server **mã hóa lại** tin nhắn với khóa B-Server
> 3. Server **chuyển tiếp** đến client B

---

## Luồng Bảo Mật End-to-End

### Sơ Đồ Trình Tự Hoàn Chỉnh

```mermaid
sequenceDiagram
    participant C as Client
    participant SS_C as SecureSession (Client)
    participant Net as TCP Network
    participant SS_S as SecureSession (Server)
    participant S as Server

    Note over C,S: GIAI ĐOẠN 1: Thiết lập kết nối
    C->>Net: Kết nối TCP
    Net->>S: Chấp nhận kết nối
    
    Note over C,S: GIAI ĐOẠN 2: Khởi tạo phiên
    C->>SS_C: InitializeAsync()
    SS_C->>SS_C: Tạo cặp khóa ECDH
    SS_C->>SS_C: Tạo Session ID
    S->>SS_S: InitializeAsync()
    SS_S->>SS_S: Tạo cặp khóa ECDH
    
    Note over C,S: GIAI ĐOẠN 3: Trao đổi khóa
    SS_C->>Net: KeyExchange {publicKey}
    Net->>SS_S: KeyExchange {publicKey}
    SS_S->>SS_S: ValidatePublicKey()
    SS_S->>SS_S: DeriveSharedSecret()
    SS_S->>SS_S: HKDF → (encKey, macKey)
    
    SS_S->>Net: KeyExchange {publicKey}
    Net->>SS_C: KeyExchange {publicKey}
    SS_C->>SS_C: ValidatePublicKey()
    SS_C->>SS_C: DeriveSharedSecret()
    SS_C->>SS_C: HKDF → (encKey, macKey)
    
    Note over C,S: Cả hai có cùng encKey và macKey
    
    Note over C,S: GIAI ĐOẠN 4: Nhắn tin mã hóa
    C->>SS_C: EncryptMessageAsync(message)
    SS_C->>SS_C: AES-256-GCM Encrypt
    SS_C->>SS_C: HMAC-SHA256 Sign
    SS_C->>Net: Encrypted Message + HMAC
    Net->>SS_S: Encrypted Message + HMAC
    SS_S->>SS_S: Verify HMAC
    SS_S->>SS_S: AES-256-GCM Decrypt
    SS_S->>S: Plaintext Message
    
    Note over C,S: GIAI ĐOẠN 5: Kết thúc phiên
    C->>SS_C: Dispose()
    SS_C->>SS_C: Xóa khóa khỏi bộ nhớ
```

---

## Luồng Tin Nhắn Trực Tiếp (Direct Message)

### Routing Qua Server

```mermaid
sequenceDiagram
    participant A as Client A (Vinh)
    participant S as Server
    participant B as Client B (Hoang)
    
    Note over A,B: Tin nhắn từ A đến B
    
    A->>A: EncryptMessageAsync(msg, keyA-S)
    A->>S: Encrypted Message (A→S)
    S->>S: DecryptMessageAsync(keyA-S)
    S->>S: Read recipientName = "Hoang"
    S->>S: EncryptMessageAsync(msg, keyB-S)
    S->>B: Encrypted Message (S→B)
    B->>B: DecryptMessageAsync(keyB-S)
    B->>B: Display message from Vinh
    
    Note over A,B: Echo lại cho người gửi
    S->>S: EncryptMessageAsync(msg, keyA-S)
    S->>A: Encrypted Echo (S→A)
    A->>A: Display sent message
```

---

## Luồng File Transfer

### Sơ Đồ File Transfer

```mermaid
sequenceDiagram
    participant Sender as Client Gửi
    participant FTS as FileTransferService
    participant Server as Server
    participant Receiver as Client Nhận

    Note over Sender,Receiver: GIAI ĐOẠN 1: Chuẩn bị file
    Sender->>FTS: PrepareFileForSendingAsync(filePath)
    FTS->>FTS: Tính SHA-256 hash
    FTS->>FTS: Chia file thành chunks 64KB
    FTS-->>Sender: FileMetadata (fileId, fileName, totalChunks)

    Note over Sender,Receiver: GIAI ĐOẠN 2: Gửi metadata
    Sender->>Server: Encrypted FileMetadata
    Server->>Server: Decrypt + Re-encrypt
    Server->>Receiver: Encrypted FileMetadata
    Receiver->>FTS: StartReceiving(metadata)

    Note over Sender,Receiver: GIAI ĐOẠN 3: Gửi chunks
    loop Cho mỗi chunk
        Sender->>FTS: ReadFileChunksAsync()
        FTS-->>Sender: FileChunkData (Base64)
        Sender->>Server: Encrypted Chunk
        Server->>Server: Decrypt + Re-encrypt
        Server->>Receiver: Encrypted Chunk
        Receiver->>FTS: ReceiveChunk(chunkData)
    end

    Note over Sender,Receiver: GIAI ĐOẠN 4: Hoàn tất
    Sender->>Server: FileComplete message
    Server->>Receiver: FileComplete message
    Receiver->>FTS: SaveReceivedFileAsync()
    FTS->>FTS: Verify SHA-256 hash
    FTS-->>Receiver: File saved to Downloads
```

### Cấu Trúc File Transfer Messages

```
┌─────────────────────────────────────────────────────────────┐
│                     FileMetadata                             │
├─────────────────────────────────────────────────────────────┤
│  fileId: "unique-guid"                                      │
│  fileName: "document.pdf"                                   │
│  fileSize: 54930 (bytes)                                    │
│  totalChunks: 1                                             │
│  fileHash: "Base64(SHA-256)"                                │
│  contentType: "application/pdf"                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     FileChunkData                            │
├─────────────────────────────────────────────────────────────┤
│  fileId: "same-guid-as-metadata"                            │
│  chunkIndex: 0 (0-based)                                    │
│  data: "Base64(chunk data up to 64KB)"                      │
│  totalChunks: 1                                             │
└─────────────────────────────────────────────────────────────┘
```

### Giới Hạn File Transfer

| Thuộc tính | Giá trị | Ghi chú |
|------------|---------|---------|
| Chunk Size | 64 KB | Mỗi chunk tối đa 65,536 bytes |
| Max Message Size | 512 KB | Bao gồm JSON + encryption overhead |
| Max Content Length | 500,000 chars | Hỗ trợ Base64 chunks + encryption |
| File Save Location | ~/Downloads | Tự động lưu vào thư mục Downloads |

---

## Tương Tác Giữa Các Thành Phần

### Sơ Đồ Thành Phần

```mermaid
flowchart TB
    subgraph SecureSession
        Init[InitializeAsync]
        KE[GetKeyExchangeMessage]
        PKE[ProcessKeyExchangeMessage]
        Enc[EncryptMessageAsync]
        Dec[DecryptMessageAsync]
    end
    
    subgraph Components[Các Thành Phần Mã Hóa]
        ECDH[EcdhKeyExchange]
        HKDF[HkdfKeyDerivation]
        AES[AesGcmEncryption]
        HMAC[HmacSha256Signer]
    end
    
    subgraph FileTransfer[File Transfer]
        FTS[FileTransferService]
        Prepare[PrepareFileForSendingAsync]
        Read[ReadFileChunksAsync]
        Receive[ReceiveChunk]
        Save[SaveReceivedFileAsync]
    end
    
    Init --> ECDH
    KE --> ECDH
    PKE --> ECDH
    PKE --> HKDF
    Enc --> AES
    Enc --> HMAC
    Dec --> HMAC
    Dec --> AES
    
    FTS --> Prepare
    FTS --> Read
    FTS --> Receive
    FTS --> Save
```

### Vai Trò Từng Thành Phần

| Thành Phần | File | Vai Trò |
|------------|------|---------|
| **SecureSession** | [SecureSession.cs](file:///Users/quocvinhtrinhlam/Desktop/SecureChat-System/src/SecureChat.Core/Security/Implementations/SecureSession.cs) | Điều phối toàn bộ quy trình mã hóa |
| **EcdhKeyExchange** | [EcdhKeyExchange.cs](file:///Users/quocvinhtrinhlam/Desktop/SecureChat-System/src/SecureChat.Core/Security/Implementations/EcdhKeyExchange.cs) | Trao đổi khóa ECDH P-256 |
| **HkdfKeyDerivation** | [HkdfKeyDerivation.cs](file:///Users/quocvinhtrinhlam/Desktop/SecureChat-System/src/SecureChat.Core/Security/Implementations/HkdfKeyDerivation.cs) | Dẫn xuất khóa từ shared secret |
| **AesGcmEncryption** | [AesGcmEncryption.cs](file:///Users/quocvinhtrinhlam/Desktop/SecureChat-System/src/SecureChat.Core/Security/Implementations/AesGcmEncryption.cs) | Mã hóa AES-256-GCM |
| **HmacSha256Signer** | [HmacSha256Signer.cs](file:///Users/quocvinhtrinhlam/Desktop/SecureChat-System/src/SecureChat.Core/Security/Implementations/HmacSha256Signer.cs) | Xác thực toàn vẹn HMAC |
| **FileTransferService** | [FileTransferService.cs](file:///Users/quocvinhtrinhlam/Desktop/SecureChat-System/src/SecureChat.Core/Services/FileTransferService.cs) | Xử lý gửi/nhận file |
| **JsonMessageSerializer** | [JsonMessageSerializer.cs](file:///Users/quocvinhtrinhlam/Desktop/SecureChat-System/src/SecureChat.Core/Networking/JsonMessageSerializer.cs) | Serialize/deserialize messages |

---

## Chi Tiết Các Luồng

### 1. Luồng Trao Đổi Khóa

```mermaid
flowchart TD
    subgraph Khởi tạo
        A[GenerateKeyPairAsync] --> B[Tạo ECDH P-256]
        B --> C[Export SPKI Public Key]
    end
    
    subgraph Trao đổi
        D[Nhận Public Key của peer]
        D --> E{ValidatePublicKey}
        E -->|Hợp lệ| F[DeriveSharedSecretAsync]
        E -->|Không hợp lệ| G[Từ chối kết nối]
    end
    
    subgraph Dẫn xuất khóa
        F --> H[HKDF-SHA256]
        H --> I[Encryption Key 32 bytes]
        H --> J[MAC Key 32 bytes]
    end
    
    C --> D
```

**Các bước xác thực khóa**:
1. Kiểm tra Base64 hợp lệ
2. Import thành công dưới dạng SPKI
3. Xác minh đường cong P-256
4. Kiểm tra tất cả bytes được sử dụng

### 2. Luồng Mã Hóa Tin Nhắn (Encrypt-then-MAC)

```mermaid
flowchart LR
    subgraph Input
        A[Plaintext Message]
    end
    
    subgraph Serialize
        A --> B[JSON với type, sender, content, fileMetadata, fileChunkData]
    end
    
    subgraph Mã hóa
        B --> C[AES-256-GCM]
        C --> D[Ciphertext + Auth Tag]
    end
    
    subgraph Xác thực
        D --> E[HMAC-SHA256]
        E --> F[HMAC Tag]
    end
    
    subgraph Output
        D --> G[Encrypted Message]
        F --> G
    end
```

**Cấu trúc tin nhắn mã hóa**:
```
┌─────────────────────────────────────────────────────────────┐
│                    Encrypted Message                         │
├─────────────────────────────────────────────────────────────┤
│  type: "Encrypted"                                          │
│  senderId: sender UUID                                      │
│  senderName: "Vinh"                                         │
│  recipientName: "Hoang" (optional)                          │
│  content: Base64(ciphertext)                                │
├─────────────────────────────────────────────────────────────┤
│  securityMetadata:                                          │
│    ├── algorithm: "AES-256-GCM"                             │
│    ├── iv: Base64(nonce 12 bytes)                           │
│    ├── signature: Base64(GCM auth tag 16 bytes)             │
│    ├── hmac: Base64(HMAC-SHA256 32 bytes)                   │
│    └── keyId: session identifier                            │
└─────────────────────────────────────────────────────────────┘
```

### 3. Luồng Giải Mã Tin Nhắn (Verify-then-Decrypt)

```mermaid
flowchart LR
    subgraph Xác minh
        A[Encrypted Message] --> B{HMAC Valid?}
        B -->|Không| C[SecurityException]
    end
    
    subgraph Giải mã
        B -->|Có| D[AES-256-GCM Decrypt]
        D --> E{GCM Tag Valid?}
        E -->|Không| F[CryptographicException]
        E -->|Có| G[Plaintext JSON]
    end
    
    subgraph Phục hồi
        G --> H[Deserialize Message]
        H --> I[Extract FileMetadata/FileChunkData if present]
    end
```

> [!IMPORTANT]
> **HMAC được xác minh TRƯỚC khi giải mã** để ngăn chặn các tấn công oracle và đảm bảo tin nhắn không bị giả mạo.

---

## Server Message Handling

### Các Loại Message và Xử Lý

```mermaid
flowchart TD
    Receive[Nhận Message] --> Check{Message Type?}
    
    Check -->|KeyExchange| KE[HandleKeyExchangeAsync]
    Check -->|Encrypted| ENC[HandleEncryptedMessageAsync]
    Check -->|File/FileChunk/FileComplete| FILE[HandleFileTransferAsync]
    Check -->|Join| JOIN[HandleJoinAsync]
    Check -->|Leave| LEAVE[HandleLeaveAsync]
    
    ENC --> Route{Has RecipientName?}
    Route -->|Yes| Direct[RouteDirectMessageAsync]
    Route -->|No| Broadcast[BroadcastMessageAsync]
    
    Direct --> Decrypt1[Decrypt với key người gửi]
    Decrypt1 --> Encrypt1[Encrypt với key người nhận]
    Encrypt1 --> Send1[Gửi đến người nhận]
    Encrypt1 --> Echo1[Echo lại người gửi]
    
    FILE --> DecryptFile[Decrypt file message]
    DecryptFile --> EncryptFile[Encrypt với key người nhận]
    EncryptFile --> SendFile[Gửi đến người nhận]
```

---

## Các Hạn Chế Đã Biết

### Bảng Tóm Tắt

| Hạn chế | Mức độ | Mô tả |
|---------|--------|-------|
| Server có thể đọc tin nhắn | Cao | Server làm relay, giải mã và mã hóa lại |
| Không có xác thực lẫn nhau | Cao | TOFU (Trust On First Use) |
| Không có key rotation | Trung bình | Khóa cố định trong suốt phiên |
| Không có session resumption | Thấp | Phải trao đổi khóa mới mỗi lần kết nối |
| Không có PKI | Cao | Không có certificate authority |

### Chi Tiết Hạn Chế

#### 1. Server Có Thể Đọc Tin Nhắn (Server-Relayed Model)

```
┌─────────────────────────────────────────────────────────────┐
│  CẢNH BÁO: Server là trung gian giải mã                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Client A ──(enc)──> Server ──(enc)──> Client B             │
│                        ↓                                    │
│                   [Đọc được plaintext]                      │
│                                                             │
│  • Server giữ SecureSession riêng với mỗi client            │
│  • Server giải mã tin nhắn để routing                       │
│  • Không phải true E2E encryption                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

> [!CAUTION]
> **Hệ thống hiện tại KHÔNG cung cấp E2E thực sự**. Server có khả năng đọc tất cả tin nhắn vì nó phải giải mã để route.

#### 2. Không Có Xác Thực Lẫn Nhau (TOFU Model)

- Client không xác minh danh tính Server
- Server không xác minh danh tính Client
- Dễ bị tấn công MITM trong lần kết nối đầu tiên

#### 3. Không Có Key Rotation

- Khóa phiên (`encryptionKey`, `macKey`) được tạo một lần
- Nếu khóa bị lộ, tất cả tin nhắn trong phiên đó có thể bị giải mã

#### 4. File Transfer Không Có E2E

- File chunks đi qua server và bị giải mã/mã hóa lại
- Server có thể đọc nội dung file được truyền

---

## Các Vector Tấn Công & Biện Pháp

### Bảng Tổng Quan

| Tấn công | Trạng thái | Biện pháp |
|----------|------------|-----------|
| Man-in-the-Middle (Server) | Không bảo vệ | Server là trusted party |
| Man-in-the-Middle (Network) | Đã bảo vệ | TLS-like encryption |
| Replay Attack | Đã xử lý | Message ID + Timestamp |
| Timing Attack | Đã xử lý | FixedTimeEquals |
| Invalid Curve Attack | Đã xử lý | Public key validation |
| Tampering | Đã xử lý | AES-GCM + HMAC |
| Large Message DoS | Đã xử lý | MaxContentLength = 500,000 |

### Chi Tiết Biện Pháp

#### 1. Chống Tấn Công Timing

```csharp
// SecureChat sử dụng so sánh thời gian hằng số
CryptographicOperations.FixedTimeEquals(computedHmac, expectedHmac);
```

#### 2. Chống Invalid Curve Attack

```csharp
// Xác minh khóa nằm trên đường cong P-256
if (parameters.Curve.Oid?.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
{
    return false; // Từ chối khóa không hợp lệ
}
```

#### 3. Chống Replay Attack

- **Message ID**: Mỗi tin nhắn có UUID duy nhất
- **Timestamp**: Xác minh tin nhắn trong khoảng ±5 phút
- **Session ID**: Khóa chỉ hợp lệ trong phiên hiện tại

#### 4. Bảo Vệ Toàn Vẹn Kép

SecureChat sử dụng cả:
- **AES-GCM Authentication Tag**: Bảo vệ tầng trong
- **HMAC-SHA256**: Bảo vệ tầng ngoài (Encrypt-then-MAC)

#### 5. Giới Hạn Kích Thước Tin Nhắn

```csharp
// Ngăn chặn DoS bằng tin nhắn lớn
public const int MaxMessageSize = 512 * 1024; // 512 KB
const int MaxContentLength = 500_000; // Characters
```

---

## Khuyến Nghị Cải Tiến

### Ưu Tiên Cao

| Cải tiến | Mô tả |
|----------|-------|
| **True E2E Encryption** | Clients trao đổi khóa trực tiếp, server chỉ relay encrypted blobs |
| **Mutual Authentication** | Thêm xác thực lẫn nhau bằng certificate hoặc pre-shared key |
| **Key Rotation** | Triển khai rekeying định kỳ hoặc sau N tin nhắn |

### Ưu Tiên Trung Bình

| Cải tiến | Mô tả |
|----------|-------|
| **Double Ratchet** | Áp dụng Signal Protocol cho PFS ở mức tin nhắn |
| **Message Deduplication** | Theo dõi Message ID để chống replay |
| **File Encryption E2E** | Mã hóa file trước khi gửi, server chỉ relay |

### Ưu Tiên Thấp

| Cải tiến | Mô tả |
|----------|-------|
| **Session Resumption** | Cho phép resume session đã thiết lập |
| **Post-Quantum Crypto** | Chuẩn bị cho kỷ nguyên quantum computing |

---

## Xem Thêm

- [ARCHITECTURE.md](file:///Users/quocvinhtrinhlam/Desktop/SecureChat-System/docs/ARCHITECTURE.md) - Tổng quan kiến trúc
- [CRYPTOGRAPHY.md](file:///Users/quocvinhtrinhlam/Desktop/SecureChat-System/docs/CRYPTOGRAPHY.md) - Đặc tả thuật toán
- [MESSAGE_PROTOCOL.md](file:///Users/quocvinhtrinhlam/Desktop/SecureChat-System/docs/MESSAGE_PROTOCOL.md) - Giao thức tin nhắn
- [CODE_EXPLANATION.md](file:///Users/quocvinhtrinhlam/Desktop/SecureChat-System/docs/CODE_EXPLANATION.md) - Giải thích chi tiết code
