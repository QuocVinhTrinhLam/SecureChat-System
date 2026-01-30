# Luồng Bảo Mật & Hạn Chế SecureChat

**Phiên bản**: 2.0  
**Trạng thái**: Đã triển khai  
**Cập nhật lần cuối**: 27/01/2026

---

## Tổng Quan

Tài liệu này mô tả luồng bảo mật end-to-end của SecureChat-System, cách các thành phần tương tác, và các hạn chế bảo mật đã biết.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Luồng Bảo Mật SecureChat (Hybrid)                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Kết nối TCP  →  2. Trao đổi khóa  →  3. Hybrid Message Routing          │
│                        ECDH P-256         (Ưu tiên E2E, Fallback Relay)     │
├─────────────────────────────────────────────────────────────────────────────┤
│  SecureSession điều phối: ECDH + HKDF + AES-256-GCM + HMAC-SHA256           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Bộ Não Bảo Mật (The Security Brain)

Để hiểu rõ cách hệ thống xử lý bảo mật, hãy hình dung "bộ não" này gồm 2 bán cầu chính: **Trao Đổi (Exchange)** và **Dẫn Xuất (Derivation)**.

### 1. Phân Biệt ECDH và HKDF

| Thành Phần | File Code | Loại Hình | Vai Trò Thực Sự |
|------------|-----------|-----------|-----------------|
| **ECDH** | `EcdhKeyExchange.cs` | **Trao đổi qua mạng** | Phối hợp giữa 2 bên để tạo ra một bí mật chung (Shared Secret). Cần gửi Public Key qua mạng. |
| **HKDF** | `HkdfKeyDerivation.cs` | **Xử lý cục bộ** | Từ bí mật chung đó, "xay" ra các chìa khóa cụ thể để sử dụng. Không bao giờ gửi qua mạng. |

#### Mô Hình Tư Duy Đúng (Correct Mental Model)

```
┌─────────────────────────────────────────────────────────────────────────┐
│              SỰ PHỐI HỢP GIỮA ECDH VÀ HKDF                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Client A (Alice)                         Client B (Bob)               │
│   ────────────────                         ──────────────               │
│                                                                         │
│   1️⃣ ECDH (Trao đổi)                       1️⃣ ECDH (Trao đổi)            │
│   • Tạo Private/Public Key                 • Tạo Private/Public Key     │
│   • Gửi Public Key A ──────────>           • Nhận Public Key A          │
│   • Nhận Public Key B <──────────          • Gửi Public Key B           │
│          ↓                                        ↓                     │
│   ⚡ Shared Secret (Giống nhau) ⚡         ⚡ Shared Secret (Giống nhau) ⚡ │
│          ↓                                        ↓                     │
│                                                                         │
│   ════════════════════════════════════════════════════════════════════  │
│          🛑 Ranh giới mạng (Ngừng gửi dữ liệu bảo mật tại đây) 🛑         │
│   ════════════════════════════════════════════════════════════════════  │
│                                                                         │
│   2️⃣ HKDF (Dẫn xuất cục bộ)                2️⃣ HKDF (Dẫn xuất cục bộ)     │
│   • Input: Shared Secret                   • Input: Shared Secret       │
│   • Output:                                • Output:                    │
│     🔑 Encryption Key                        🔑 Encryption Key          │
│     🔖 MAC Key                               🔖 MAC Key                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2. Vai Trò Của Các Loại Khóa (Defense in Depth)

Hệ thống sử dụng mô hình **Encrypt-then-MAC** để bảo vệ kép.

#### 🔑 Encryption Key (Khóa Mã Hóa) - Bảo Mật (Confidentiality)
*   **Mục đích**: Giấu nội dung tin nhắn.
*   **Cơ chế**: Dùng AES-256-GCM. Biến "Hello" thành `xc9f1...`.
*   **Ví dụ**: Giống như **Chiếc Chìa Khóa** két sắt. Chỉ người có chìa mới mở két đọc thư được.

#### 🔖 MAC Key (Khóa Xác Thực) - Toàn Vẹn (Integrity)
*   **Mục đích**: Đảm bảo tin nhắn chính chủ và không bị sửa đổi.
*   **Cơ chế**: Dùng HMAC-SHA256. Tạo chữ ký số trên dữ liệu đã mã hóa.
*   **Ví dụ**: Giống như **Con Dấu Niêm Phong** dán ngoài két sắt.
    *   Nếu niêm phong rách → Có kẻ gian đụng vào két.
    *   Nếu niêm phong lạ → Không phải két chính chủ gửi.

> [!TIP]
> **Quy trình nhận tin**: Kiểm tra **Niêm phong (MAC)** trước 🧐. Nếu xịn mới dùng **Chìa khóa (Encryption Key)** mở két 🔓.

---

## Mô Hình Bảo Mật Lai (Hybrid Security Model)

Hệ thống sử dụng cơ chế bảo mật lai thông minh, ưu tiên **True E2E** và tự động chuyển sang **Server Relay** nếu cần thiết.

### 1. Cơ Chế Ưu Tiên (Priority Logic)
Client sẽ luôn cố gắng thiết lập kênh bảo mật trực tiếp (E2E) trước.

```mermaid
flowchart TD
    A[Gửi Tin Nhắn Direct] --> B{Đã có E2E Session?}
    B -->|Có| C[Gửi qua kênh E2E]
    B -->|Chưa| D[Thử Key Exchange với Peer]
    
    D --> E{Thành công?}
    E -->|OK| F[Lưu Session] --> C
    E -->|Timeout (5s)| G[Fallback: Server Relay]
    
    C -->|Mã hóa với Key Peer| H[Server Blind Forward]
    G -->|Mã hóa với Key Server| I[Server Decrypt/Re-encrypt]
```

### 2. Hai Chế Độ Hoạt Động

#### ✅ Chế Độ 1: True E2E (Ưu Tiên)
*   **Kích hoạt**: Khi 2 client trao đổi key thành công.
*   **Bảo mật**: Server **KHÔNG THỂ** đọc tin nhắn (do không có Shared Secret của 2 client).
*   **Luồng**: `Client A (Encrypt E2E) --> Server (Blind Forward) --> Client B (Decrypt E2E)`

#### ⚠️ Chế Độ 2: Server Relay (Fallback)
*   **Kích hoạt**: Khi kết nối P2P thất bại hoặc timeout (5s).
*   **Bảo mật**: Server **CÓ THỂ** đọc tin nhắn (Server-in-the-Middle).
*   **Luồng**: `Client A (Encrypt Server) --> Server (Decrypt & Re-encrypt) --> Client B (Decrypt Server)`

> [!NOTE]
> Đoạn mô tả trong hình ảnh bạn đề cập ("Mô hình hiện tại: Server đóng vai trò relay...") chính là mô tả cho **Chế Độ 2 (Fallback)** khi E2E không khả dụng.

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

## Luồng Tin Nhắn Trực Tiếp (Direct Message Flow)

### 1. Luồng E2E (Mặc định)

```mermaid
sequenceDiagram
    participant A as Client A
    participant S as Server
    participant B as Client B
    
    Note over A,B: Giai đoạn Handshake (Một lần)
    A->>S: PeerKeyExchange (Public Key A)
    S->>B: Forward KeyExchange
    B->>S: PeerKeyExchangeResponse (Public Key B)
    S->>A: Forward Response
    Note over A,B: Đã thiết lập Shared Secret (Server không biết)

    Note over A,B: Giai đoạn Nhắn tin
    A->>A: Encrypt(msg, Key_AB)
    A->>S: Encrypted E2E Message
    S->>S: Routing (Blind Forward)
    S->>B: Encrypted E2E Message
    B->>B: Decrypt(msg, Key_AB)
```

### 2. Luồng Fallback (Relay Mode)
*Tự động kích hoạt khi E2E handshake thất bại hoặc timeout.*

```mermaid
sequenceDiagram
    participant A as Client A
    participant S as Server
    participant B as Client B
    
    A->>A: Encrypt(msg, Key_AS)
    A->>S: Encrypted Message
    S->>S: Decrypt(Key_AS) -> Plaintext -> Encrypt(Key_BS)
    S->>B: Re-Encrypted Message
    B->>B: Decrypt(Key_BS)
```

---

## Luồng File Transfer

### Sơ Đồ File Transfer (E2EE Enforced)

```mermaid
sequenceDiagram
    participant Sender as Client Gửi
    participant FTS as FileTransferService
    participant PSM as PeerSessionManager
    participant Server as Server
    participant Receiver as Client Nhận

    Note over Sender,Receiver: GIAI ĐOẠN 1: Chuẩn bị file & Handshake
    Sender->>FTS: PrepareFileForSendingAsync(filePath)
    FTS-->>Sender: FileMetadata (fileId, hash, etc.)
    Sender->>PSM: Establish E2E Session (if needed)
    
    rect rgb(255, 230, 230)
    Note right of Sender: CRITICAL: Nếu E2EE Handshake thất bại, HỦY transfer.<br/>KHÔNG fallback sang Server Encryption.
    end

    Note over Sender,Receiver: GIAI ĐOẠN 2: Gửi metadata (E2E)
    Sender->>PSM: Encrypt(FileMetadata, RecipientKey)
    Sender->>Server: Encrypted FileMetadata
    Server->>Server: Blind Forward (Can't Decrypt)
    Server->>Receiver: Encrypted FileMetadata
    Receiver->>PSM: Decrypt(RecipientKey)
    Receiver->>FTS: StartReceiving(metadata)

    Note over Sender,Receiver: GIAI ĐOẠN 3: Gửi chunks (E2E)
    loop Cho mỗi chunk
        Sender->>FTS: ReadFileChunksAsync()
        FTS-->>Sender: FileChunkData
        Sender->>PSM: Encrypt(Chunk, RecipientKey)
        Sender->>Server: Encrypted Chunk
        Server->>Server: Blind Forward
        Server->>Receiver: Encrypted Chunk
        Receiver->>PSM: Decrypt(RecipientKey)
        Receiver->>FTS: ReceiveChunk(chunkData)
    end

    Note over Sender,Receiver: GIAI ĐOẠN 4: Hoàn tất
    Sender->>PSM: Encrypt(FileComplete)
    Sender->>Server: Encrypted FileComplete
    Server->>Receiver: Encrypted FileComplete
    Receiver->>PSM: Decrypt
    Receiver->>FTS: SaveReceivedFileAsync()
    FTS->>FTS: Verify SHA-256 hash
    FTS-->>Receiver: File saved
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
┌─────────────────────────────────────────────────────────────────────────────┐
│  Trạng thái: CHỈ xảy ra ở chế độ Fallback (Text Only)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Client A ──(enc)──> Server ──(enc)──> Client B                             │
│                        ↓                                                    │
│                   [Đọc được plaintext]                                      │
│                                                                             │
│  • Xảy ra khi: E2E Handshake Timeout (Chỉ Text Message)                     │
│  • Server phải giải mã để re-encrypt cho đích                               │
│  • LƯU Ý: File Transfer sẽ THẤT BẠI nếu E2E lỗi (không fallback)            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

> [!WARNING]
> Trong chế độ **True E2E** (mặc định cho tin nhắn văn bản), Server **KHÔNG THỂ** đọc nội dung tin nhắn. Hạn chế này chỉ áp dụng cho chế độ Fallback và File Transfer.

#### 2. Không Có Xác Thực Lẫn Nhau (TOFU Model)

- Client không xác minh danh tính Server
- Server không xác minh danh tính Client
- Dễ bị tấn công MITM trong lần kết nối đầu tiên

#### 3. Không Có Key Rotation

- Khóa phiên (`encryptionKey`, `macKey`) được tạo một lần
- Nếu khóa bị lộ, tất cả tin nhắn trong phiên đó có thể bị giải mã

#### 4. (ĐÃ GIẢI QUYẾT) File Transfer Đã Có E2E

- File chunks được mã hóa E2E bằng Peer Key
- Server CHỈ forward mù (blind forward), không thể đọc nội dung file
- Yêu cầu bắt buộc phải thiết lập được E2E Session để gửi file

---

## Các Vector Tấn Công & Biện Pháp

### Bảng Tổng Quan

| Tấn công | Trạng thái | Biện pháp |
|----------|------------|-----------|
| Man-in-the-Middle (Server) | **Đã bảo vệ** (E2E Mode) | Server không thể giải mã trong chế độ E2E |
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
| **File Encryption E2E** | ✅ Đã triển khai (Strict Mode: No Fallback) |
| **Mutual Authentication** | Thêm xác thực lẫn nhau bằng certificate hoặc pre-shared key |
| **Key Rotation** | Triển khai rekeying định kỳ hoặc sau N tin nhắn |

### Ưu Tiên Trung Bình

| Cải tiến | Mô tả |
|----------|-------|
| **Double Ratchet** | Áp dụng Signal Protocol cho PFS ở mức tin nhắn |
| **Message Deduplication** | Theo dõi Message ID để chống replay |

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
