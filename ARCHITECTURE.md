# DistributionVC - Architektura i Projektowanie

## Przegląd Systemu

**KLUCZOWA KONCEPCJA: Serwer na maszynie SGX jest "blind proxy"**

```
┌─────────────────────────────────────────────────────────────┐
│                    DistributionVC System                    │
└─────────────────────────────────────────────────────────────┘

   Untrusted Server Space          Trusted (SGX Enclave)
   ──────────────────────          ──────────────────────

   ┌─────────────────┐
   │  Receiver       │                
   │  Client         │─────TLS──────┐ (encrypted)
   │                 │◀─────TLS─────┤
   └─────────────────┘               │
                                     ▼
                          ┌─────────────────────┐
                          │ Untrusted Server    │
                          │ (BLIND PROXY)       │
                          │                     │
                          │ ❌ Nie wie co są    │
                          │ ❌ encrypted buffers│
                          │ ✅ Przekazuje tylko│
                          │    OCALL buffers   │
                          └──────────┬──────────┘
                                     │ OCALL
                                     │ (opaque)
                                     ▼
                          ┌───────────────────────────┐
                          │  SGX Enclave (Trusted)    │
                          │                           │
                          │  ✅ Decrypts data         │
                          │  ✅ TLS z relay'ami       │
                          │  ✅ Query relay servers   │
                          │  ✅ Aggregate data        │
                          │  ✅ Process securely      │
                          │  ✅ Encrypt results       │
                          │                           │
   ┌──────────────┐ │◀────OCALL────│ ┌──────────────┐
   │ Relay 1      │ │  (encrypted)  │ │ Relay 2      │
   │ Port 13001   │ │               │ │ Port 13002   │
   └──────────────┘ └───────────────┘ └──────────────┘
                          ▲
                   OCALL (encrypted)
                   Enklaawa sama
                   inicjuje TLS
```

**KRYTYCZNE: Serwer nigdy nie widzi plaintext danych!**

## Komponenty

### 1. App/Server.cpp - Blind Proxy Serwer

**Odpowiedzialność:**
- ✅ Tworzy enklavę SGX
- ✅ Zarządza TLS connections od klientów (encrypted)
- ✅ Przekazuje encrypted buffers do/z enklaawy (OCALL)
- ❌ NIE widzi jakie dane są w bufferach
- ❌ NIE wie co enklaawa robi

**KRYTYCZNE: Serwer jest "blind" - wszystko encrypted!**

**Przepływ (simplified):**
```
1. main()
   ├─ initialize_enclave()  [Tworzy enklavę]
   ├─ Create WolfSSL context
   ├─ Bind port 12345
   └─ Accept connections
       ├─ client_handler() [Per client thread]
       │  ├─ TLS handshake (encrypted)
       │  ├─ Read encrypted data
       │  ├─ OCALL: ocall_process_encrypted(encrypted_buf)
       │  │   └─ Enklaawa: decrypts, processes, re-encrypts
       │  ├─ Receive encrypted result
       │  └─ Send encrypted result via TLS
       └─ Close connection
```

**Serwer rzeczywiście:**
```cpp
// Receive encrypted data from client
recv_encrypted_data(ssl, encrypted_buf);

// Send to enclave (enklaawa wie co to)
status = ocall_process_request(encrypted_buf, encrypted_result);

// Send back to client (encrypted)
send_encrypted_data(ssl, encrypted_result);

// Serwer NIGDY nie decryptuje!
```

### 2. Enclave/Enclave.cpp - Trusted Enklaawa (HEART OF SYSTEM)

**Odpowiedzialność:**
- ✅ **DEKRYPTUJE encrypted data od klienta**
- ✅ **Inicjuje TLS connection z relay'ami** (INSIDE ENCLAVE!)
- ✅ **Query'je relay'ów securely**
- ✅ **Agreguje i przetwarzauje dane**
- ✅ **Enkryptuje wynik**
- ✅ Zwraca encrypted wynik do Untrusted Servera

**KLUCZOWE: Cała sensowna logika jest WEWNĄTRZ enklaawy!**

**Przepływ (real logic):**
```
Client              Untrusted Server        Enklaawa
  │                     │                    │
  ├─ TLS send ────────▶ │                    │
  │ (encrypted)         │                    │
  │                     ├─ OCALL encrypted ─▶│
  │                     │ buffer             │
  │                     │                    ├─ Decrypt
  │                     │                    ├─ TLS with Relay1
  │                     │◀─ OCALL send ─────┤ (inside enclave!)
  │                     │ (opaque buffer)    │
  │   [Untrusted Server not aware]            │
  │                     │                    ├─ TLS with Relay2
  │                     │◀─ OCALL recv ─────┤ (inside enclave!)
  │                     │ (opaque buffer)    │
  │                     │                    ├─ Aggregate
  │                     │                    ├─ Process
  │                     │                    └─ Encrypt result
  │                     │◀─ OCALL result ───┤
  │                     │ (encrypted)        │
  │◀─ TLS response ────┤
  │ (encrypted)
```

**Enklaawa MUSI zawierać:**
- Decrypt logic
- TLS client (connects to relays)
- Data aggregation logic
- Encrypt logic

**OCALL Interface:**
```cpp
// Enklaawa inicjuje TLS connections
ocall_connect_relay(relay_id, host, port);
ocall_tls_handshake(relay_id);

// Enklaawa wysyła/odbiera szyfrowane dane
ocall_send_encrypted(relay_id, encrypted_query);
ocall_recv_encrypted(relay_id, encrypted_response);

// Enklaawa decrypts/processes wewnątrz siebie
// Rezultat wraca encrypted
```

**Storage:**
```cpp
struct AggregatedData {
    char relay_id[64];
    uint8_t encrypted_data[512];  // Still encrypted!
    uint32_t data_len;
};

// Dekryptuj wewnątrz enklaawy
// Nie wysyłaj plaintext nigdzie poza enklawę!
```

### 3. Receiver/client.cpp - Klient Receivera

**Odpowiedzialność:**
- Inicjuje TLS connection do serwera
- Wysyła dane do agregacji
- Otrzymuje wynik

**Przepływ:**
```
1. main()
   ├─ wolfSSL_library_init()
   ├─ Create SSL context
   ├─ Connect to server:12345
   ├─ TLS handshake
   ├─ Send client identification ("RECEIVER")
   ├─ Send data [size:4][data]
   ├─ Receive result
   └─ Send exit signal (0xFFFFFFFF)
```

**Protokół:**
```
SEND: [4 bytes: size] [N bytes: data]
RECV: [result: ACK:client_id:size]
SEND: [0xFFFFFFFF: exit]
```

### 4. DataServer/relay.cpp - Data Relay Servery

**Odpowiedzialność:**
- Posiadają hardcoded dane
- Odpowiadają na requesty od serwera
- Zwracają swoje dane w response

**Instancje:**
- Relay 1: Port 13001
- Relay 2: Port 13002

**Protokół:**
```
RECV: [4 bytes: size] [N bytes: query data]
SEND: [4 bytes: size] [N bytes: relay data]
```

## TLS / WolfSSL

### Certyfikaty

- Użyte test certificates z `wolfssl/certs_test.h`
- `server_cert_der` - Certyfikat serwera (DER)
- `server_key_der` - Klucz prywatny serwera (DER)

### Handshake

```
Client                              Server
  │                                   │
  ├──────── ClientHello ────────────▶ │
  │                                   │
  │ ◀───────── ServerHello ──────────┤
  │ ◀──────── Certificate ──────────┤
  │ ◀─────── ServerKeyExchange ─────┤
  │ ◀────── ServerHelloDone ────────┤
  │                                   │
  ├───────── ClientKeyExchange ─────▶ │
  ├───────── ChangeCipherSpec ──────▶ │
  ├───────────── Finished ──────────▶ │
  │                                   │
  │ ◀──────── ChangeCipherSpec ─────┤
  │ ◀────────── Finished ───────────┤
  │                                   │
  └─── Encrypted Data Exchange ───────┘
```

## SGX Enklaawa

### SIM Mode

- Nie wymaga SGX sprzętu
- Wszystko uruchamia się w user-space
- Enclave = zwykły shared library
- Brak rzeczywistego hardware isolation

### Budowa Enklaawy

```
Enclave.edl (Interface Definition)
    ↓
sgx_edger8r (Edger8r Tool)
    ├─ Enclave_t.c/h (Trusted proxy)
    └─ Enclave_u.c/h (Untrusted proxy)
    ↓
Enclave.cpp (Implementation)
    ↓
[kompilacja z SGX libs]
    ↓
enclave.so (Shared Library)
    ↓
sgx_sign (Signing Tool)
    ↓
enclave.signed.so (Signed Enclave)
```

### ECall vs OCall

```
App Code              Enclave Code
    │                    │
    ├─── ecall_foo() ───▶ │ (Enter enklavę)
    │                    │
    │ ◀─── ocall_bar() ──┤ (Wyjdź z enklaawy)
    │ (Normal code)      │
    │                    │
    ├─── ecall_baz() ───▶ │ (Ponownie w enkaawie)
    │                    │
    └───────────────────▶│ Done
```

W naszym systemie:
- **ECall**: `ecall_aggregate_data()`, `ecall_process_and_return()`
- **OCall**: `ocall_print_string()` (debug)
- **W przyszłości**: `ocall_query_relay()` - query data servers

## Bezpieczeństwo (Current Design)

### ✅ SECURED:
1. **Client → Server TLS**
   - Data encrypted on wire
   - Server nie zna plaintext

2. **Enclave ← Encrypted Buffer ← Server**
   - Buffer encrypted, serwer blind

3. **Enclave → TLS with Relays**
   - Enklaawa sama robi TLS
   - Nie polega na untrusted serverze

4. **Enclave Processing**
   - All data stays encrypted until inside enclave
   - Dekryption happens securely in hardware isolation
   - Results encrypted before leaving enclave

5. **Enclave → Encrypted Buffer → Server → Client TLS**
   - Server nigdy nie widzi plaintext

### ✅ WHY THIS IS SECURE:
```
[Threat Model: Assume untrusted server code is compromised]

❌ Attacker can:
- See encrypted data (useless without key)
- See network traffic (encrypted)
- Modify untrusted server code
- Try to read memory of untrusted process

✅ Attacker CANNOT:
- Access plaintext data (stays in enclave)
- Know what enklaawa robi (black box)
- Access enclave memory (hardware protected)
- Decrypt data without key (which is in enclave)
```

### ⚠️ Future improvements:
- Real certificates (zamiast test certs)
- Attestation (client weryfikuje enklavę)
- Authenticated encryption
- Hardware SGX mode

## Przepływ Danych (CORRECTED)

```
┌─────────────────────────────────────────────────────────────────┐
│                     COMPLETE DATA FLOW                          │
└─────────────────────────────────────────────────────────────────┘

1. Receiver sends encrypted data to Server (TLS)
   Data: [ENCRYPTED BY CLIENT TLS]
   Server: Receives but CANNOT decrypt (no key)

2. Server sends encrypted buffer to Enclave (OCALL)
   Serwer: Acts as blind proxy, passes opaque buffer

3. Enclave receives encrypted data
   Enklaawa: Decrypts (has key) ✅

4. Enclave decrypts and processes
   ├─ Decrypt client data
   ├─ Initialize TLS with Relay1 (INSIDE enclave)
   ├─ Send encrypted query to Relay1 (via OCALL)
   ├─ Receive encrypted response from Relay1 (via OCALL)
   ├─ Initialize TLS with Relay2 (INSIDE enclave)
   ├─ Send encrypted query to Relay2 (via OCALL)
   ├─ Receive encrypted response from Relay2 (via OCALL)
   └─ Aggregate and process data securely inside enclave

5. Enclave encrypts result
   Result: [ENCRYPTED FOR CLIENT]

6. Enclave sends encrypted result to Server (OCALL)
   Server: Acts as blind proxy, passes opaque buffer

7. Server sends encrypted result to Client (TLS)
   Client: Receives and decrypts with own key

┌────────────────────────────────────────────────────────────────┐
│ KEY INSIGHT:                                                   │
│ Server NEVER sees plaintext. It's just a networking proxy.    │
│ All real work happens INSIDE the enclave.                      │
└────────────────────────────────────────────────────────────────┘
```

**Why this model is stronger:**

1. ✅ **Serwer nie wie co agreguje** - Nie może go zhackować
2. ✅ **TLS with relays od enklawy** - Relays mówią do enklawy, nie do untrusted servera
3. ✅ **Cała logika w enkaawie** - Brak exposure na untrusted layerze
4. ✅ **Enklaawa odpowiada za bezpieczeństwo** - Wszystkie klucze tam są

**This is the correct security model for SGX!**

## Testowanie

### Unit Testing

```bash
# Compile jednotlivých komponentów
make clean
make
```

### Integration Testing

```bash
# Terminal 1
./bin/server

# Terminal 2
./bin/relay_server 1

# Terminal 3
./bin/relay_server 2

# Terminal 4
./bin/receiver_client "test data"
```

## Rozszerzenia

### Plany na przyszłość

1. **OCALL do Query Relay'ów**
   - Enklaawa query'je relay servery
   - Enklaawa agreguje response'y
   - Securely (all inside enclave)

2. **End-to-End Encryption**
   - ECDH in enclave
   - AES-GCM encryption
   - Receiver nie widzi surowych danych

3. **Attestation**
   - Remote attestation
   - Receiver weryfikuje enklavę
   - Pewność że kod jest trusted

4. **Hardware Mode**
   - Rzeczywisty SGX sprzęt
   - Real isolation
   - Production ready

5. **Multi-Relay Federation**
   - Współpraca między relay'ami
   - Distributed aggregation
   - Load balancing

## Dependencje

```
wolfssl (WolfTLS)
├─ SSL/TLS communication
└─ Certificates, crypto

SGX SDK
├─ Compiler (sgx_sign, sgx_edger8r)
├─ Runtime libraries (sgx_urts)
└─ Enclave libraries

Standard C++11
└─ pthread, socket, sys libraries
```

## Build Order

1. Enclave (trusted code)
   - Compile Enclave.cpp
   - Link with SGX libs
   - Sign enclave

2. Untrusted Code
   - Generate proxies (Enclave_u.c/h)
   - Compile Server.cpp
   - Link with SGX runtime

3. Standalone Clients
   - Compile Receiver.cpp
   - Compile Relay.cpp
   - No SGX dependency

## Performance Notes

- Thread per client (can use thread pool)
- No async I/O (blocking socket calls)
- TLS handshake overhead
- Enclave transition overhead (~100-1000 cycles)

Dla produkcji:
- Async I/O (epoll, select)
- Thread pool / worker threads
- Certificate caching
- Data compression
