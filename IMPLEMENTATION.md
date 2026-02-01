# DistributionVC - System Komunikacji SGX z Agregacją Danych

## Architektura

Pełna komunikacja TLS między komponentami:

```
RECEIVER --TLS--> SERVER(SGX Enclave)
                      |
                      +--> RELAY 1 (TLS) --> dane czujnika 1
                      |
                      +--> RELAY 2 (TLS) --> dane czujnika 2
                      
SERVER (Enclave) agreguje wszystkie dane i zwraca do RECEIVER
```

## Komponenty

### 1. **Server (App/Server.cpp)** - Port 12345
   - Ładuje SGX Enclave (bin/enclave.signed.so)
   - Nasłuchuje na TLS dla Receiver
   - Implementuje OCALL `ocall_fetch_relay_data()` - pobiera dane z relay serwerów
   - Wywołuje Enclave ECALL `ecall_process_and_return()` do agregacji

### 2. **Receiver (Receiver/client.cpp)** - Client
   - Łączy się z Server na porcie 12345 (TLS)
   - Wysyła identyfikator i dane do agregacji
   - Odbiera wynik agregacji

### 3. **Relay Servers (DataServer/relay.cpp)** - Porty 13001, 13002
   - Relay 1: port 13001
   - Relay 2: port 13002
   - Nasłuchują na TLS, czekają na requestu od Server
   - Zwracają swoje dane (czujnik)

### 4. **SGX Enclave (Enclave/Enclave.cpp)**
   - Funkcja `ecall_aggregate_data()` - otrzymuje dane z Receiver
   - Funkcja `ecall_process_and_return()`:
     * Łączy dane z Receiver
     * Pobiera dane z Relay 1 (OCALL)
     * Pobiera dane z Relay 2 (OCALL)
     * Agreguje wszystkie dane
     * Zwraca wynik

## Przepływ Danych

1. **Receiver wysyła request:**
   ```
   [RECEIVER] Connecting to localhost:12345
   [RECEIVER] Sent identification: "RECEIVER"
   [RECEIVER] Data to send: "Hello from receiver"
   ```

2. **Server odbiera i przetwarza:**
   ```
   [SERVER] Client 1: Connected
   [SERVER] Client 1: TLS handshake OK
   [SERVER] Client 1: Identified as 'RECEIVER'
   [SERVER] Client 1: Received X bytes
   [SERVER] Client 1: Aggregated
   [SERVER] Client 1: Now processing with relay data...
   ```

3. **Enclave pobiera dane z relay (OCALL -> OCALL_FETCH):**
   ```
   [SERVER] ocall_fetch_relay_data: relay_id=1
   [SERVER] Connected to relay 1, performing TLS handshake...
   [SERVER] TLS handshake OK with relay 1
   [SERVER] Successfully fetched N bytes from relay 1
   ```

4. **Server zwraca wynik agregacji:**
   ```
   [SERVER] Client 1: Final result: [RESULT] Aggregated data from 3 sources:
                                        CLIENT_1: X bytes
                                        RELAY_1: Y bytes
                                        RELAY_2: Z bytes
   [SERVER] Client 1: Sent result (N bytes)
   ```

## Uruchamianie

```bash
cd /home/marcel/sgx_lab/examples/DistributionVC

# Terminal 1: Server
./bin/server

# Terminal 2: Relay 1
./bin/relay_server 1

# Terminal 3: Relay 2  
./bin/relay_server 2

# Terminal 4: Receiver (wysyła dane)
./bin/receiver_client "Hello from receiver"
```

## Ostatnie Zmiany

- **Enclave.edl**: Dodano OCALL `ocall_fetch_relay_data()` do pobierania danych z relay
- **Enclave.cpp**: 
  - `ecall_process_and_return()` teraz pobiera dane z relay i agreguje
  - Dodano MAX_AGG_DATA constant
- **Server.cpp**:
  - Implementacja `ocall_fetch_relay_data()` - łączy się z relay serverem na porcie 13000+relay_id
  - Wykonuje TLS handshake z relay i pobiera dane
  - Poprawiona logika `inet_pton()` do parsowania "127.0.0.1"
  - `client_handler()` teraz wywołuje `ecall_process_and_return()` dla pełnej agregacji

## Build

```bash
cd /home/marcel/sgx_lab/examples/DistributionVC
make clean
make
```

Wszystkie binaria tworzone w `bin/` :
- `bin/server` - Server z Enclave
- `bin/receiver_client` - Receiver
- `bin/relay_server` - Relay (uniwersalny dla relay 1 i 2)
- `bin/enclave.signed.so` - Podpisany SGX Enclave

## Status

✅ Build - SUKCES  
✅ Enclave signing - SUKCES  
✅ Architecture - KOMPLETNA  
⏳ Testing - GOTOWY DO TESTU
