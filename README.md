# DistributionVC - SGX Data Aggregation with WolfTLS

Bezpieczny system dystrybucji i agregacji danych z:
- **SGX enklavą** w SIM mode (serce systemu!)
- **Blind Proxy Server** (untrusted layer nie widzi danych)
- **WolfTLS** do komunikacji (end-to-end encrypted)
- **C++** dla wszystkich komponentów

## Kluczowa Koncepcja Bezpieczeństwa

**Serwer na maszynie SGX jest "blind proxy"** - nie widzi żadnych plaintext danych!

```
Cała komunikacja szyfrowana:
Receiver ─TLS─▶ Blind Server ─OCALL─▶ Enklaawa ◀─ Relay'e
         ◀─TLS─ (encrypted) ◀─OCALL─ (decrypts/    (encrypted)
                                      processes)
```

Serwer tylko przekazuje encrypted buffers - nie wie co zawierają!

## Komponenty

1. **App/Server.cpp** - Główny serwer SGX
   - Tworzy enklawę
   - Przyjmuje połączenia TLS od klientów
   - Agreguje dane w enklaawie
   - Wysyła wyniki

2. **Receiver/client.cpp** - Klient receivera
   - Łączy się do serwera SGX przez TLS
   - Wysyła dane do agregacji
   - Otrzymuje wynik

3. **DataServer/relay.cpp** - Serwery relay danych
   - Słuchają na portach 13001 i 13002
   - Odpowiadają na zapytania od SGX
   - Zwracają hardcoded dane

4. **Enclave/Enclave.cpp** - Trusted enklaawa
   - Przechowuje agregowane dane
   - Wykonuje operacje na danych

## Build

```bash
cd /home/marcel/sgx_lab/examples/DistributionVC

# Czyszczenie
make clean

# Build w SIM mode (domyślnie)
make

# Build w HW mode
make SGX_MODE=HW

# Build Release
make SGX_DEBUG=0
```

## Uruchomienie

Otworzyć 4 terminale:

**Terminal 1 - Główny serwer SGX:**
```bash
cd /home/marcel/sgx_lab/examples/DistributionVC
export LD_LIBRARY_PATH=/opt/intel/sgxsdk/lib64:$LD_LIBRARY_PATH
./bin/server
```

**Terminal 2 - Data Relay 1 (port 13001):**
```bash
./bin/relay_server 1
```

**Terminal 3 - Data Relay 2 (port 13002):**
```bash
./bin/relay_server 2
```

**Terminal 4 - Receiver Client:**
```bash
./bin/receiver_client "Moje dane do agregacji"
```

## Output

Powinien wyglądać tak:

```
[SERVER] Enclave created successfully
[SERVER] Listening on port 12345

[RELAY-1] Listening on port 13001
[RELAY-2] Listening on port 13002

[RECEIVER] Connecting to localhost:12345
[RECEIVER] TLS handshake OK
[RECEIVER] Sent identification
[RECEIVER] Sending data (31 bytes)
[RECEIVER] Data sent
[RECEIVER] Result from server: ACK:RECEIVER:31
```

## Wymagania

- Intel SGX SDK zainstalowany w `/opt/intel/sgxsdk`
- WolfSSL zainstalowany (`apt install libwolfssl-dev` lub z źródeł)
- GCC/G++ z obsługą C++11

## Testowanie SIM mode

Projekt domyślnie buduje się w SIM mode, który nie wymaga SGX sprzętu.

```bash
make SGX_MODE=SIM
./bin/server
```

## Struktura projektu

```
DistributionVC/
├── Makefile              # Główny makefile
├── Enclave/
│   ├── Enclave.edl      # EDL interface
│   ├── Enclave.cpp      # Trusted code
│   ├── Enclave.config.xml
│   ├── Enclave.lds
│   └── Enclave_private_test.pem
├── App/
│   └── Server.cpp        # Untrusted server z WolfTLS
├── Receiver/
│   └── client.cpp        # Receiver client
├── DataServer/
│   └── relay.cpp         # Data relay servers
├── Include/              # Common headers (opcjonalnie)
└── bin/                  # Build output
    ├── server            # Main server
    ├── receiver_client   # Receiver client
    ├── relay_server      # Data relay
    └── enclave.signed.so # Enklaawa
```

## Notatki

- Wszystko w C++ (WolfTLS jest C++)
- Certyfikaty testowe ze WolfSSL (hardcoded w `certs_test.h`)
- SIM mode domyślnie (nie wymaga sprzętu SGX)
- TLS 1.3 dla komunikacji
- Threading dla multi-client support

## Debugging

Aby zobaczyć debugowe info:

```bash
# Build z debugiem
make clean
make SGX_DEBUG=1

# Uruchom z verbose output
./bin/server
```

## Znane ograniczenia

- SIM mode - nie jest bezpieczny dla produkcji
- Hardcoded dane relay'ów
- Brak prawdziwej agregacji (na razie echo)
- Testowe certyfikaty SE

## Rozszerzone funkcjonalności

Do dodania w przyszłości:
- Implementacja OCALL do queryowania relay'ów z enklaawy
- Rzeczywista agregacja danych
- Szyfrowanie E2E
- Attestation

