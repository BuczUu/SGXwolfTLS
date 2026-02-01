#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Enable 1024-bit certificate buffers before including certs_test.h */
#define USE_CERT_BUFFERS_1024

/* WolfSSL must be included after standard headers */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

#include "Enclave_u.h"
#include "sgx_urts.h"

#define PORT 12345
#define LOG_PRINTF(fmt, ...)        \
    do                              \
    {                               \
        printf(fmt, ##__VA_ARGS__); \
        fflush(stdout);             \
    } while (0)

sgx_enclave_id_t global_eid = 0;

// Persistent TLS connections to relay servers
typedef struct
{
    WOLFSSL *ssl;
    WOLFSSL_CTX *ctx;
    int sock;
    int relay_id;
    bool connected;
} relay_connection_t;

relay_connection_t g_relay1 = {NULL, NULL, -1, 1, false};
relay_connection_t g_relay2 = {NULL, NULL, -1, 2, false};

extern "C" void ocall_print_string(const char *str)
{
    printf("%s", str);
}

// Socket I/O OCALLs for TLS in enclave
extern "C" int ocall_read_socket(int sockfd, uint8_t *buf, size_t len)
{
    return (int)read(sockfd, buf, len);
}

extern "C" int ocall_write_socket(int sockfd, const uint8_t *buf, size_t len)
{
    return (int)write(sockfd, buf, len);
}

extern "C" int ocall_fetch_relay_data(int relay_id, uint8_t *buffer, uint32_t buffer_size)
{
    LOG_PRINTF("[SERVER] ocall_fetch_relay_data: relay_id=%d\n", relay_id);

    // Select relay connection
    relay_connection_t *relay = (relay_id == 1) ? &g_relay1 : &g_relay2;

    if (!relay->connected)
    {
        LOG_PRINTF("[SERVER] Relay %d not connected\n", relay_id);
        return -1;
    }

    WOLFSSL *ssl = relay->ssl;

    // Send request marker (empty request)
    uint32_t request_size = 0;
    int ret = wolfSSL_write(ssl, (unsigned char *)&request_size, 4);
    if (ret < 0)
    {
        LOG_PRINTF("[SERVER] Failed to send request to relay %d\n", relay_id);
        return -1;
    }

    // Read response size (4 bytes)
    unsigned char size_bytes[4];
    ret = wolfSSL_read(ssl, size_bytes, 4);
    if (ret != 4)
    {
        LOG_PRINTF("[SERVER] Failed to read response size from relay %d\n", relay_id);
        return -1;
    }

    uint32_t response_size = *(uint32_t *)size_bytes;
    if (response_size > buffer_size)
        response_size = buffer_size;

    LOG_PRINTF("[SERVER] Receiving %u bytes from relay %d\n", response_size, relay_id);

    // Read response data
    if (response_size > 0)
    {
        ret = wolfSSL_read(ssl, buffer, response_size);
        if (ret != (int)response_size)
        {
            LOG_PRINTF("[SERVER] Read error from relay %d\n", relay_id);
            return -1;
        }
    }

    LOG_PRINTF("[SERVER] Successfully fetched %u bytes from relay %d\n", response_size, relay_id);
    return response_size;
}

int connect_to_relay(relay_connection_t *relay)
{
    int relay_port = 13000 + relay->relay_id;

    LOG_PRINTF("[SERVER] Connecting to relay %d on port %d...\n", relay->relay_id, relay_port);

    // Create socket
    relay->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (relay->sock < 0)
    {
        LOG_PRINTF("[SERVER] Failed to create socket for relay %d\n", relay->relay_id);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(relay_port);

    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) <= 0)
    {
        LOG_PRINTF("[SERVER] Invalid address for relay %d\n", relay->relay_id);
        close(relay->sock);
        return -1;
    }

    if (connect(relay->sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        LOG_PRINTF("[SERVER] Failed to connect to relay %d\n", relay->relay_id);
        close(relay->sock);
        return -1;
    }

    // Setup TLS
    relay->ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!relay->ctx)
    {
        LOG_PRINTF("[SERVER] Failed to create SSL context for relay %d\n", relay->relay_id);
        close(relay->sock);
        return -1;
    }
    wolfSSL_CTX_set_verify(relay->ctx, SSL_VERIFY_NONE, NULL);

    relay->ssl = wolfSSL_new(relay->ctx);
    if (!relay->ssl)
    {
        LOG_PRINTF("[SERVER] Failed to create SSL for relay %d\n", relay->relay_id);
        wolfSSL_CTX_free(relay->ctx);
        close(relay->sock);
        return -1;
    }

    wolfSSL_set_fd(relay->ssl, relay->sock);

    // TLS handshake
    int ret = wolfSSL_connect(relay->ssl);
    if (ret != WOLFSSL_SUCCESS)
    {
        int err = wolfSSL_get_error(relay->ssl, ret);
        LOG_PRINTF("[SERVER] TLS handshake failed for relay %d: %d\n", relay->relay_id, err);
        wolfSSL_free(relay->ssl);
        wolfSSL_CTX_free(relay->ctx);
        close(relay->sock);
        return -1;
    }

    relay->connected = true;
    LOG_PRINTF("[SERVER] Connected to relay %d with TLS\n", relay->relay_id);
    return 0;
}

typedef struct
{
    int client_sock;
    int client_id;
    pthread_t thread;
} client_info_t;

int initialize_enclave(void)
{
    sgx_status_t ret = sgx_create_enclave("bin/enclave.signed.so", SGX_DEBUG_FLAG,
                                          NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        printf("[SERVER] Failed to create enclave: 0x%x\n", ret);
        return -1;
    }
    printf("[SERVER] Enclave created successfully (eid=0x%llx)\n", global_eid);
    return 0;
}

void *client_handler(void *arg)
{
    client_info_t *client = (client_info_t *)arg;
    int client_sock = client->client_sock;
    int client_id = client->client_id;
    sgx_status_t status, retval;

    LOG_PRINTF("[SERVER] Client %d: Connected, passing to enclave for TLS...\n", client_id);

    // All TLS handling is now done inside the enclave
    status = ecall_handle_tls_session(global_eid, &retval, client_sock);
    if (status != SGX_SUCCESS || retval != SGX_SUCCESS)
    {
        LOG_PRINTF("[SERVER] Client %d: ecall_handle_tls_session failed: 0x%x / 0x%x\n",
                   client_id, status, retval);
    }

    close(client_sock);
    free(client);
    LOG_PRINTF("[SERVER] Client %d: Closed\n", client_id);
    return NULL;
}

int main(void)
{
    printf("=== DistributionVC Server with TLS in Enclave ===\n");
    printf("Initializing SGX enclave in SIM mode...\n");

    if (initialize_enclave() < 0)
        return 1;

    // Initialize enclave TLS context
    sgx_status_t status, retval;
    status = enclave_init(global_eid, &retval);
    if (status != SGX_SUCCESS || retval != SGX_SUCCESS)
    {
        printf("[SERVER] Failed to initialize enclave TLS: 0x%x / 0x%x\n", status, retval);
        return 1;
    }

    printf("[SERVER] Enclave TLS initialized\n");

    /* Connect to relay servers */
    printf("[SERVER] Establishing TLS connections to relay servers...\n");
    if (connect_to_relay(&g_relay1) < 0)
    {
        printf("[SERVER] Failed to connect to relay 1 - continuing anyway\n");
    }
    if (connect_to_relay(&g_relay2) < 0)
    {
        printf("[SERVER] Failed to connect to relay 2 - continuing anyway\n");
    }

    /* Create listening socket */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        printf("[SERVER] Failed to create socket\n");
        return 1;
    }

    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        printf("[SERVER] Failed to set socket options\n");
        close(listen_fd);
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        printf("[SERVER] Failed to bind to port %d (errno: %d)\n", PORT, errno);
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 5) < 0)
    {
        printf("[SERVER] Failed to listen\n");
        return 1;
    }

    printf("[SERVER] Listening on port %d (TLS handled in enclave)\n", PORT);

    int client_count = 0;
    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        int client_sock = accept(listen_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sock < 0)
        {
            printf("[SERVER] Accept failed\n");
            continue;
        }

        client_count++;

        client_info_t *info = (client_info_t *)malloc(sizeof(client_info_t));
        if (!info)
        {
            close(client_sock);
            continue;
        }

        info->client_sock = client_sock;
        info->client_id = client_count;

        pthread_create(&info->thread, NULL, client_handler, (void *)info);
    }

    close(listen_fd);
    return 0;
}
