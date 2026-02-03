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

extern "C" int ocall_connect_relay(int relay_id, int *sockfd)
{
    if (!sockfd)
    {
        return -1;
    }

    int relay_port = 13000 + relay_id;
    LOG_PRINTF("[SERVER] Connecting to relay %d on port %d...\n", relay_id, relay_port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        LOG_PRINTF("[SERVER] Failed to create socket for relay %d\n", relay_id);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(relay_port);

    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) <= 0)
    {
        LOG_PRINTF("[SERVER] Invalid address for relay %d\n", relay_id);
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        LOG_PRINTF("[SERVER] Failed to connect to relay %d\n", relay_id);
        close(sock);
        return -1;
    }

    *sockfd = sock;
    return 0;
}

extern "C" void ocall_close_socket(int sockfd)
{
    if (sockfd >= 0)
    {
        close(sockfd);
    }
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

    /* Initialize relay structures */
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
