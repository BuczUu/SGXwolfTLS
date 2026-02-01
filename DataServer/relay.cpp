#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

/* Data for each relay */
const char *RELAY_DATA_1 = "Data from Relay 1: sensor_value=42.5, timestamp=2026-02-01";
const char *RELAY_DATA_2 = "Data from Relay 2: sensor_value=37.2, timestamp=2026-02-01";

typedef struct
{
    WOLFSSL *ssl;
    int client_sock;
    int relay_id;
    const char *relay_data;
} client_context_t;

void *handle_client(void *arg)
{
    client_context_t *ctx = (client_context_t *)arg;
    WOLFSSL *ssl = ctx->ssl;
    int relay_id = ctx->relay_id;
    const char *relay_data = ctx->relay_data;
    int ret;
    unsigned char size_bytes[4];
    uint32_t request_size;
    unsigned char request[2048];
    uint32_t response_len;

    printf("[RELAY-%d] Client connected\n", relay_id);

    /* TLS handshake */
    while ((ret = wolfSSL_accept(ssl)) != WOLFSSL_SUCCESS)
    {
        int err = wolfSSL_get_error(ssl, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
        {
            printf("[RELAY-%d] TLS handshake failed: %d\n", relay_id, err);
            goto cleanup;
        }
    }

    printf("[RELAY-%d] TLS handshake OK\n", relay_id);

    /* Receive request: [size:4][data] */
    ret = wolfSSL_read(ssl, size_bytes, 4);
    if (ret != 4)
    {
        printf("[RELAY-%d] Failed to read request size\n", relay_id);
        goto cleanup;
    }

    request_size = *(uint32_t *)size_bytes;
    printf("[RELAY-%d] Received request header (size=%u)\n", relay_id, request_size);

    if (request_size > 0 && request_size < 2048)
    {
        ret = wolfSSL_read(ssl, request, request_size);
        if (ret > 0)
        {
            request[ret] = '\0';
            printf("[RELAY-%d] Request: %s\n", relay_id, (char *)request);
        }
    }

    /* Send response: [size:4][data] */
    response_len = strlen(relay_data);
    printf("[RELAY-%d] Sending response (%u bytes)\n", relay_id, response_len);

    ret = wolfSSL_write(ssl, (unsigned char *)&response_len, 4);
    if (ret != 4)
    {
        printf("[RELAY-%d] Failed to send response size\n", relay_id);
        goto cleanup;
    }

    ret = wolfSSL_write(ssl, (unsigned char *)relay_data, response_len);
    if (ret != (int)response_len)
    {
        printf("[RELAY-%d] Failed to send response data\n", relay_id);
        goto cleanup;
    }

    printf("[RELAY-%d] Response sent\n", relay_id);

cleanup:
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(ctx->client_sock);
    free(ctx);
    printf("[RELAY-%d] Client disconnected\n", relay_id);
    return NULL;
}

int start_relay_server(int relay_id, int port, const char *relay_data)
{
    printf("[RELAY-%d] Starting on port %d\n", relay_id, port);

    wolfSSL_library_init();

    /* Create WolfTLS context */
    WOLFSSL_CTX *ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!ssl_ctx)
    {
        printf("[RELAY-%d] Failed to create WolfSSL context\n", relay_id);
        return 1;
    }

    /* Load test certificates */
    int ret = wolfSSL_CTX_use_certificate_buffer(ssl_ctx, server_cert_der_1024, sizeof(server_cert_der_1024), SSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS)
    {
        printf("[RELAY-%d] Failed to load certificate\n", relay_id);
        return 1;
    }

    ret = wolfSSL_CTX_use_PrivateKey_buffer(ssl_ctx, server_key_der_1024, sizeof(server_key_der_1024), SSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS)
    {
        printf("[RELAY-%d] Failed to load private key\n", relay_id);
        return 1;
    }

    printf("[RELAY-%d] WolfSSL context initialized\n", relay_id);

    /* Create listening socket */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        printf("[RELAY-%d] Failed to create socket\n", relay_id);
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        printf("[RELAY-%d] Failed to bind to port %d\n", relay_id, port);
        return 1;
    }

    if (listen(listen_fd, 5) < 0)
    {
        printf("[RELAY-%d] Failed to listen\n", relay_id);
        return 1;
    }

    printf("[RELAY-%d] Listening on port %d\n", relay_id, port);

    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        int client_sock = accept(listen_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sock < 0)
        {
            printf("[RELAY-%d] Accept failed\n", relay_id);
            continue;
        }

        WOLFSSL *ssl = wolfSSL_new(ssl_ctx);
        if (!ssl)
        {
            printf("[RELAY-%d] Failed to create SSL object\n", relay_id);
            close(client_sock);
            continue;
        }

        wolfSSL_set_fd(ssl, client_sock);

        client_context_t *ctx = (client_context_t *)malloc(sizeof(client_context_t));
        if (!ctx)
        {
            wolfSSL_free(ssl);
            close(client_sock);
            continue;
        }

        ctx->ssl = ssl;
        ctx->client_sock = client_sock;
        ctx->relay_id = relay_id;
        ctx->relay_data = relay_data;

        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, ctx);
        pthread_detach(thread);
    }

    wolfSSL_CTX_free(ssl_ctx);
    close(listen_fd);
    return 0;
}

int main(int argc, char *argv[])
{
    int relay_id = 1;
    int port = 13001;
    const char *relay_data = RELAY_DATA_1;

    if (argc > 1)
    {
        relay_id = atoi(argv[1]);
        port = 13000 + relay_id;
        relay_data = (relay_id == 1) ? RELAY_DATA_1 : RELAY_DATA_2;
    }

    printf("=== DistributionVC Data Relay Server (WolfTLS) ===\n");
    return start_relay_server(relay_id, port, relay_data);
}
