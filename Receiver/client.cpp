#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Enable 1024-bit certificate buffers before including certs_test.h */
#define USE_CERT_BUFFERS_1024

/* WolfSSL must be included after standard headers */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 12345

int main(int argc, char *argv[])
{
    printf("=== DistributionVC Receiver Client (Simple) ===\n");

    const char *host = (argc > 1) ? argv[1] : SERVER_HOST;
    int port = (argc > 2) ? atoi(argv[2]) : SERVER_PORT;

    printf("[RECEIVER] Connecting to %s:%d via TLS...\n", host, port);

    wolfSSL_library_init();

    /* Create WolfTLS context for client */
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx)
    {
        printf("[RECEIVER] Failed to create WolfSSL context\n");
        return 1;
    }

    /* Disable certificate verification for testing */
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /* Create socket and connect to server */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        printf("[RECEIVER] Failed to create socket\n");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0)
    {
        printf("[RECEIVER] Invalid address: %s\n", host);
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        printf("[RECEIVER] Failed to connect to server\n");
        close(sock);
        return 1;
    }

    printf("[RECEIVER] Connected, performing TLS handshake...\n");

    /* Create SSL object and connect */
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl)
    {
        printf("[RECEIVER] Failed to create SSL object\n");
        close(sock);
        return 1;
    }

    wolfSSL_set_fd(ssl, sock);

    /* TLS handshake */
    int ret = wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS)
    {
        int err = wolfSSL_get_error(ssl, ret);
        printf("[RECEIVER] TLS handshake failed: %d\n", err);
        wolfSSL_free(ssl);
        close(sock);
        return 1;
    }

    printf("[RECEIVER] TLS handshake OK\n");

    /* Send client identification */
    const char *client_id = "RECEIVER";
    ret = wolfSSL_write(ssl, (unsigned char *)client_id, strlen(client_id));
    if (ret <= 0)
    {
        printf("[RECEIVER] Failed to send identification\n");
        wolfSSL_free(ssl);
        close(sock);
        return 1;
    }

    printf("[RECEIVER] Connected to SGX enclave via TLS\n");
    printf("\n=== Commands ===\n");
    printf("  fetch      - Fetch aggregated data from relay servers\n");
    printf("  help       - Show this help\n");
    printf("  exit       - Disconnect and exit\n");
    printf("================\n\n");

    /* Interactive command loop */
    char input[1024];
    unsigned char response[4096];

    while (1)
    {
        printf("receiver> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL)
            break;

        // Remove newline
        input[strcspn(input, "\n")] = 0;

        if (strlen(input) == 0)
            continue;

        if (strcmp(input, "exit") == 0)
        {
            printf("[RECEIVER] Exiting...\n");
            break;
        }
        else if (strcmp(input, "help") == 0)
        {
            printf("\n=== Commands ===\n");
            printf("  fetch      - Fetch aggregated data from relay servers\n");
            printf("  help       - Show this help\n");
            printf("  exit       - Disconnect and exit\n");
            printf("================\n\n");
        }
        else if (strcmp(input, "fetch") == 0)
        {
            /* Send GET_DATA command to SGX */
            printf("[RECEIVER] Fetching data from SGX enclave...\n");
            const char *cmd = "GET_DATA";
            uint32_t cmd_len = strlen(cmd);

            ret = wolfSSL_write(ssl, (unsigned char *)&cmd_len, 4);
            if (ret != 4)
            {
                printf("[RECEIVER] Failed to send command size\n");
                break;
            }

            ret = wolfSSL_write(ssl, (unsigned char *)cmd, cmd_len);
            if (ret != (int)cmd_len)
            {
                printf("[RECEIVER] Failed to send command\n");
                break;
            }

            /* Receive response with data from relay servers */
            ret = wolfSSL_read(ssl, response, sizeof(response) - 1);
            if (ret > 0)
            {
                response[ret] = '\0';
                printf("\n[RECEIVED FROM SGX]:\n");
                printf("%s\n\n", (char *)response);
            }
            else
            {
                printf("[RECEIVER] Failed to receive response (ret=%d)\n", ret);
            }
        }
        else
        {
            printf("[RECEIVER] Unknown command: '%s' (type 'help' for commands)\n", input);
        }
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(sock);

    printf("[RECEIVER] Disconnected\n");
    return 0;
}
