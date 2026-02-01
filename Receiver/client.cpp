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

void *wolfSSL_Malloc_override(size_t size)
{
    return malloc(size);
}

void wolfSSL_Free_override(void *ptr)
{
    free(ptr);
}

void print_help()
{
    printf("\n=== Commands ===\n");
    printf("  send <data>    - Send data to SGX enclave for aggregation\n");
    printf("  query          - Query aggregated results from enclave\n");
    printf("  status         - Get enclave status\n");
    printf("  help           - Show this help\n");
    printf("  exit           - Disconnect and exit\n");
    printf("================\n\n");
}

int send_command(WOLFSSL *ssl, const char *cmd, const char *data)
{
    char buffer[2048];
    int len;

    if (strcmp(cmd, "send") == 0)
    {
        if (!data || strlen(data) == 0)
        {
            printf("[ERROR] send requires data: send <your_data>\n");
            return -1;
        }
        len = snprintf(buffer, sizeof(buffer), "SEND:%s", data);
    }
    else if (strcmp(cmd, "query") == 0)
    {
        len = snprintf(buffer, sizeof(buffer), "QUERY");
    }
    else if (strcmp(cmd, "status") == 0)
    {
        len = snprintf(buffer, sizeof(buffer), "STATUS");
    }
    else
    {
        printf("[ERROR] Unknown command: %s\n", cmd);
        return -1;
    }

    // Send size + data
    uint32_t data_len = len;
    int ret = wolfSSL_write(ssl, (unsigned char *)&data_len, 4);
    if (ret != 4)
    {
        printf("[ERROR] Failed to send command size\n");
        return -1;
    }

    ret = wolfSSL_write(ssl, (unsigned char *)buffer, data_len);
    if (ret != (int)data_len)
    {
        printf("[ERROR] Failed to send command data\n");
        return -1;
    }

    printf("[SENT] %s\n", buffer);

    // Receive response
    unsigned char result[2048];
    ret = wolfSSL_read(ssl, result, sizeof(result) - 1);
    if (ret > 0)
    {
        result[ret] = '\0';
        printf("\n[RESPONSE]\n%s\n", (char *)result);
        return 0;
    }
    else
    {
        printf("[ERROR] Failed to receive response (ret=%d)\n", ret);
        return -1;
    }
}

int main(int argc, char *argv[])
{
    printf("=== DistributionVC Interactive Receiver Client ===\n");

    const char *host = (argc > 1) ? argv[1] : SERVER_HOST;
    int port = (argc > 2) ? atoi(argv[2]) : SERVER_PORT;

    printf("[RECEIVER] Connecting to %s:%d\n", host, port);

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
        perror("connect");
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
    print_help();

    /* Interactive command loop */
    char input[1024];
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

        // Parse command
        char *cmd = strtok(input, " ");
        if (!cmd)
            continue;

        if (strcmp(cmd, "exit") == 0)
        {
            printf("[RECEIVER] Exiting...\n");
            break;
        }
        else if (strcmp(cmd, "help") == 0)
        {
            print_help();
        }
        else if (strcmp(cmd, "send") == 0)
        {
            char *data = strtok(NULL, "");
            send_command(ssl, "send", data);
        }
        else if (strcmp(cmd, "query") == 0)
        {
            send_command(ssl, "query", NULL);
        }
        else if (strcmp(cmd, "status") == 0)
        {
            send_command(ssl, "status", NULL);
        }
        else
        {
            printf("[ERROR] Unknown command: %s (type 'help' for commands)\n", cmd);
        }
    }

    /* Send exit signal: 0xFFFFFFFF */
    uint32_t exit_signal = 0xFFFFFFFF;
    wolfSSL_write(ssl, (unsigned char *)&exit_signal, 4);

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(sock);

    printf("[RECEIVER] Disconnected\n");
    return 0;
}
