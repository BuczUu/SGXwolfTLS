#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Enclave_t.h"
#include "sgx_trts.h"

#define USE_CERT_BUFFERS_1024
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

// Provide recv/send stubs for WolfSSL (it expects these but we use custom I/O)
extern "C" int recv(int sockfd, void *buf, size_t len, int flags)
{
    (void)flags; // Ignore flags in SGX
    int ret;
    ocall_read_socket(&ret, sockfd, (uint8_t *)buf, len);
    return ret;
}

extern "C" int send(int sockfd, const void *buf, size_t len, int flags)
{
    (void)flags; // Ignore flags in SGX
    int ret;
    ocall_write_socket(&ret, sockfd, (const uint8_t *)buf, len);
    return ret;
}

#define MAX_DATA_SIZE 2048
#define MAX_SERVERS 10
#define MAX_AGG_DATA MAX_SERVERS

typedef struct
{
    char server_id[64];
    uint8_t data[512];
    uint32_t data_len;
} AggregatedData;

static AggregatedData g_aggregated[MAX_SERVERS];
static int g_agg_count = 0;

// WolfSSL context
static WOLFSSL_CTX *g_wolfssl_ctx = NULL;

// Custom I/O callbacks for WolfSSL to use OCALLs
static int wolfssl_recv_callback(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int sockfd = *(int *)ctx;
    int ret = 0;
    ocall_read_socket(&ret, sockfd, (uint8_t *)buf, sz);
    return ret;
}

static int wolfssl_send_callback(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int sockfd = *(int *)ctx;
    int ret = 0;
    ocall_write_socket(&ret, sockfd, (uint8_t *)buf, sz);
    return ret;
}

sgx_status_t enclave_init()
{
    ocall_print_string("[ENCLAVE] Initializing WolfSSL...\n");

    wolfSSL_Init();

    // Create server context
    g_wolfssl_ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    if (!g_wolfssl_ctx)
    {
        ocall_print_string("[ENCLAVE] Failed to create WolfSSL context\n");
        return SGX_ERROR_UNEXPECTED;
    }

    // Load server certificate and key from test buffers
    int ret = wolfSSL_CTX_use_certificate_buffer(g_wolfssl_ctx,
                                                 server_cert_der_1024,
                                                 sizeof(server_cert_der_1024),
                                                 SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS)
    {
        ocall_print_string("[ENCLAVE] Failed to load certificate\n");
        return SGX_ERROR_UNEXPECTED;
    }

    ret = wolfSSL_CTX_use_PrivateKey_buffer(g_wolfssl_ctx,
                                            server_key_der_1024,
                                            sizeof(server_key_der_1024),
                                            SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS)
    {
        ocall_print_string("[ENCLAVE] Failed to load private key\n");
        return SGX_ERROR_UNEXPECTED;
    }

    ocall_print_string("[ENCLAVE] WolfSSL initialized successfully with certificates\n");
    return SGX_SUCCESS;
}

sgx_status_t ecall_handle_tls_session(int client_sockfd)
{
    ocall_print_string("[ENCLAVE] Starting TLS session...\n");

    if (!g_wolfssl_ctx)
    {
        ocall_print_string("[ENCLAVE] WolfSSL not initialized!\n");
        return SGX_ERROR_INVALID_STATE;
    }

    // Create SSL object
    WOLFSSL *ssl = wolfSSL_new(g_wolfssl_ctx);
    if (!ssl)
    {
        ocall_print_string("[ENCLAVE] Failed to create SSL object\n");
        return SGX_ERROR_UNEXPECTED;
    }

    // Set custom I/O callbacks
    wolfSSL_SetIORecv(g_wolfssl_ctx, wolfssl_recv_callback);
    wolfSSL_SetIOSend(g_wolfssl_ctx, wolfssl_send_callback);
    wolfSSL_SetIOReadCtx(ssl, &client_sockfd);
    wolfSSL_SetIOWriteCtx(ssl, &client_sockfd);

    // TLS handshake
    int ret = wolfSSL_accept(ssl);
    if (ret != WOLFSSL_SUCCESS)
    {
        int err = wolfSSL_get_error(ssl, ret);
        char msg[128];
        snprintf(msg, sizeof(msg), "[ENCLAVE] TLS handshake failed: %d\n", err);
        ocall_print_string(msg);
        wolfSSL_free(ssl);
        return SGX_ERROR_UNEXPECTED;
    }

    ocall_print_string("[ENCLAVE] TLS handshake successful!\n");

    // Read client ID
    uint8_t buf[2048];
    ret = wolfSSL_read(ssl, buf, sizeof(buf) - 1);
    if (ret > 0)
    {
        buf[ret] = '\0';
        char msg[300];
        snprintf(msg, sizeof(msg), "[ENCLAVE] Client identified as: %s\n", (char *)buf);
        ocall_print_string(msg);
    }

    // Main command loop
    while (1)
    {
        // Read command size (4 bytes)
        uint32_t cmd_size = 0;
        ret = wolfSSL_read(ssl, (unsigned char *)&cmd_size, 4);
        if (ret <= 0)
        {
            ocall_print_string("[ENCLAVE] Client disconnected\n");
            break;
        }

        // Check for exit signal
        if (cmd_size == 0xFFFFFFFF)
        {
            ocall_print_string("[ENCLAVE] EXIT signal received\n");
            break;
        }

        if (cmd_size > 2048)
        {
            ocall_print_string("[ENCLAVE] Invalid command size\n");
            break;
        }

        // Read command data
        ret = wolfSSL_read(ssl, buf, cmd_size);
        if (ret != (int)cmd_size)
        {
            ocall_print_string("[ENCLAVE] Failed to read command\n");
            break;
        }
        buf[cmd_size] = '\0';

        char msg[512];
        snprintf(msg, sizeof(msg), "[ENCLAVE] Received command: %s\n", (char *)buf);
        ocall_print_string(msg);

        // Parse and process command
        char response[2048];
        int resp_len = 0;

        if (strncmp((char *)buf, "SEND:", 5) == 0)
        {
            // SEND command: store data
            const char *data = (char *)buf + 5;
            if (g_agg_count < MAX_SERVERS)
            {
                snprintf(g_aggregated[g_agg_count].server_id, 64, "CLIENT_%d", g_agg_count);
                size_t data_len = strlen(data);
                if (data_len > 512)
                    data_len = 512;
                memcpy(g_aggregated[g_agg_count].data, data, data_len);
                g_aggregated[g_agg_count].data_len = data_len;
                g_agg_count++;

                resp_len = snprintf(response, sizeof(response),
                                    "[ENCLAVE] Data stored (%zu bytes). Total: %d entries",
                                    data_len, g_agg_count);
            }
            else
            {
                resp_len = snprintf(response, sizeof(response),
                                    "[ENCLAVE] Storage full! Cannot store more data.");
            }
        }
        else if (strcmp((char *)buf, "QUERY") == 0)
        {
            // QUERY command: return aggregated data
            resp_len = snprintf(response, sizeof(response),
                                "[ENCLAVE] Aggregated Data (%d entries):\n", g_agg_count);
            for (int i = 0; i < g_agg_count && resp_len < 1900; i++)
            {
                resp_len += snprintf(response + resp_len, sizeof(response) - resp_len,
                                     "  [%d] %s: %.*s (%u bytes)\n",
                                     i + 1, g_aggregated[i].server_id,
                                     (int)g_aggregated[i].data_len,
                                     (char *)g_aggregated[i].data,
                                     g_aggregated[i].data_len);
            }
        }
        else if (strcmp((char *)buf, "STATUS") == 0)
        {
            // STATUS command
            resp_len = snprintf(response, sizeof(response),
                                "[ENCLAVE] Status:\n"
                                "  Entries stored: %d/%d\n"
                                "  TLS version: TLSv1.2\n"
                                "  Mode: SGX Simulation\n",
                                g_agg_count, MAX_SERVERS);
        }
        else
        {
            resp_len = snprintf(response, sizeof(response),
                                "[ENCLAVE] Unknown command: %s", (char *)buf);
        }

        // Send response
        ret = wolfSSL_write(ssl, response, resp_len);
        if (ret != resp_len)
        {
            ocall_print_string("[ENCLAVE] Failed to send response\n");
            break;
        }
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);

    ocall_print_string("[ENCLAVE] TLS session completed\n");
    return SGX_SUCCESS;
}

sgx_status_t ecall_aggregate_data(
    const char *client_id,
    const uint8_t *data,
    size_t data_len,
    uint8_t *result,
    uint32_t *result_len)
{

    char msg[256];
    snprintf(msg, sizeof(msg), "[ENCLAVE] Aggregating data from %s (%zu bytes)\n",
             client_id, data_len);
    ocall_print_string(msg);

    if (g_agg_count < MAX_SERVERS)
    {
        strncpy(g_aggregated[g_agg_count].server_id, client_id, 63);
        g_aggregated[g_agg_count].server_id[63] = '\0';

        if (data_len > 512)
            data_len = 512;
        memcpy(g_aggregated[g_agg_count].data, data, data_len);
        g_aggregated[g_agg_count].data_len = data_len;
        g_agg_count++;
    }

    // Return confirmation
    snprintf((char *)result, 1024, "ACK:%s:%zu", client_id, data_len);
    *result_len = strlen((char *)result);

    return SGX_SUCCESS;
}

sgx_status_t ecall_process_and_return(
    uint8_t *response,
    uint32_t *response_len)
{

    ocall_print_string("[ENCLAVE] Processing aggregated data...\n");
    ocall_print_string("[ENCLAVE] Fetching data from relay servers...\n");

    // Fetch data from relay servers
    uint8_t relay_buffer[2048];
    int relay1_len = 0;
    sgx_status_t ret = ocall_fetch_relay_data(&relay1_len, 1, relay_buffer, sizeof(relay_buffer));
    if (ret == SGX_SUCCESS && relay1_len > 0 && g_agg_count < MAX_AGG_DATA)
    {
        char relay1_id[64];
        snprintf(relay1_id, sizeof(relay1_id), "RELAY_1");
        strncpy(g_aggregated[g_agg_count].server_id, relay1_id, 63);
        g_aggregated[g_agg_count].server_id[63] = '\0';
        memcpy(g_aggregated[g_agg_count].data, relay_buffer, relay1_len);
        g_aggregated[g_agg_count].data_len = relay1_len;
        g_agg_count++;
    }

    int relay2_len = 0;
    ret = ocall_fetch_relay_data(&relay2_len, 2, relay_buffer, sizeof(relay_buffer));
    if (ret == SGX_SUCCESS && relay2_len > 0 && g_agg_count < MAX_AGG_DATA)
    {
        char relay2_id[64];
        snprintf(relay2_id, sizeof(relay2_id), "RELAY_2");
        strncpy(g_aggregated[g_agg_count].server_id, relay2_id, 63);
        g_aggregated[g_agg_count].server_id[63] = '\0';
        memcpy(g_aggregated[g_agg_count].data, relay_buffer, relay2_len);
        g_aggregated[g_agg_count].data_len = relay2_len;
        g_agg_count++;
    }

    // Build response from aggregated data
    char *resp = (char *)response;
    int offset = 0;

    offset += snprintf(resp + offset, 2048 - offset, "[RESULT] Aggregated data from %d sources:\n", g_agg_count);

    for (int i = 0; i < g_agg_count; i++)
    {
        offset += snprintf(resp + offset, 2048 - offset, "  %s: %d bytes\n",
                           g_aggregated[i].server_id, g_aggregated[i].data_len);
    }

    *response_len = offset;
    return SGX_SUCCESS;
}
