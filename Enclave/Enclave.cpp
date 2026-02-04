#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Enclave_t.h"
#include "sgx_trts.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/integer.h>
#include "Include/mtls_certs_pem.h"

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
static WOLFSSL_CTX *g_wolfssl_relay_ctx = NULL;

static const char *THETA_INV_STR = "629308883988655905523753285434973609735521955413121655314869469798359331814399404413728965733664739718336549541383011258452262804433288695289430286141092560";
static const char *N_STR = "681857855702518740704953601369673633705135695298229808586169116464264137928690445929259101132662230830731696844493369649448124756686478300425338032781377689";
static const char *N_SQUARED_STR = "464930135383236868762294282050575283938809426167548765226163728200940659685431102544884065874275716634166967233262482170376770348807693876165684682131900426399828933721979124423334934940339166587941442600701425521344926937573241873018987863259105401307755464132075701586932737973059065335629721586487188866980721";
static const int DEGREE = 8; // Threshold degree (t in t-of-n scheme)

static const char *DECODE_ALPHABET = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890";
static const int SPLIT_A = 10;
static const int SPLIT_B = 5;
static const size_t MAX_PREFIX_LEN = 256;
static const size_t MAX_BUCKET_LEN = 256;

// Decode BigInteger to string using base-N alphabet
static int decode_bigint_to_string(const mp_int *encoded, char *out, size_t out_len)
{
    if (!encoded || !out || out_len < 2)
    {
        return -1;
    }

    size_t base_value = strlen(DECODE_ALPHABET);
    if (base_value < 2)
    {
        return -2;
    }

    mp_int value, base_mp, rem;
    if (mp_init(&value) != MP_OKAY || mp_init(&base_mp) != MP_OKAY || mp_init(&rem) != MP_OKAY)
    {
        return -3;
    }

    mp_copy(encoded, &value);
    if (mp_iszero(&value))
    {
        out[0] = DECODE_ALPHABET[0];
        out[1] = '\0';
        mp_clear(&value);
        mp_clear(&base_mp);
        mp_clear(&rem);
        return 0;
    }
    mp_set_int(&base_mp, (unsigned long)base_value);

    char tmp[1024];
    size_t tmp_len = 0;

    while (!mp_iszero(&value))
    {
        if (mp_mod(&value, &base_mp, &rem) != MP_OKAY)
        {
            mp_clear(&value);
            mp_clear(&base_mp);
            mp_clear(&rem);
            return -4;
        }

        unsigned char rem_buf[8];
        unsigned long idx = 0;
        int rem_len = mp_unsigned_bin_size(&rem);
        if (rem_len <= 0 || rem_len > (int)sizeof(rem_buf))
        {
            mp_clear(&value);
            mp_clear(&base_mp);
            mp_clear(&rem);
            return -5;
        }
        if (mp_to_unsigned_bin(&rem, rem_buf) != MP_OKAY)
        {
            mp_clear(&value);
            mp_clear(&base_mp);
            mp_clear(&rem);
            return -5;
        }
        for (int i = 0; i < rem_len; i++)
        {
            idx = (idx << 8) | rem_buf[i];
        }
        if (idx >= base_value)
        {
            mp_clear(&value);
            mp_clear(&base_mp);
            mp_clear(&rem);
            return -5;
        }

        if (tmp_len + 1 >= sizeof(tmp))
        {
            mp_clear(&value);
            mp_clear(&base_mp);
            mp_clear(&rem);
            return -6;
        }

        tmp[tmp_len++] = DECODE_ALPHABET[idx];

        if (mp_div(&value, &base_mp, &value, NULL) != MP_OKAY)
        {
            mp_clear(&value);
            mp_clear(&base_mp);
            mp_clear(&rem);
            return -7;
        }
    }

    if (tmp_len + 1 > out_len)
    {
        mp_clear(&value);
        mp_clear(&base_mp);
        mp_clear(&rem);
        return -8;
    }

    for (size_t i = 0; i < tmp_len; i++)
    {
        out[i] = tmp[tmp_len - 1 - i];
    }
    out[tmp_len] = '\0';

    mp_clear(&value);
    mp_clear(&base_mp);
    mp_clear(&rem);
    return 0;
}

// SplitAndDistribute: returns prefix and distributes remaining chars into B buckets
static int split_and_distribute(const char *s,
                                char *prefix, size_t prefix_len,
                                char buckets[][MAX_BUCKET_LEN], size_t bucket_len)
{
    if (!s || !prefix || !buckets || prefix_len < 2 || bucket_len < 2)
    {
        return -1;
    }

    int A = SPLIT_A;
    int B = SPLIT_B;
    if (A < 0)
    {
        A = 0;
    }
    if (B <= 0)
    {
        strncpy(prefix, s, prefix_len - 1);
        prefix[prefix_len - 1] = '\0';
        return 0;
    }

    size_t len = strlen(s);
    if ((size_t)A > len)
    {
        A = (int)len;
    }

    size_t copy_len = (size_t)A;
    if (copy_len >= prefix_len)
    {
        copy_len = prefix_len - 1;
    }
    memcpy(prefix, s, copy_len);
    prefix[copy_len] = '\0';

    for (int i = 0; i < B; i++)
    {
        buckets[i][0] = '\0';
    }

    size_t idx = 0;
    for (size_t i = (size_t)A; i < len; i++)
    {
        int b = (int)(idx % (size_t)B);
        size_t blen = strlen(buckets[b]);
        if (blen + 1 < bucket_len)
        {
            buckets[b][blen] = s[i];
            buckets[b][blen + 1] = '\0';
        }
        idx++;
    }

    return 0;
}

// Helper function: multiply list of mp_int modulo a modulus
static int mult_list(mp_int *result, mp_int partial_decryptions[], int count, mp_int *modulus)
{
    int ret;
    mp_int temp;

    ret = mp_init(result);
    if (ret != MP_OKAY)
        return ret;

    ret = mp_init(&temp);
    if (ret != MP_OKAY)
    {
        mp_clear(result);
        return ret;
    }

    mp_set(result, 1); // result = 1

    for (int i = 0; i < count; i++)
    {
        // result = result * partial_decryptions[i]
        ret = mp_mul(result, &partial_decryptions[i], &temp);
        if (ret != MP_OKAY)
        {
            mp_clear(result);
            mp_clear(&temp);
            return ret;
        }

        // If modulus is provided, reduce
        if (modulus != NULL && !mp_iszero(modulus))
        {
            ret = mp_mod(&temp, modulus, result);
            if (ret != MP_OKAY)
            {
                mp_clear(result);
                mp_clear(&temp);
                return ret;
            }
        }
        else
        {
            mp_copy(&temp, result);
        }
    }

    mp_clear(&temp);
    return MP_OKAY;
}

// Threshold Paillier decryption
// partial_shares: array of partial decryptions (as decimal strings)
// num_shares: number of shares
// result_str: output buffer for decrypted message (as decimal string)
// result_str_len: size of output buffer
static int threshold_paillier_decrypt(const char *partial_shares[], int num_shares,
                                      char *result_str, int result_str_len)
{
    int ret;
    mp_int theta_inv, n, n_squared;
    mp_int *partial_decryptions = NULL;
    mp_int combined_decryption, temp1, temp2, temp3, message, one;

    // Initialize all mp_int variables
    ret = mp_init(&theta_inv);
    if (ret != MP_OKAY)
        return ret;
    ret = mp_init(&n);
    if (ret != MP_OKAY)
    {
        mp_clear(&theta_inv);
        return ret;
    }
    ret = mp_init(&n_squared);
    if (ret != MP_OKAY)
    {
        mp_clear(&theta_inv);
        mp_clear(&n);
        return ret;
    }
    ret = mp_init(&combined_decryption);
    if (ret != MP_OKAY)
        goto cleanup_basic;
    ret = mp_init(&temp1);
    if (ret != MP_OKAY)
        goto cleanup_basic;
    ret = mp_init(&temp2);
    if (ret != MP_OKAY)
        goto cleanup_basic;
    ret = mp_init(&temp3);
    if (ret != MP_OKAY)
        goto cleanup_basic;
    ret = mp_init(&message);
    if (ret != MP_OKAY)
        goto cleanup_basic;
    ret = mp_init(&one);
    if (ret != MP_OKAY)
        goto cleanup_basic;

    // Load constants from strings
    ret = mp_read_radix(&theta_inv, THETA_INV_STR, 10);
    if (ret != MP_OKAY)
        goto cleanup_all;
    ret = mp_read_radix(&n, N_STR, 10);
    if (ret != MP_OKAY)
        goto cleanup_all;
    ret = mp_read_radix(&n_squared, N_SQUARED_STR, 10);
    if (ret != MP_OKAY)
        goto cleanup_all;

    mp_set(&one, 1);

    // Check if we have enough shares
    if (num_shares < DEGREE + 1)
    {
        ocall_print_string("[ENCLAVE] Not enough shares for decryption\n");
        ret = -1;
        goto cleanup_all;
    }

    // Allocate and load partial decryptions
    partial_decryptions = (mp_int *)malloc(sizeof(mp_int) * (DEGREE + 1));
    if (!partial_decryptions)
    {
        ret = -2;
        goto cleanup_all;
    }

    for (int i = 0; i <= DEGREE; i++)
    {
        ret = mp_init(&partial_decryptions[i]);
        if (ret != MP_OKAY)
            goto cleanup_partials;

        ret = mp_read_radix(&partial_decryptions[i], partial_shares[i], 10);
        if (ret != MP_OKAY)
            goto cleanup_partials;
    }

    // Combine partial decryptions: product of first (degree+1) shares mod n_squared
    ret = mult_list(&combined_decryption, partial_decryptions, DEGREE + 1, &n_squared);
    if (ret != MP_OKAY)
    {
        ocall_print_string("[ENCLAVE] Failed to multiply partial decryptions\n");
        goto cleanup_partials;
    }

    // temp1 = combined_decryption - 1
    ret = mp_sub(&combined_decryption, &one, &temp1);
    if (ret != MP_OKAY)
        goto cleanup_partials;

    // Check if temp1 is divisible by n
    mp_int remainder;
    ret = mp_init(&remainder);
    if (ret != MP_OKAY)
        goto cleanup_partials;
    ret = mp_mod(&temp1, &n, &remainder);
    if (ret != MP_OKAY)
    {
        mp_clear(&remainder);
        goto cleanup_partials;
    }

    if (!mp_iszero(&remainder))
    {
        ocall_print_string("[ENCLAVE] Combined decryption error: not divisible by N\n");
        mp_clear(&remainder);
        ret = -3;
        goto cleanup_partials;
    }
    mp_clear(&remainder);

    // temp2 = temp1 / n
    ret = mp_div(&temp1, &n, &temp2, NULL);
    if (ret != MP_OKAY)
        goto cleanup_partials;

    // temp3 = temp2 * theta_inv
    ret = mp_mul(&temp2, &theta_inv, &temp3);
    if (ret != MP_OKAY)
        goto cleanup_partials;

    // message = temp3 mod n
    ret = mp_mod(&temp3, &n, &message);
    if (ret != MP_OKAY)
        goto cleanup_partials;

    // Convert result to decimal string
    ret = mp_toradix(&message, result_str, 10);

cleanup_partials:
    if (partial_decryptions)
    {
        for (int i = 0; i <= DEGREE; i++)
        {
            mp_clear(&partial_decryptions[i]);
        }
        free(partial_decryptions);
    }

cleanup_all:
    mp_clear(&one);
    mp_clear(&message);
    mp_clear(&temp3);
    mp_clear(&temp2);
    mp_clear(&temp1);
    mp_clear(&combined_decryption);

cleanup_basic:
    mp_clear(&n_squared);
    mp_clear(&n);
    mp_clear(&theta_inv);

    return ret;
}

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

static int fetch_relay_data_tls(int relay_id, uint8_t *buffer, uint32_t buffer_size, int *out_len)
{
    if (!buffer || !out_len || !g_wolfssl_relay_ctx)
    {
        return -1;
    }

    int sockfd = -1;
    int ocall_ret = -1;
    sgx_status_t ocall_status = ocall_connect_relay(&ocall_ret, relay_id, &sockfd);
    if (ocall_status != SGX_SUCCESS || ocall_ret != 0 || sockfd < 0)
    {
        return -1;
    }

    int ret = 0;

    WOLFSSL *ssl = wolfSSL_new(g_wolfssl_relay_ctx);
    if (!ssl)
    {
        ocall_close_socket(sockfd);
        return -1;
    }

    wolfSSL_SetIORecv(g_wolfssl_relay_ctx, wolfssl_recv_callback);
    wolfSSL_SetIOSend(g_wolfssl_relay_ctx, wolfssl_send_callback);
    wolfSSL_SetIOReadCtx(ssl, &sockfd);
    wolfSSL_SetIOWriteCtx(ssl, &sockfd);

    ret = wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS)
    {
        wolfSSL_free(ssl);
        ocall_close_socket(sockfd);
        return -1;
    }

    uint32_t request_size = 0;
    ret = wolfSSL_write(ssl, (unsigned char *)&request_size, 4);
    if (ret != 4)
    {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        ocall_close_socket(sockfd);
        return -1;
    }

    unsigned char size_bytes[4];
    ret = wolfSSL_read(ssl, size_bytes, 4);
    if (ret != 4)
    {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        ocall_close_socket(sockfd);
        return -1;
    }

    uint32_t response_size = *(uint32_t *)size_bytes;
    if (response_size > buffer_size)
        response_size = buffer_size;

    if (response_size > 0)
    {
        ret = wolfSSL_read(ssl, buffer, response_size);
        if (ret != (int)response_size)
        {
            wolfSSL_shutdown(ssl);
            wolfSSL_free(ssl);
            ocall_close_socket(sockfd);
            return -1;
        }
    }

    *out_len = (int)response_size;

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    ocall_close_socket(sockfd);
    return 0;
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

    // Load CA for client certificate verification (mTLS)
    int ret = wolfSSL_CTX_load_verify_buffer(g_wolfssl_ctx,
                                             (const unsigned char *)DVC_CA_CERT_PEM,
                                             (int)strlen(DVC_CA_CERT_PEM),
                                             SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS)
    {
        ocall_print_string("[ENCLAVE] Failed to load CA certificate\n");
        return SGX_ERROR_UNEXPECTED;
    }

    // Require client certificate
    wolfSSL_CTX_set_verify(g_wolfssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    // Load server certificate and key (mTLS)
    ret = wolfSSL_CTX_use_certificate_buffer(g_wolfssl_ctx,
                                             (const unsigned char *)DVC_ENCLAVE_CERT_PEM,
                                             (int)strlen(DVC_ENCLAVE_CERT_PEM),
                                             SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS)
    {
        ocall_print_string("[ENCLAVE] Failed to load certificate\n");
        return SGX_ERROR_UNEXPECTED;
    }

    ret = wolfSSL_CTX_use_PrivateKey_buffer(g_wolfssl_ctx,
                                            (const unsigned char *)DVC_ENCLAVE_KEY_PEM,
                                            (int)strlen(DVC_ENCLAVE_KEY_PEM),
                                            SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS)
    {
        ocall_print_string("[ENCLAVE] Failed to load private key\n");
        return SGX_ERROR_UNEXPECTED;
    }

    // Create relay client context (TLS to relay servers inside enclave)
    g_wolfssl_relay_ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!g_wolfssl_relay_ctx)
    {
        ocall_print_string("[ENCLAVE] Failed to create relay TLS context\n");
        return SGX_ERROR_UNEXPECTED;
    }
    // Load CA for relay verification and set client cert (mTLS)
    ret = wolfSSL_CTX_load_verify_buffer(g_wolfssl_relay_ctx,
                                         (const unsigned char *)DVC_CA_CERT_PEM,
                                         (int)strlen(DVC_CA_CERT_PEM),
                                         SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS)
    {
        ocall_print_string("[ENCLAVE] Failed to load relay CA certificate\n");
        return SGX_ERROR_UNEXPECTED;
    }

    ret = wolfSSL_CTX_use_certificate_buffer(g_wolfssl_relay_ctx,
                                             (const unsigned char *)DVC_ENCLAVE_CERT_PEM,
                                             (int)strlen(DVC_ENCLAVE_CERT_PEM),
                                             SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS)
    {
        ocall_print_string("[ENCLAVE] Failed to load relay client certificate\n");
        return SGX_ERROR_UNEXPECTED;
    }

    ret = wolfSSL_CTX_use_PrivateKey_buffer(g_wolfssl_relay_ctx,
                                            (const unsigned char *)DVC_ENCLAVE_KEY_PEM,
                                            (int)strlen(DVC_ENCLAVE_KEY_PEM),
                                            SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS)
    {
        ocall_print_string("[ENCLAVE] Failed to load relay client key\n");
        return SGX_ERROR_UNEXPECTED;
    }

    wolfSSL_CTX_set_verify(g_wolfssl_relay_ctx, SSL_VERIFY_PEER, NULL);

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
        char response[4096];
        int resp_len = 0;

        if (strcmp((char *)buf, "FETCH") == 0)
        {
            // FETCH command: fetch data from relay servers, aggregate, and decrypt
            ocall_print_string("[ENCLAVE] FETCH: Fetching data from relay servers...\n");

            resp_len = 0;

            // Clear previous aggregated data
            g_agg_count = 0;

            // Fetch from all relay servers (1-10) and store in g_aggregated
            uint8_t relay_buffer[2048];
            int fetched_count = 0;

            for (int relay_id = 1; relay_id <= 10 && g_agg_count < MAX_AGG_DATA; relay_id++)
            {
                int relay_len = 0;
                int fetch_ret = fetch_relay_data_tls(relay_id, relay_buffer, sizeof(relay_buffer), &relay_len);
                if (fetch_ret == 0 && relay_len > 0)
                {
                    // Store in aggregated data structure
                    snprintf(g_aggregated[g_agg_count].server_id, 64, "RELAY_%d", relay_id);
                    if (relay_len > 512)
                        relay_len = 512;
                    memcpy(g_aggregated[g_agg_count].data, relay_buffer, relay_len);
                    g_aggregated[g_agg_count].data[relay_len] = '\0'; // Null terminate
                    g_aggregated[g_agg_count].data_len = relay_len;
                    g_agg_count++;
                    fetched_count++;
                }
            }

            // Perform threshold decryption if we have enough shares
            if (g_agg_count >= DEGREE + 1)
            {
                ocall_print_string("[ENCLAVE] Performing threshold Paillier decryption...\n");

                const char *partial_shares[MAX_SERVERS];
                for (int i = 0; i < g_agg_count; i++)
                {
                    partial_shares[i] = (const char *)g_aggregated[i].data;
                }

                char decrypted_result[1024];
                int decrypt_ret = threshold_paillier_decrypt(partial_shares, g_agg_count,
                                                             decrypted_result, sizeof(decrypted_result));

                if (decrypt_ret == MP_OKAY)
                {
                    mp_int decoded_mp;
                    if (mp_init(&decoded_mp) == MP_OKAY &&
                        mp_read_radix(&decoded_mp, decrypted_result, 10) == MP_OKAY)
                    {
                        char decoded_text[512];
                        int decode_ret = decode_bigint_to_string(&decoded_mp, decoded_text, sizeof(decoded_text));
                        if (decode_ret == 0)
                        {
                            char prefix[MAX_PREFIX_LEN];
                            char buckets[SPLIT_B][MAX_BUCKET_LEN];
                            int split_ret = split_and_distribute(decoded_text, prefix, sizeof(prefix), buckets, MAX_BUCKET_LEN);
                            if (split_ret == 0)
                            {
                                resp_len = snprintf(response, sizeof(response),
                                                    "PREFIX:%s\n"
                                                    "B0:%s\n"
                                                    "B1:%s\n"
                                                    "B2:%s\n"
                                                    "B3:%s\n"
                                                    "B4:%s",
                                                    prefix,
                                                    buckets[0], buckets[1], buckets[2], buckets[3], buckets[4]);
                            }
                            else
                            {
                                resp_len = snprintf(response, sizeof(response),
                                                    "[ERROR] SplitAndDistribute failed (code: %d)",
                                                    split_ret);
                            }
                        }
                        else
                        {
                            resp_len = snprintf(response, sizeof(response),
                                                "[ERROR] Decode failed (code: %d)",
                                                decode_ret);
                        }
                        mp_clear(&decoded_mp);
                    }
                    else
                    {
                        resp_len = snprintf(response, sizeof(response),
                                            "[ERROR] Failed to parse decrypted message for decode");
                    }
                }
                else
                {
                    resp_len = snprintf(response, sizeof(response),
                                        "[ERROR] Threshold decryption failed (code: %d)",
                                        decrypt_ret);
                }
            }
            else
            {
                resp_len = snprintf(response, sizeof(response),
                                    "[ERROR] Not enough shares for decryption (required: %d, received: %d)",
                                    DEGREE + 1, g_agg_count);
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
