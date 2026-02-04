#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_trts.h"
#include "sgx_key_exchange.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_READ_SOCKET_DEFINED__
#define OCALL_READ_SOCKET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_socket, (int sockfd, uint8_t* buf, size_t len));
#endif
#ifndef OCALL_WRITE_SOCKET_DEFINED__
#define OCALL_WRITE_SOCKET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_socket, (int sockfd, const uint8_t* buf, size_t len));
#endif
#ifndef OCALL_CONNECT_RELAY_DEFINED__
#define OCALL_CONNECT_RELAY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_connect_relay, (int relay_id, int* sockfd));
#endif
#ifndef OCALL_CLOSE_SOCKET_DEFINED__
#define OCALL_CLOSE_SOCKET_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close_socket, (int sockfd));
#endif

sgx_status_t enclave_init(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t ecall_handle_tls_session(sgx_enclave_id_t eid, sgx_status_t* retval, int client_sockfd);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
