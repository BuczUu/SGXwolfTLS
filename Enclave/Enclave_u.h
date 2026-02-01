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
#ifndef OCALL_FETCH_RELAY_DATA_DEFINED__
#define OCALL_FETCH_RELAY_DATA_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fetch_relay_data, (int relay_id, uint8_t* buffer, uint32_t buffer_size));
#endif

sgx_status_t enclave_init(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t ecall_handle_tls_session(sgx_enclave_id_t eid, sgx_status_t* retval, int client_sockfd);
sgx_status_t ecall_aggregate_data(sgx_enclave_id_t eid, sgx_status_t* retval, const char* client_id, const uint8_t* data, size_t data_len, uint8_t* result, uint32_t* result_len);
sgx_status_t ecall_process_and_return(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* response, uint32_t* response_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
