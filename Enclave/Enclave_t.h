#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_trts.h"
#include "sgx_key_exchange.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t enclave_init(void);
sgx_status_t ecall_handle_tls_session(int client_sockfd);
sgx_status_t ecall_aggregate_data(const char* client_id, const uint8_t* data, size_t data_len, uint8_t* result, uint32_t* result_len);
sgx_status_t ecall_process_and_return(uint8_t* response, uint32_t* response_len);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_read_socket(int* retval, int sockfd, uint8_t* buf, size_t len);
sgx_status_t SGX_CDECL ocall_write_socket(int* retval, int sockfd, const uint8_t* buf, size_t len);
sgx_status_t SGX_CDECL ocall_fetch_relay_data(int* retval, int relay_id, uint8_t* buffer, uint32_t buffer_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
