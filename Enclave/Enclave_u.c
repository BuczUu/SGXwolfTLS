#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_enclave_init_t {
	sgx_status_t ms_retval;
} ms_enclave_init_t;

typedef struct ms_ecall_handle_tls_session_t {
	sgx_status_t ms_retval;
	int ms_client_sockfd;
} ms_ecall_handle_tls_session_t;

typedef struct ms_ecall_aggregate_data_t {
	sgx_status_t ms_retval;
	const char* ms_client_id;
	size_t ms_client_id_len;
	const uint8_t* ms_data;
	size_t ms_data_len;
	uint8_t* ms_result;
	uint32_t* ms_result_len;
} ms_ecall_aggregate_data_t;

typedef struct ms_ecall_process_and_return_t {
	sgx_status_t ms_retval;
	uint8_t* ms_response;
	uint32_t* ms_response_len;
} ms_ecall_process_and_return_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_read_socket_t {
	int ms_retval;
	int ms_sockfd;
	uint8_t* ms_buf;
	size_t ms_len;
} ms_ocall_read_socket_t;

typedef struct ms_ocall_write_socket_t {
	int ms_retval;
	int ms_sockfd;
	const uint8_t* ms_buf;
	size_t ms_len;
} ms_ocall_write_socket_t;

typedef struct ms_ocall_fetch_relay_data_t {
	int ms_retval;
	int ms_relay_id;
	uint8_t* ms_buffer;
	uint32_t ms_buffer_size;
} ms_ocall_fetch_relay_data_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_socket(void* pms)
{
	ms_ocall_read_socket_t* ms = SGX_CAST(ms_ocall_read_socket_t*, pms);
	ms->ms_retval = ocall_read_socket(ms->ms_sockfd, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write_socket(void* pms)
{
	ms_ocall_write_socket_t* ms = SGX_CAST(ms_ocall_write_socket_t*, pms);
	ms->ms_retval = ocall_write_socket(ms->ms_sockfd, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fetch_relay_data(void* pms)
{
	ms_ocall_fetch_relay_data_t* ms = SGX_CAST(ms_ocall_fetch_relay_data_t*, pms);
	ms->ms_retval = ocall_fetch_relay_data(ms->ms_relay_id, ms->ms_buffer, ms->ms_buffer_size);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[4];
} ocall_table_Enclave = {
	4,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_read_socket,
		(void*)Enclave_ocall_write_socket,
		(void*)Enclave_ocall_fetch_relay_data,
	}
};
sgx_status_t enclave_init(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_enclave_init_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_handle_tls_session(sgx_enclave_id_t eid, sgx_status_t* retval, int client_sockfd)
{
	sgx_status_t status;
	ms_ecall_handle_tls_session_t ms;
	ms.ms_client_sockfd = client_sockfd;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_aggregate_data(sgx_enclave_id_t eid, sgx_status_t* retval, const char* client_id, const uint8_t* data, size_t data_len, uint8_t* result, uint32_t* result_len)
{
	sgx_status_t status;
	ms_ecall_aggregate_data_t ms;
	ms.ms_client_id = client_id;
	ms.ms_client_id_len = client_id ? strlen(client_id) + 1 : 0;
	ms.ms_data = data;
	ms.ms_data_len = data_len;
	ms.ms_result = result;
	ms.ms_result_len = result_len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_process_and_return(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* response, uint32_t* response_len)
{
	sgx_status_t status;
	ms_ecall_process_and_return_t ms;
	ms.ms_response = response;
	ms.ms_response_len = response_len;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

