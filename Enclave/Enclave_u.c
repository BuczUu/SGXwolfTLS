#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_enclave_init_t {
	sgx_status_t ms_retval;
} ms_enclave_init_t;

typedef struct ms_ecall_handle_tls_session_t {
	sgx_status_t ms_retval;
	int ms_client_sockfd;
} ms_ecall_handle_tls_session_t;

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

typedef struct ms_ocall_connect_relay_t {
	int ms_retval;
	int ms_relay_id;
	int* ms_sockfd;
} ms_ocall_connect_relay_t;

typedef struct ms_ocall_close_socket_t {
	int ms_sockfd;
} ms_ocall_close_socket_t;

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

static sgx_status_t SGX_CDECL Enclave_ocall_connect_relay(void* pms)
{
	ms_ocall_connect_relay_t* ms = SGX_CAST(ms_ocall_connect_relay_t*, pms);
	ms->ms_retval = ocall_connect_relay(ms->ms_relay_id, ms->ms_sockfd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_close_socket(void* pms)
{
	ms_ocall_close_socket_t* ms = SGX_CAST(ms_ocall_close_socket_t*, pms);
	ocall_close_socket(ms->ms_sockfd);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_Enclave = {
	5,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_read_socket,
		(void*)Enclave_ocall_write_socket,
		(void*)Enclave_ocall_connect_relay,
		(void*)Enclave_ocall_close_socket,
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

