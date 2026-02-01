#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_enclave_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_init_t* ms = SGX_CAST(ms_enclave_init_t*, pms);
	ms_enclave_init_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_enclave_init_t), ms, sizeof(ms_enclave_init_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = enclave_init();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_handle_tls_session(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_handle_tls_session_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_handle_tls_session_t* ms = SGX_CAST(ms_ecall_handle_tls_session_t*, pms);
	ms_ecall_handle_tls_session_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_handle_tls_session_t), ms, sizeof(ms_ecall_handle_tls_session_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_handle_tls_session(__in_ms.ms_client_sockfd);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_aggregate_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_aggregate_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_aggregate_data_t* ms = SGX_CAST(ms_ecall_aggregate_data_t*, pms);
	ms_ecall_aggregate_data_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_aggregate_data_t), ms, sizeof(ms_ecall_aggregate_data_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_client_id = __in_ms.ms_client_id;
	size_t _len_client_id = __in_ms.ms_client_id_len ;
	char* _in_client_id = NULL;
	const uint8_t* _tmp_data = __in_ms.ms_data;
	size_t _tmp_data_len = __in_ms.ms_data_len;
	size_t _len_data = _tmp_data_len * sizeof(uint8_t);
	uint8_t* _in_data = NULL;
	uint8_t* _tmp_result = __in_ms.ms_result;
	size_t _len_result = 1024;
	uint8_t* _in_result = NULL;
	uint32_t* _tmp_result_len = __in_ms.ms_result_len;
	size_t _len_result_len = sizeof(uint32_t);
	uint32_t* _in_result_len = NULL;
	sgx_status_t _in_retval;

	if (sizeof(*_tmp_data) != 0 &&
		(size_t)_tmp_data_len > (SIZE_MAX / sizeof(*_tmp_data))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_client_id, _len_client_id);
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);
	CHECK_UNIQUE_POINTER(_tmp_result_len, _len_result_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_client_id != NULL && _len_client_id != 0) {
		_in_client_id = (char*)malloc(_len_client_id);
		if (_in_client_id == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_client_id, _len_client_id, _tmp_client_id, _len_client_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_client_id[_len_client_id - 1] = '\0';
		if (_len_client_id != strlen(_in_client_id) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	if (_tmp_result_len != NULL && _len_result_len != 0) {
		if ( _len_result_len % sizeof(*_tmp_result_len) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result_len = (uint32_t*)malloc(_len_result_len)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result_len, 0, _len_result_len);
	}
	_in_retval = ecall_aggregate_data((const char*)_in_client_id, (const uint8_t*)_in_data, _tmp_data_len, _in_result, _in_result_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_result_len) {
		if (memcpy_verw_s(_tmp_result_len, _len_result_len, _in_result_len, _len_result_len)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_client_id) free(_in_client_id);
	if (_in_data) free(_in_data);
	if (_in_result) free(_in_result);
	if (_in_result_len) free(_in_result_len);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_process_and_return(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_process_and_return_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_process_and_return_t* ms = SGX_CAST(ms_ecall_process_and_return_t*, pms);
	ms_ecall_process_and_return_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_process_and_return_t), ms, sizeof(ms_ecall_process_and_return_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_response = __in_ms.ms_response;
	size_t _len_response = 2048;
	uint8_t* _in_response = NULL;
	uint32_t* _tmp_response_len = __in_ms.ms_response_len;
	size_t _len_response_len = sizeof(uint32_t);
	uint32_t* _in_response_len = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_response, _len_response);
	CHECK_UNIQUE_POINTER(_tmp_response_len, _len_response_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_response != NULL && _len_response != 0) {
		if ( _len_response % sizeof(*_tmp_response) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_response = (uint8_t*)malloc(_len_response)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_response, 0, _len_response);
	}
	if (_tmp_response_len != NULL && _len_response_len != 0) {
		if ( _len_response_len % sizeof(*_tmp_response_len) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_response_len = (uint32_t*)malloc(_len_response_len)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_response_len, 0, _len_response_len);
	}
	_in_retval = ecall_process_and_return(_in_response, _in_response_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_response) {
		if (memcpy_verw_s(_tmp_response, _len_response, _in_response, _len_response)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_response_len) {
		if (memcpy_verw_s(_tmp_response_len, _len_response_len, _in_response_len, _len_response_len)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_response) free(_in_response);
	if (_in_response_len) free(_in_response_len);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_enclave_init, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_handle_tls_session, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_aggregate_data, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_process_and_return, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[4][4];
} g_dyn_entry_table = {
	4,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read_socket(int* retval, int sockfd, uint8_t* buf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_read_socket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_socket_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_socket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_socket_t));
	ocalloc_size -= sizeof(ms_ocall_read_socket_t);

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write_socket(int* retval, int sockfd, const uint8_t* buf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_write_socket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_socket_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_socket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_socket_t));
	ocalloc_size -= sizeof(ms_ocall_write_socket_t);

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(const uint8_t*), &__tmp, sizeof(const uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fetch_relay_data(int* retval, int relay_id, uint8_t* buffer, uint32_t buffer_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = 2048;

	ms_ocall_fetch_relay_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fetch_relay_data_t);
	void *__tmp = NULL;

	void *__tmp_buffer = NULL;

	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fetch_relay_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fetch_relay_data_t));
	ocalloc_size -= sizeof(ms_ocall_fetch_relay_data_t);

	if (memcpy_verw_s(&ms->ms_relay_id, sizeof(ms->ms_relay_id), &relay_id, sizeof(relay_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buffer != NULL) {
		if (memcpy_verw_s(&ms->ms_buffer, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buffer = __tmp;
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buffer, 0, _len_buffer);
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}

	if (memcpy_verw_s(&ms->ms_buffer_size, sizeof(ms->ms_buffer_size), &buffer_size, sizeof(buffer_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buffer) {
			if (memcpy_s((void*)buffer, _len_buffer, __tmp_buffer, _len_buffer)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

