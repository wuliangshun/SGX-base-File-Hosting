#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_encrypt_file_t {
	int ms_retval;
	char* ms_input_file;
	size_t ms_input_file_len;
	char* ms_output_file;
	size_t ms_output_file_len;
} ms_ecall_encrypt_file_t;

typedef struct ms_ecall_decrypt_file_t {
	int ms_retval;
	char* ms_input_file;
	size_t ms_input_file_len;
	char* ms_username;
	size_t ms_username_len;
} ms_ecall_decrypt_file_t;

typedef struct ms_ocall_open_t {
	int ms_retval;
	char* ms_path;
} ms_ocall_open_t;

typedef struct ms_ocall_create_t {
	int ms_retval;
	char* ms_path;
} ms_ocall_create_t;

typedef struct ms_ocall_read_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_size;
} ms_ocall_read_t;

typedef struct ms_ocall_write_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_size;
} ms_ocall_write_t;

typedef struct ms_ocall_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_close_t;

typedef struct ms_ocall_print_t {
	char* ms_msg;
} ms_ocall_print_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_sgxprotectedfs_exclusive_file_open_t {
	void* ms_retval;
	char* ms_filename;
	uint8_t ms_read_only;
	int64_t* ms_file_size;
	int32_t* ms_error_code;
} ms_u_sgxprotectedfs_exclusive_file_open_t;

typedef struct ms_u_sgxprotectedfs_check_if_file_exists_t {
	uint8_t ms_retval;
	char* ms_filename;
} ms_u_sgxprotectedfs_check_if_file_exists_t;

typedef struct ms_u_sgxprotectedfs_fread_node_t {
	int32_t ms_retval;
	void* ms_f;
	uint64_t ms_node_number;
	uint8_t* ms_buffer;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_fread_node_t;

typedef struct ms_u_sgxprotectedfs_fwrite_node_t {
	int32_t ms_retval;
	void* ms_f;
	uint64_t ms_node_number;
	uint8_t* ms_buffer;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_fwrite_node_t;

typedef struct ms_u_sgxprotectedfs_fclose_t {
	int32_t ms_retval;
	void* ms_f;
} ms_u_sgxprotectedfs_fclose_t;

typedef struct ms_u_sgxprotectedfs_fflush_t {
	uint8_t ms_retval;
	void* ms_f;
} ms_u_sgxprotectedfs_fflush_t;

typedef struct ms_u_sgxprotectedfs_remove_t {
	int32_t ms_retval;
	char* ms_filename;
} ms_u_sgxprotectedfs_remove_t;

typedef struct ms_u_sgxprotectedfs_recovery_file_open_t {
	void* ms_retval;
	char* ms_filename;
} ms_u_sgxprotectedfs_recovery_file_open_t;

typedef struct ms_u_sgxprotectedfs_fwrite_recovery_node_t {
	uint8_t ms_retval;
	void* ms_f;
	uint8_t* ms_data;
	uint32_t ms_data_length;
} ms_u_sgxprotectedfs_fwrite_recovery_node_t;

typedef struct ms_u_sgxprotectedfs_do_file_recovery_t {
	int32_t ms_retval;
	char* ms_filename;
	char* ms_recovery_filename;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_do_file_recovery_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

static sgx_status_t SGX_CDECL sgx_ecall_encrypt_file(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_encrypt_file_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_encrypt_file_t* ms = SGX_CAST(ms_ecall_encrypt_file_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_input_file = ms->ms_input_file;
	size_t _len_input_file = ms->ms_input_file_len ;
	char* _in_input_file = NULL;
	char* _tmp_output_file = ms->ms_output_file;
	size_t _len_output_file = ms->ms_output_file_len ;
	char* _in_output_file = NULL;

	CHECK_UNIQUE_POINTER(_tmp_input_file, _len_input_file);
	CHECK_UNIQUE_POINTER(_tmp_output_file, _len_output_file);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_input_file != NULL && _len_input_file != 0) {
		_in_input_file = (char*)malloc(_len_input_file);
		if (_in_input_file == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_input_file, _tmp_input_file, _len_input_file);
		_in_input_file[_len_input_file - 1] = '\0';
		if (_len_input_file != strlen(_in_input_file) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_output_file != NULL && _len_output_file != 0) {
		_in_output_file = (char*)malloc(_len_output_file);
		if (_in_output_file == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_output_file, _tmp_output_file, _len_output_file);
		_in_output_file[_len_output_file - 1] = '\0';
		if (_len_output_file != strlen(_in_output_file) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_encrypt_file((const char*)_in_input_file, (const char*)_in_output_file);
err:
	if (_in_input_file) free((void*)_in_input_file);
	if (_in_output_file) free((void*)_in_output_file);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_decrypt_file(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_decrypt_file_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_decrypt_file_t* ms = SGX_CAST(ms_ecall_decrypt_file_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_input_file = ms->ms_input_file;
	size_t _len_input_file = ms->ms_input_file_len ;
	char* _in_input_file = NULL;
	char* _tmp_username = ms->ms_username;
	size_t _len_username = ms->ms_username_len ;
	char* _in_username = NULL;

	CHECK_UNIQUE_POINTER(_tmp_input_file, _len_input_file);
	CHECK_UNIQUE_POINTER(_tmp_username, _len_username);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_input_file != NULL && _len_input_file != 0) {
		_in_input_file = (char*)malloc(_len_input_file);
		if (_in_input_file == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_input_file, _tmp_input_file, _len_input_file);
		_in_input_file[_len_input_file - 1] = '\0';
		if (_len_input_file != strlen(_in_input_file) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_username != NULL && _len_username != 0) {
		_in_username = (char*)malloc(_len_username);
		if (_in_username == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_username, _tmp_username, _len_username);
		_in_username[_len_username - 1] = '\0';
		if (_len_username != strlen(_in_username) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_decrypt_file((const char*)_in_input_file, (const char*)_in_username);
err:
	if (_in_input_file) free((void*)_in_input_file);
	if (_in_username) free((void*)_in_username);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_ecall_encrypt_file, 0},
		{(void*)(uintptr_t)sgx_ecall_decrypt_file, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[25][2];
} g_dyn_entry_table = {
	25,
	{
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_open(int* retval, const char* path)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_ocall_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_open_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_open_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		memcpy(__tmp, path, _len_path);
		__tmp = (void *)((size_t)__tmp + _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_create(int* retval, const char* path)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_ocall_create_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_create_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_create_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_create_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		memcpy(__tmp, path, _len_path);
		__tmp = (void *)((size_t)__tmp + _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read(ssize_t* retval, int fd, void* buf, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = size;

	ms_ocall_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write(ssize_t* retval, int fd, const void* buf, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = size;

	ms_ocall_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		memcpy(__tmp, buf, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_close_t));

	ms->ms_fd = fd;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print(const char* msg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_msg = msg ? strlen(msg) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;

	ocalloc_size += (msg != NULL && sgx_is_within_enclave(msg, _len_msg)) ? _len_msg : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));

	if (msg != NULL && sgx_is_within_enclave(msg, _len_msg)) {
		ms->ms_msg = (char*)__tmp;
		memcpy(__tmp, msg, _len_msg);
		__tmp = (void *)((size_t)__tmp + _len_msg);
	} else if (msg == NULL) {
		ms->ms_msg = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;
	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) memcpy((void*)cpuinfo, __tmp_cpuinfo, _len_cpuinfo);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		memcpy(__tmp, waiters, _len_waiters);
		__tmp = (void *)((size_t)__tmp + _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_exclusive_file_open(void** retval, const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_file_size = sizeof(int64_t);
	size_t _len_error_code = sizeof(int32_t);

	ms_u_sgxprotectedfs_exclusive_file_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_exclusive_file_open_t);
	void *__tmp = NULL;

	void *__tmp_file_size = NULL;
	void *__tmp_error_code = NULL;
	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;
	ocalloc_size += (file_size != NULL && sgx_is_within_enclave(file_size, _len_file_size)) ? _len_file_size : 0;
	ocalloc_size += (error_code != NULL && sgx_is_within_enclave(error_code, _len_error_code)) ? _len_error_code : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_exclusive_file_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_exclusive_file_open_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_read_only = read_only;
	if (file_size != NULL && sgx_is_within_enclave(file_size, _len_file_size)) {
		ms->ms_file_size = (int64_t*)__tmp;
		__tmp_file_size = __tmp;
		memset(__tmp_file_size, 0, _len_file_size);
		__tmp = (void *)((size_t)__tmp + _len_file_size);
	} else if (file_size == NULL) {
		ms->ms_file_size = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (error_code != NULL && sgx_is_within_enclave(error_code, _len_error_code)) {
		ms->ms_error_code = (int32_t*)__tmp;
		__tmp_error_code = __tmp;
		memset(__tmp_error_code, 0, _len_error_code);
		__tmp = (void *)((size_t)__tmp + _len_error_code);
	} else if (error_code == NULL) {
		ms->ms_error_code = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (file_size) memcpy((void*)file_size, __tmp_file_size, _len_file_size);
		if (error_code) memcpy((void*)error_code, __tmp_error_code, _len_error_code);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_check_if_file_exists(uint8_t* retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_u_sgxprotectedfs_check_if_file_exists_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_check_if_file_exists_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_check_if_file_exists_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_check_if_file_exists_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fread_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = node_size;

	ms_u_sgxprotectedfs_fread_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fread_node_t);
	void *__tmp = NULL;

	void *__tmp_buffer = NULL;
	ocalloc_size += (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) ? _len_buffer : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fread_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fread_node_t));

	ms->ms_f = SGX_CAST(void*, f);
	ms->ms_node_number = node_number;
	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		ms->ms_buffer = (uint8_t*)__tmp;
		__tmp_buffer = __tmp;
		memset(__tmp_buffer, 0, _len_buffer);
		__tmp = (void *)((size_t)__tmp + _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_node_size = node_size;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buffer) memcpy((void*)buffer, __tmp_buffer, _len_buffer);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = node_size;

	ms_u_sgxprotectedfs_fwrite_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fwrite_node_t);
	void *__tmp = NULL;

	ocalloc_size += (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) ? _len_buffer : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fwrite_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fwrite_node_t));

	ms->ms_f = SGX_CAST(void*, f);
	ms->ms_node_number = node_number;
	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		ms->ms_buffer = (uint8_t*)__tmp;
		memcpy(__tmp, buffer, _len_buffer);
		__tmp = (void *)((size_t)__tmp + _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_node_size = node_size;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fclose(int32_t* retval, void* f)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxprotectedfs_fclose_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fclose_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fclose_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fclose_t));

	ms->ms_f = SGX_CAST(void*, f);
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fflush(uint8_t* retval, void* f)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxprotectedfs_fflush_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fflush_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fflush_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fflush_t));

	ms->ms_f = SGX_CAST(void*, f);
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_remove(int32_t* retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_u_sgxprotectedfs_remove_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_remove_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_remove_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_remove_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_recovery_file_open(void** retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_u_sgxprotectedfs_recovery_file_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_recovery_file_open_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_recovery_file_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_recovery_file_open_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_recovery_node(uint8_t* retval, void* f, uint8_t* data, uint32_t data_length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = data_length * sizeof(uint8_t);

	ms_u_sgxprotectedfs_fwrite_recovery_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fwrite_recovery_node_t);
	void *__tmp = NULL;

	ocalloc_size += (data != NULL && sgx_is_within_enclave(data, _len_data)) ? _len_data : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fwrite_recovery_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fwrite_recovery_node_t));

	ms->ms_f = SGX_CAST(void*, f);
	if (data != NULL && sgx_is_within_enclave(data, _len_data)) {
		ms->ms_data = (uint8_t*)__tmp;
		memcpy(__tmp, data, _len_data);
		__tmp = (void *)((size_t)__tmp + _len_data);
	} else if (data == NULL) {
		ms->ms_data = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_data_length = data_length;
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_do_file_recovery(int32_t* retval, const char* filename, const char* recovery_filename, uint32_t node_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_recovery_filename = recovery_filename ? strlen(recovery_filename) + 1 : 0;

	ms_u_sgxprotectedfs_do_file_recovery_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_do_file_recovery_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;
	ocalloc_size += (recovery_filename != NULL && sgx_is_within_enclave(recovery_filename, _len_recovery_filename)) ? _len_recovery_filename : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_do_file_recovery_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_do_file_recovery_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		memcpy(__tmp, filename, _len_filename);
		__tmp = (void *)((size_t)__tmp + _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (recovery_filename != NULL && sgx_is_within_enclave(recovery_filename, _len_recovery_filename)) {
		ms->ms_recovery_filename = (char*)__tmp;
		memcpy(__tmp, recovery_filename, _len_recovery_filename);
		__tmp = (void *)((size_t)__tmp + _len_recovery_filename);
	} else if (recovery_filename == NULL) {
		ms->ms_recovery_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_node_size = node_size;
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(uint32_t);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	void *__tmp_sid = NULL;
	void *__tmp_dh_msg1 = NULL;
	ocalloc_size += (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) ? _len_sid : 0;
	ocalloc_size += (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) ? _len_dh_msg1 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));

	if (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) {
		ms->ms_sid = (uint32_t*)__tmp;
		__tmp_sid = __tmp;
		memset(__tmp_sid, 0, _len_sid);
		__tmp = (void *)((size_t)__tmp + _len_sid);
	} else if (sid == NULL) {
		ms->ms_sid = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) {
		ms->ms_dh_msg1 = (uint8_t*)__tmp;
		__tmp_dh_msg1 = __tmp;
		memset(__tmp_dh_msg1, 0, _len_dh_msg1);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
	} else if (dh_msg1 == NULL) {
		ms->ms_dh_msg1 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg1_size = dh_msg1_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (sid) memcpy((void*)sid, __tmp_sid, _len_sid);
		if (dh_msg1) memcpy((void*)dh_msg1, __tmp_dh_msg1, _len_dh_msg1);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	void *__tmp_dh_msg3 = NULL;
	ocalloc_size += (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) ? _len_dh_msg2 : 0;
	ocalloc_size += (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) ? _len_dh_msg3 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));

	ms->ms_sid = sid;
	if (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) {
		ms->ms_dh_msg2 = (uint8_t*)__tmp;
		memcpy(__tmp, dh_msg2, _len_dh_msg2);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
	} else if (dh_msg2 == NULL) {
		ms->ms_dh_msg2 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg2_size = dh_msg2_size;
	if (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) {
		ms->ms_dh_msg3 = (uint8_t*)__tmp;
		__tmp_dh_msg3 = __tmp;
		memset(__tmp_dh_msg3, 0, _len_dh_msg3);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
	} else if (dh_msg3 == NULL) {
		ms->ms_dh_msg3 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg3_size = dh_msg3_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (dh_msg3) memcpy((void*)dh_msg3, __tmp_dh_msg3, _len_dh_msg3);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));

	ms->ms_sid = sid;
	ms->ms_timeout = timeout;
	status = sgx_ocall(23, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	void *__tmp_pse_message_resp = NULL;
	ocalloc_size += (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) ? _len_pse_message_req : 0;
	ocalloc_size += (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) ? _len_pse_message_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));

	if (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) {
		ms->ms_pse_message_req = (uint8_t*)__tmp;
		memcpy(__tmp, pse_message_req, _len_pse_message_req);
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
	} else if (pse_message_req == NULL) {
		ms->ms_pse_message_req = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_req_size = pse_message_req_size;
	if (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) {
		ms->ms_pse_message_resp = (uint8_t*)__tmp;
		__tmp_pse_message_resp = __tmp;
		memset(__tmp_pse_message_resp, 0, _len_pse_message_resp);
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
	} else if (pse_message_resp == NULL) {
		ms->ms_pse_message_resp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_resp_size = pse_message_resp_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(24, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (pse_message_resp) memcpy((void*)pse_message_resp, __tmp_pse_message_resp, _len_pse_message_resp);
	}
	sgx_ocfree();
	return status;
}

