#include "isv_enclave_t.h"

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


typedef struct ms_enclave_init_ra_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_p_context;
} ms_enclave_init_ra_t;

typedef struct ms_enclave_ra_close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
} ms_enclave_ra_close_t;

typedef struct ms_verify_att_result_mac_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_mac;
	size_t ms_mac_size;
} ms_verify_att_result_mac_t;

typedef struct ms_put_secret_data_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_p_secret;
	uint32_t ms_secret_size;
	uint8_t* ms_gcm_mac;
} ms_put_secret_data_t;

typedef struct ms_generate_server_key_t {
	sgx_status_t ms_retval;
	uint8_t* ms_out_data;
	uint32_t ms_secret_size;
} ms_generate_server_key_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

static sgx_status_t SGX_CDECL sgx_enclave_init_ra(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_init_ra_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_init_ra_t* ms = SGX_CAST(ms_enclave_init_ra_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_p_context = ms->ms_p_context;
	size_t _len_p_context = sizeof(sgx_ra_context_t);
	sgx_ra_context_t* _in_p_context = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_context, _len_p_context);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_context != NULL && _len_p_context != 0) {
		if ((_in_p_context = (sgx_ra_context_t*)malloc(_len_p_context)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_context, 0, _len_p_context);
	}

	ms->ms_retval = enclave_init_ra(ms->ms_b_pse, _in_p_context);
	if (_in_p_context) {
		if (memcpy_s(_tmp_p_context, _len_p_context, _in_p_context, _len_p_context)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_context) free(_in_p_context);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_ra_close_t* ms = SGX_CAST(ms_enclave_ra_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enclave_ra_close(ms->ms_context);


	return status;
}

static sgx_status_t SGX_CDECL sgx_verify_att_result_mac(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_verify_att_result_mac_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_verify_att_result_mac_t* ms = SGX_CAST(ms_verify_att_result_mac_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_message = ms->ms_message;
	size_t _tmp_message_size = ms->ms_message_size;
	size_t _len_message = _tmp_message_size;
	uint8_t* _in_message = NULL;
	uint8_t* _tmp_mac = ms->ms_mac;
	size_t _tmp_mac_size = ms->ms_mac_size;
	size_t _len_mac = _tmp_mac_size;
	uint8_t* _in_mac = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_message != NULL && _len_message != 0) {
		if ( _len_message % sizeof(*_tmp_message) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_message = (uint8_t*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_message, _len_message, _tmp_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_mac != NULL && _len_mac != 0) {
		if ( _len_mac % sizeof(*_tmp_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_mac = (uint8_t*)malloc(_len_mac);
		if (_in_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_mac, _len_mac, _tmp_mac, _len_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = verify_att_result_mac(ms->ms_context, _in_message, _tmp_message_size, _in_mac, _tmp_mac_size);

err:
	if (_in_message) free(_in_message);
	if (_in_mac) free(_in_mac);
	return status;
}

static sgx_status_t SGX_CDECL sgx_put_secret_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_put_secret_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_put_secret_data_t* ms = SGX_CAST(ms_put_secret_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p_secret = ms->ms_p_secret;
	uint32_t _tmp_secret_size = ms->ms_secret_size;
	size_t _len_p_secret = _tmp_secret_size;
	uint8_t* _in_p_secret = NULL;
	uint8_t* _tmp_gcm_mac = ms->ms_gcm_mac;
	size_t _len_gcm_mac = 16 * sizeof(uint8_t);
	uint8_t* _in_gcm_mac = NULL;

	if (sizeof(*_tmp_gcm_mac) != 0 &&
		16 > (SIZE_MAX / sizeof(*_tmp_gcm_mac))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_p_secret, _len_p_secret);
	CHECK_UNIQUE_POINTER(_tmp_gcm_mac, _len_gcm_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_secret != NULL && _len_p_secret != 0) {
		if ( _len_p_secret % sizeof(*_tmp_p_secret) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_secret = (uint8_t*)malloc(_len_p_secret);
		if (_in_p_secret == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_secret, _len_p_secret, _tmp_p_secret, _len_p_secret)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_gcm_mac != NULL && _len_gcm_mac != 0) {
		if ( _len_gcm_mac % sizeof(*_tmp_gcm_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_gcm_mac = (uint8_t*)malloc(_len_gcm_mac);
		if (_in_gcm_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_gcm_mac, _len_gcm_mac, _tmp_gcm_mac, _len_gcm_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = put_secret_data(ms->ms_context, _in_p_secret, _tmp_secret_size, _in_gcm_mac);

err:
	if (_in_p_secret) free(_in_p_secret);
	if (_in_gcm_mac) free(_in_gcm_mac);
	return status;
}

static sgx_status_t SGX_CDECL sgx_generate_server_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_generate_server_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_generate_server_key_t* ms = SGX_CAST(ms_generate_server_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_out_data = ms->ms_out_data;
	size_t _len_out_data = 32;
	uint8_t* _in_out_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_out_data, _len_out_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_out_data != NULL && _len_out_data != 0) {
		if ( _len_out_data % sizeof(*_tmp_out_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_out_data = (uint8_t*)malloc(_len_out_data);
		if (_in_out_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_out_data, _len_out_data, _tmp_out_data, _len_out_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = generate_server_key(_in_out_data, ms->ms_secret_size);

err:
	if (_in_out_data) free(_in_out_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}

	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
	if (_in_g_a) {
		if (memcpy_s(_tmp_g_a, _len_g_a, _in_g_a, _len_g_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_g_a) free(_in_g_a);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(sgx_ra_msg2_t);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	const sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(sgx_quote_nonce_t);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_msg2 != NULL && _len_p_msg2 != 0) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_msg2, _len_p_msg2, _tmp_p_msg2, _len_p_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_qe_target != NULL && _len_p_qe_target != 0) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_qe_target, _len_p_qe_target, _tmp_p_qe_target, _len_p_qe_target)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL && _len_p_nonce != 0) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}

	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
	if (_in_p_report) {
		if (memcpy_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_nonce) {
		if (memcpy_s(_tmp_p_nonce, _len_p_nonce, _in_p_nonce, _len_p_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_msg2) free(_in_p_msg2);
	if (_in_p_qe_target) free(_in_p_qe_target);
	if (_in_p_report) free(_in_p_report);
	if (_in_p_nonce) free(_in_p_nonce);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(sgx_report_t);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_qe_report != NULL && _len_qe_report != 0) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_qe_report, _len_qe_report, _tmp_qe_report, _len_qe_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);

err:
	if (_in_qe_report) free(_in_qe_report);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_enclave_init_ra, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_close, 0, 0},
		{(void*)(uintptr_t)sgx_verify_att_result_mac, 0, 0},
		{(void*)(uintptr_t)sgx_put_secret_data, 0, 0},
		{(void*)(uintptr_t)sgx_generate_server_key, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


