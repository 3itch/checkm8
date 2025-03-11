/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>

#include <pkcs11.h>

#include "2common.h"
#include "host_p11.h"
#include "vboot_host.h"
#include "util_misc.h"

struct pkcs11_key {
	CK_OBJECT_HANDLE handle;
	CK_SESSION_HANDLE session;
};

// We only maintain one global p11 module at a time.
static CK_FUNCTION_LIST_PTR p11 = NULL;

static void *pkcs11_load(const char *mspec, CK_FUNCTION_LIST_PTR_PTR funcs)
{
	void *mod;
	CK_RV rv;
	CK_RV (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR p11);

	if (mspec == NULL)
		return NULL;

	mod = dlopen(mspec, RTLD_LAZY);
	if (mod == NULL) {
		fprintf(stderr, "dlopen failed: %s\n", dlerror());
		return NULL;
	}

	/* Get the list of function pointers */
	c_get_function_list =
		(CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(mod, "C_GetFunctionList");
	if (!c_get_function_list)
		goto err;
	rv = c_get_function_list(funcs);
	if (rv == CKR_OK)
		return mod;
	fprintf(stderr, "C_GetFunctionList failed 0x%lx", rv);
err:
	dlclose(mod);
	return NULL;
}

static vb2_error_t pkcs11_find(CK_SESSION_HANDLE session, CK_ATTRIBUTE attributes[],
			       CK_ULONG num_attributes, CK_OBJECT_HANDLE *object)
{
	CK_RV result = p11->C_FindObjectsInit(session, attributes, num_attributes);
	if (result != CKR_OK)
		return VB2_ERROR_UNKNOWN;

	CK_ULONG object_count = 1;
	result = p11->C_FindObjects(session, object, 1, &object_count);
	if (result != CKR_OK || object_count == 0)
		return VB2_ERROR_UNKNOWN;

	result = p11->C_FindObjectsFinal(session);
	if (result != CKR_OK)
		return VB2_ERROR_UNKNOWN;

	return VB2_SUCCESS;
}

static enum vb2_hash_algorithm
pkcs11_mechanism_type_to_hash_alg(CK_MECHANISM_TYPE p11_mechanism)
{
	switch (p11_mechanism) {
	case CKM_SHA1_RSA_PKCS:
		return VB2_HASH_SHA1;
	case CKM_SHA256_RSA_PKCS:
		return VB2_HASH_SHA256;
	case CKM_SHA512_RSA_PKCS:
		return VB2_HASH_SHA512;
	}
	return VB2_HASH_INVALID;
}

vb2_error_t pkcs11_init(const char *pkcs11_lib)
{
	static char *loaded_pkcs11_lib = NULL;
	static void *pkcs11_mod = NULL;
	if (pkcs11_lib == NULL) {
		fprintf(stderr, "Missing the path of pkcs11 library\n");
		return VB2_ERROR_UNKNOWN;
	}
	if (loaded_pkcs11_lib) {
		/* Return success if the same pkcs11 library is already loaded */
		if (strcmp(loaded_pkcs11_lib, pkcs11_lib) == 0)
			return VB2_SUCCESS;
		fprintf(stderr, "Pkcs11 module is already loaded\n");
		return VB2_ERROR_UNKNOWN;
	}

	pkcs11_mod = pkcs11_load(pkcs11_lib, &p11);
	if (pkcs11_mod == NULL) {
		fprintf(stderr, "Failed to load pkcs11 library '%s'\n", pkcs11_lib);
		return VB2_ERROR_UNKNOWN;
	}

	CK_RV result = p11->C_Initialize(NULL);
	if (result != CKR_OK) {
		fprintf(stderr, "Failed to C_Initialize\n");
		dlclose(pkcs11_mod);
		pkcs11_mod = NULL;
		return VB2_ERROR_UNKNOWN;
	}
	loaded_pkcs11_lib = strdup(pkcs11_lib);
	return VB2_SUCCESS;
}

struct pkcs11_key *pkcs11_get_key(int slot_id, char *label)
{
	if (!p11) {
		fprintf(stderr, "pkcs11 is not loaded\n");
		return NULL;
	}

	struct pkcs11_key *p11_key = malloc(sizeof(struct pkcs11_key));
	if (!p11_key) {
		fprintf(stderr, "Failed to allocate pkcs11 key\n");
		return NULL;
	}

	CK_RV result = p11->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
					  NULL, &p11_key->session);

	if (result != CKR_OK) {
		fprintf(stderr, "Failed to open session with slot id %d\n", slot_id);
		free(p11_key);
		return NULL;
	}

	/* Find the private key */
	CK_OBJECT_CLASS class_value = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE attributes[] = {
		{CKA_CLASS, &class_value, sizeof(class_value)},
		{CKA_LABEL, label, strlen(label)},
	};
	if (pkcs11_find(p11_key->session, attributes, ARRAY_SIZE(attributes),
			&p11_key->handle) != VB2_SUCCESS) {
		fprintf(stderr, "Failed to find the key with label '%s'\n", label);
		pkcs11_free_key(p11_key);
		return NULL;
	}

	return p11_key;
}

enum vb2_hash_algorithm pkcs11_get_hash_alg(struct pkcs11_key *p11_key)
{
	/* For PKCS#11 modules that support CKA_ALLOWED_MECHANISMS, we'll use the attribute
	 * to determine the correct mechanism to use. However, not all PKCS#11 modules
	 * support CKA_ALLOWED_MECHANISMS. In the event that we need to support such a
	 * module, we'll then need to determine the the mechanism to use from the key type
	 * and key size. That probably involves assuming we'll use PKCS#1 v1.5 padding for
	 * RSA. */
	CK_ATTRIBUTE mechanism_attr = {CKA_ALLOWED_MECHANISMS, NULL, 0};
	if (p11->C_GetAttributeValue(p11_key->session, p11_key->handle, &mechanism_attr, 1) !=
	    CKR_OK) {
		fprintf(stderr, "Failed to get mechanisum attribute length\n");
		return VB2_HASH_INVALID;
	}
	mechanism_attr.pValue = malloc(mechanism_attr.ulValueLen);
	if (p11->C_GetAttributeValue(p11_key->session, p11_key->handle, &mechanism_attr, 1) !=
	    CKR_OK) {
		fprintf(stderr, "Failed to get mechanisum attribute value\n");
		free(mechanism_attr.pValue);
		return VB2_HASH_INVALID;
	}
	CK_MECHANISM_TYPE *mechanisms = mechanism_attr.pValue;
	uint32_t mechanism_count = mechanism_attr.ulValueLen / sizeof(CK_MECHANISM_TYPE);
	enum vb2_hash_algorithm hash_alg = VB2_HASH_INVALID;
	for (int i = 0; i < mechanism_count; ++i) {
		hash_alg = pkcs11_mechanism_type_to_hash_alg(mechanisms[i]);
		if (hash_alg != VB2_HASH_INVALID)
			break;
	}
	free(mechanism_attr.pValue);
	return hash_alg;
}

enum vb2_signature_algorithm pkcs11_get_sig_alg(struct pkcs11_key *p11_key)
{
	if (!p11) {
		fprintf(stderr, "pkcs11 is not loaded\n");
		return VB2_SIG_INVALID;
	}
	CK_ULONG modulus_bits = 0;
	CK_ATTRIBUTE modulus_attr = {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)};
	if (p11->C_GetAttributeValue(p11_key->session, p11_key->handle, &modulus_attr, 1) !=
	    CKR_OK) {
		fprintf(stderr, "Failed to get modulus bits\n");
		return VB2_SIG_INVALID;
	}

	CK_ATTRIBUTE exponent_attr = {CKA_PUBLIC_EXPONENT, NULL, 0};
	if (p11->C_GetAttributeValue(p11_key->session, p11_key->handle, &exponent_attr, 1) !=
	    CKR_OK) {
		fprintf(stderr, "Failed to get exponent attribute length\n");
		return VB2_SIG_INVALID;
	}
	CK_ULONG exp_size = exponent_attr.ulValueLen;
	if (exp_size > 4) {
		fprintf(stderr, "Exponent size is too large\n");
		return VB2_SIG_INVALID;
	}
	exponent_attr.pValue = malloc(exp_size);
	if (p11->C_GetAttributeValue(p11_key->session, p11_key->handle, &exponent_attr, 1) !=
	    CKR_OK) {
		fprintf(stderr, "Failed to get exponent attribute value\n");
		free(exponent_attr.pValue);
		return VB2_SIG_INVALID;
	}
	// Parse the CKA_PUBLIC_EXPONENT in Big-endian.
	CK_BYTE *exp_value = exponent_attr.pValue;
	uint32_t exp = 0;
	for (int i = 0; i < exp_size; ++i)
		exp = (exp << 8) + exp_value[i];
	free(exponent_attr.pValue);

	return vb2_get_sig_alg(exp, modulus_bits);
}

uint8_t *pkcs11_get_modulus(struct pkcs11_key *p11_key, uint32_t *sizeptr)
{
	if (!p11) {
		fprintf(stderr, "pkcs11 is not loaded\n");
		return NULL;
	}
	CK_ATTRIBUTE modulus_attr = {CKA_MODULUS, NULL, 0};
	if (p11->C_GetAttributeValue(p11_key->session, p11_key->handle, &modulus_attr, 1) !=
	    CKR_OK) {
		fprintf(stderr, "Failed to get modulus attribute length\n");
		return NULL;
	}
	CK_ULONG modulus_size = modulus_attr.ulValueLen;
	modulus_attr.pValue = malloc(modulus_size);
	if (p11->C_GetAttributeValue(p11_key->session, p11_key->handle, &modulus_attr, 1) !=
	    CKR_OK) {
		fprintf(stderr, "Failed to get modulus attribute value\n");
		free(modulus_attr.pValue);
		return NULL;
	}
	*sizeptr = modulus_size;
	return modulus_attr.pValue;
}

vb2_error_t pkcs11_sign(struct pkcs11_key *p11_key, enum vb2_hash_algorithm hash_alg,
			const uint8_t *data, int data_size, uint8_t *sig, uint32_t sig_size)
{
	if (!p11) {
		fprintf(stderr, "pkcs11 is not loaded\n");
		return VB2_ERROR_UNKNOWN;
	}

	CK_MECHANISM mechanism;
	switch (hash_alg) {
	case VB2_HASH_SHA1:
		mechanism.mechanism = CKM_SHA1_RSA_PKCS;
		break;
	case VB2_HASH_SHA256:
		mechanism.mechanism = CKM_SHA256_RSA_PKCS;
		break;
	case VB2_HASH_SHA512:
		mechanism.mechanism = CKM_SHA512_RSA_PKCS;
		break;
	default:
		fprintf(stderr, "Unsupported hash algorithm %d\n", hash_alg);
		return VB2_ERROR_UNKNOWN;
	}
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;

	CK_RV result = p11->C_SignInit(p11_key->session, &mechanism, p11_key->handle);
	if (result != CKR_OK) {
		fprintf(stderr, "Failed to sign init\n");
		return VB2_ERROR_UNKNOWN;
	}
	CK_ULONG ck_sig_size = sig_size;
	result = p11->C_Sign(p11_key->session, (unsigned char *)data, data_size, sig,
			     &ck_sig_size);
	if (result != CKR_OK) {
		fprintf(stderr, "Failed to sign\n");
		return VB2_ERROR_UNKNOWN;
	}
	return VB2_SUCCESS;
}

void pkcs11_free_key(struct pkcs11_key *p11_key)
{
	if (!p11) {
		fprintf(stderr, "pkcs11 is not loaded\n");
		return;
	}
	CK_RV result = p11->C_CloseSession(p11_key->session);
	if (result != CKR_OK)
		fprintf(stderr, "Failed to close session\n");
	free(p11_key);
}
