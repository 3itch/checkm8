/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Host functions for keys.
 */

#include <openssl/pem.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "2common.h"
#include "2rsa.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "host_common.h"
#include "host_common21.h"
#include "host_key21.h"
#include "host_key.h"
#include "host_misc.h"
#include "host_p11.h"

enum vb2_crypto_algorithm vb2_get_crypto_algorithm(
	enum vb2_hash_algorithm hash_alg,
	enum vb2_signature_algorithm sig_alg)
{
	/* Make sure algorithms are in the range supported by crypto alg */
	if (sig_alg < VB2_SIG_RSA1024 || sig_alg >= VB2_SIG_ALG_COUNT)
		return VB2_ALG_COUNT;
	if (hash_alg < VB2_HASH_SHA1 || hash_alg > VB2_HASH_SHA512)
		return VB2_ALG_COUNT;

	return (sig_alg - VB2_SIG_RSA1024)
		* (VB2_HASH_SHA512 - VB2_HASH_SHA1 + 1)
		+ (hash_alg - VB2_HASH_SHA1);
};

static vb2_error_t vb2_read_local_private_key(uint8_t *buf, uint32_t bufsize,
					      struct vb2_private_key *key)
{
	uint64_t alg = *(uint64_t *)buf;
	key->key_location = PRIVATE_KEY_LOCAL;
	key->hash_alg = vb2_crypto_to_hash(alg);
	key->sig_alg = vb2_crypto_to_signature(alg);
	const unsigned char *start = buf + sizeof(alg);

	key->rsa_private_key = d2i_RSAPrivateKey(0, &start, bufsize - sizeof(alg));

	if (!key->rsa_private_key) {
		VB2_DEBUG("Unable to parse RSA private key\n");
		return VB2_ERROR_UNKNOWN;
	}
	return VB2_SUCCESS;
}

static vb2_error_t vb2_read_p11_private_key(const char *key_info, struct vb2_private_key *key)
{
	/* The format of p11 key info: "remote:{lib_path}:{slot_id}:{key_label}" */
	char *p11_lib = NULL, *p11_label = NULL;
	int p11_slot_id;
	vb2_error_t ret = VB2_ERROR_UNKNOWN;
	if (sscanf(key_info, "remote:%m[^:]:%i:%m[^:]", &p11_lib, &p11_slot_id, &p11_label) !=
	    3) {
		VB2_DEBUG("Failed to parse pkcs11 key info\n");
		goto done;
	}

	if (pkcs11_init(p11_lib) != VB2_SUCCESS) {
		VB2_DEBUG("Unable to initialize pkcs11 library\n");
		goto done;
	}

	struct pkcs11_key *p11_key = pkcs11_get_key(p11_slot_id, p11_label);
	if (!p11_key) {
		VB2_DEBUG("Unable to get pkcs11 key\n");
		goto done;
	}

	key->key_location = PRIVATE_KEY_P11;
	key->p11_key = p11_key;
	key->sig_alg = pkcs11_get_sig_alg(p11_key);
	key->hash_alg = pkcs11_get_hash_alg(p11_key);
	if (key->sig_alg == VB2_SIG_INVALID || key->hash_alg == VB2_HASH_INVALID) {
		VB2_DEBUG("Unable to get signature or hash algorithm\n");
		pkcs11_free_key(p11_key);
		goto done;
	}
	ret = VB2_SUCCESS;
done:
	free(p11_lib);
	free(p11_label);
	return ret;
}

static bool is_vb21_private_key(const uint8_t *buf, uint32_t bufsize)
{
	const struct vb21_packed_private_key *pkey =
		(const struct vb21_packed_private_key *)buf;
	return bufsize >= sizeof(pkey->c.magic) &&
	       pkey->c.magic == VB21_MAGIC_PACKED_PRIVATE_KEY;
}

struct vb2_private_key *vb2_read_private_key(const char *key_info)
{
	struct vb2_private_key *key = (struct vb2_private_key *)calloc(sizeof(*key), 1);
	if (!key) {
		VB2_DEBUG("Unable to allocate private key\n");
		return NULL;
	}

	static const char p11_prefix[] = "remote";
	static const char local_prefix[] = "local";
	char *colon = strchr(key_info, ':');
	if (colon) {
		int prefix_size = colon - key_info;
		if (!strncmp(key_info, p11_prefix, prefix_size)) {
			if (vb2_read_p11_private_key(key_info, key) != VB2_SUCCESS) {
				VB2_DEBUG("Unable to read pkcs11 private key\n");
				free(key);
				return NULL;
			}
			return key;
		}
		if (!strncmp(key_info, local_prefix, prefix_size))
			key_info = colon + 1;
	}

	// Read the private key from local file.
	uint8_t *buf = NULL;
	uint32_t bufsize = 0;
	if (vb2_read_file(key_info, &buf, &bufsize) != VB2_SUCCESS) {
		VB2_DEBUG("unable to read from file %s\n", key_info);
		return NULL;
	}

	vb2_error_t rv;
	bool is_vb21 = is_vb21_private_key(buf, bufsize);
	if (is_vb21)
		rv = vb21_private_key_unpack_raw(buf, bufsize, key);
	else
		rv = vb2_read_local_private_key(buf, bufsize, key);

	free(buf);
	if (rv != VB2_SUCCESS) {
		VB2_DEBUG("Unable to read local %s private key\n", is_vb21 ? "vb21" : "vb2");
		free(key);
		return NULL;
	}
	return key;
}

struct vb2_private_key *vb2_read_private_key_pem(
	const char* filename,
	enum vb2_crypto_algorithm algorithm)
{
	if (algorithm >= VB2_ALG_COUNT) {
		VB2_DEBUG("%s() called with invalid algorithm!\n",
			  __FUNCTION__);
		return NULL;
	}

	/* Read private key */
	FILE *f = fopen(filename, "r");
	if (!f) {
		VB2_DEBUG("%s(): Couldn't open key file: %s\n",
			  __FUNCTION__, filename);
		return NULL;
	}
	struct rsa_st *rsa_key = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
	fclose(f);
	if (!rsa_key) {
		VB2_DEBUG("%s(): Couldn't read private key from file: %s\n",
			 __FUNCTION__, filename);
		return NULL;
	}

	/* Store key and algorithm in our struct */
	struct vb2_private_key *key =
		(struct vb2_private_key *)calloc(sizeof(*key), 1);
	if (!key) {
		RSA_free(rsa_key);
		return NULL;
	}
	key->rsa_private_key = rsa_key;
	key->hash_alg = vb2_crypto_to_hash(algorithm);
	key->sig_alg = vb2_crypto_to_signature(algorithm);

	/* Return the key */
	return key;
}

void vb2_free_private_key(struct vb2_private_key *key)
{
	if (!key)
		return;

	if (key->key_location == PRIVATE_KEY_LOCAL && key->rsa_private_key)
		RSA_free(key->rsa_private_key);
	else if (key->key_location == PRIVATE_KEY_P11 && key->p11_key)
		pkcs11_free_key(key->p11_key);

	if (key->desc)
		free(key->desc);

	free(key);
}

vb2_error_t vb2_write_private_key(const char *filename,
				  const struct vb2_private_key *key)
{
	/* Convert back to legacy vb1 algorithm enum */
	uint64_t alg = vb2_get_crypto_algorithm(key->hash_alg, key->sig_alg);
	if (alg == VB2_ALG_COUNT) {
		fprintf(stderr, "Can't find crypto algorithm\n");
		return VB2_ERROR_VB1_CRYPTO_ALGORITHM;
	}

	uint8_t *outbuf = NULL;
	int buflen = i2d_RSAPrivateKey(key->rsa_private_key, &outbuf);
	if (buflen <= 0) {
		fprintf(stderr, "Unable to write private key buffer\n");
		return VB2_ERROR_PRIVATE_KEY_WRITE_RSA;
	}

	FILE *f = fopen(filename, "wb");
	if (!f) {
		fprintf(stderr, "Unable to open file %s\n", filename);
		free(outbuf);
		return VB2_ERROR_PRIVATE_KEY_WRITE_FILE;
	}

	if (1 != fwrite(&alg, sizeof(alg), 1, f) ||
	    1 != fwrite(outbuf, buflen, 1, f)) {
		fprintf(stderr, "Unable to write to file %s\n", filename);
		fclose(f);
		unlink(filename);  /* Delete any partial file */
		free(outbuf);
		return VB2_ERROR_PRIVATE_KEY_WRITE_FILE;
	}

	fclose(f);
	free(outbuf);
	return VB2_SUCCESS;
}

void vb2_init_packed_key(struct vb2_packed_key *key, uint8_t *key_data,
			 uint32_t key_size)
{
	memset(key, 0, sizeof(*key));
	key->key_offset = vb2_offset_of(key, key_data);
	key->key_size = key_size;
	key->algorithm = VB2_ALG_COUNT; /* Key not present yet */
}

struct vb2_packed_key *vb2_alloc_packed_key(uint32_t key_size,
					    uint32_t algorithm,
					    uint32_t version)
{
	struct vb2_packed_key *key =
		(struct vb2_packed_key *)calloc(sizeof(*key) + key_size, 1);
	if (!key)
		return NULL;

	key->algorithm = algorithm;
	key->key_version = version;
	key->key_size = key_size;
	key->key_offset = sizeof(*key);
	return key;
}

vb2_error_t vb2_copy_packed_key(struct vb2_packed_key *dest,
				const struct vb2_packed_key *src)
{
	if (dest->key_size < src->key_size)
		return VB2_ERROR_COPY_KEY_SIZE;

	dest->key_size = src->key_size;
	dest->algorithm = src->algorithm;
	dest->key_version = src->key_version;
	memcpy(vb2_packed_key_data_mutable(dest),
	       vb2_packed_key_data(src),
	       src->key_size);
	return VB2_SUCCESS;
}

struct vb2_packed_key *vb2_read_packed_key(const char *filename)
{
	struct vb2_packed_key *key = NULL;
	uint32_t file_size = 0;

	if (VB2_SUCCESS !=
	    vb2_read_file(filename, (uint8_t **)&key, &file_size)) {
		return NULL;
	}

	if (vb2_packed_key_looks_ok(key, file_size) == VB2_SUCCESS)
		return key;

	/* Error */
	free(key);
	return NULL;
}

struct vb2_packed_key *vb2_read_packed_keyb(const char *filename,
					    uint32_t algorithm,
					    uint32_t version)
{
	if (algorithm >= VB2_ALG_COUNT) {
		fprintf(stderr, "%s() - invalid algorithm\n", __func__);
		return NULL;
	}
	if (version > VB2_MAX_KEY_VERSION) {
		/* Currently, TPM only supports 16-bit version */
		fprintf(stderr, "%s() - invalid version %#x\n", __func__,
			version);
		return NULL;
	}

	uint8_t *key_data = NULL;
	uint32_t key_size = 0;
	if (VB2_SUCCESS != vb2_read_file(filename, &key_data, &key_size))
		return NULL;

	uint32_t expected_key_size =
			vb2_packed_key_size(vb2_crypto_to_signature(algorithm));
	if (!expected_key_size || expected_key_size != key_size) {
		fprintf(stderr, "%s() - wrong key size %u for algorithm %u\n",
			__func__, key_size, algorithm);
		free(key_data);
		return NULL;
	}

	struct vb2_packed_key *key =
		vb2_alloc_packed_key(key_size, algorithm, version);
	if (!key) {
		free(key_data);
		return NULL;
	}
	memcpy(vb2_packed_key_data_mutable(key), key_data, key_size);

	free(key_data);
	return key;
}

vb2_error_t vb2_write_packed_key(const char *filename,
				 const struct vb2_packed_key *key)
{
	/* Copy the key, so its data is contiguous with the header */
	struct vb2_packed_key *kcopy =
		vb2_alloc_packed_key(key->key_size, 0, 0);
	if (!kcopy)
		return VB2_ERROR_PACKED_KEY_ALLOC;
	if (VB2_SUCCESS != vb2_copy_packed_key(kcopy, key)) {
		free(kcopy);
		return VB2_ERROR_PACKED_KEY_COPY;
	}

	/* Write the copy, then free it */
	vb2_error_t rv = vb2_write_file(filename, kcopy,
				kcopy->key_offset + kcopy->key_size);
	free(kcopy);
	return rv;
}

vb2_error_t vb2_packed_key_looks_ok(const struct vb2_packed_key *key,
				    uint32_t size)
{
	struct vb2_public_key pubkey;
	vb2_error_t rv;

	rv = vb2_unpack_key_buffer(&pubkey, (const uint8_t *)key, size);
	if (rv)
		return rv;

	if (key->key_version > VB2_MAX_KEY_VERSION) {
		/* Currently, TPM only supports 16-bit version */
		VB2_DEBUG("packed key invalid version\n");
		return VB2_ERROR_PACKED_KEY_VERSION;
	}

	return VB2_SUCCESS;
}

vb2_error_t vb2_unpack_key_data(struct vb2_public_key *key,
				const uint8_t *key_data, uint32_t key_size)
{
	const uint32_t *buf32 = (const uint32_t *)key_data;
	uint32_t expected_key_size = vb2_packed_key_size(key->sig_alg);

	/* Make sure buffer is the correct length */
	if (!expected_key_size || expected_key_size != key_size) {
		VB2_DEBUG("Wrong key size for algorithm\n");
		return VB2_ERROR_UNPACK_KEY_SIZE;
	}

	/* Check for alignment */
	if (!vb2_aligned(buf32, sizeof(uint32_t)))
		return VB2_ERROR_UNPACK_KEY_ALIGN;

	key->arrsize = buf32[0];

	/* Validity check key array size */
	if (key->arrsize * sizeof(uint32_t) != vb2_rsa_sig_size(key->sig_alg))
		return VB2_ERROR_UNPACK_KEY_ARRAY_SIZE;

	key->n0inv = buf32[1];

	/* Arrays point inside the key data */
	key->n = buf32 + 2;
	key->rr = buf32 + 2 + key->arrsize;

	return VB2_SUCCESS;
}
