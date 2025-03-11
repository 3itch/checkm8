/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <openssl/pem.h>

#include "2common.h"
#include "2id.h"
#include "2rsa.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "file_type.h"
#include "futility.h"
#include "futility_options.h"
#include "host_common.h"
#include "host_common21.h"
#include "host_key21.h"
#include "host_misc21.h"
#include "openssl_compat.h"
#include "util_misc.h"

enum futil_file_type ft_recognize_vb21_key(uint8_t *buf, uint32_t len)
{
	struct vb2_public_key pubkey;
	struct vb2_private_key *privkey = 0;

	/* The pubkey points into buf, so nothing to free */
	if (VB2_SUCCESS == vb21_unpack_key(&pubkey, buf, len))
		return FILE_TYPE_VB2_PUBKEY;

	/* The private key unpacks into new structs */
	if (VB2_SUCCESS == vb21_private_key_unpack(&privkey, buf, len)) {
		vb2_free_private_key(privkey);
		return FILE_TYPE_VB2_PRIVKEY;
	}

	return FILE_TYPE_UNKNOWN;
}

static int vb2_public_key_sha1sum(struct vb2_public_key *key,
				  struct vb2_hash *hash)
{
	struct vb21_packed_key *pkey;

	if (vb21_public_key_pack(&pkey, key))
		return 0;

	vb2_hash_calculate(false, (uint8_t *)pkey + pkey->key_offset,
			   pkey->key_size, VB2_HASH_SHA1, hash);

	free(pkey);
	return 1;
}

int show_vb21_pubkey_buf(const char *fname, uint8_t *buf, uint32_t len)
{
	struct vb2_public_key key;
	struct vb2_hash hash;

	/* The key's members will point into the state buffer after this. Don't
	 * free anything. */
	if (VB2_SUCCESS != vb21_unpack_key(&key, buf, len))
		return 1;

	printf("Public Key file:       %s\n", fname);
	printf("  Vboot API:           2.1\n");
	printf("  Desc:                \"%s\"\n", key.desc);
	printf("  Signature Algorithm: %d %s\n", key.sig_alg,
	       vb2_get_sig_algorithm_name(key.sig_alg));
	printf("  Hash Algorithm:      %d %s\n", key.hash_alg,
	       vb2_get_hash_algorithm_name(key.hash_alg));
	printf("  Version:             0x%08x\n", key.version);
	printf("  ID:                  ");
	print_bytes(key.id, sizeof(*key.id));
	printf("\n");
	if (vb2_public_key_sha1sum(&key, &hash) &&
	    memcmp(key.id, hash.sha1, sizeof(*key.id))) {
		printf("  Key sha1sum:         ");
		print_bytes(hash.sha1, sizeof(hash.sha1));
		printf("\n");
	}
	return 0;
}

int ft_show_vb21_pubkey(const char *fname)
{
	int fd = -1;
	uint8_t *buf;
	uint32_t len;
	int rv;

	if (show_option.parseable) {
		ERROR("Parseable output not supported for this file.\n");
		return 1;
	}

	if (futil_open_and_map_file(fname, &fd, FILE_RO, &buf, &len))
		return 1;

	rv = show_vb21_pubkey_buf(fname, buf, len);

	futil_unmap_and_close_file(fd, FILE_RO, buf, len);
	return rv;
}

static int vb2_private_key_sha1sum(struct vb2_private_key *key,
				   struct vb2_hash *hash)
{
	uint8_t *buf;
	uint32_t buflen;

	if (vb_keyb_from_rsa(key->rsa_private_key, &buf, &buflen))
		return 0;

	vb2_hash_calculate(false, buf, buflen, VB2_HASH_SHA1, hash);

	free(buf);
	return 1;
}

int ft_show_vb21_privkey(const char *fname)
{
	struct vb2_private_key *key = 0;
	struct vb2_hash hash;
	int fd = -1;
	uint8_t *buf;
	uint32_t len;
	int rv = 0;

	if (show_option.parseable) {
		ERROR("Parseable output not supported for this file.\n");
		return 1;
	}

	if (futil_open_and_map_file(fname, &fd, FILE_RO, &buf, &len))
		return 1;

	if (VB2_SUCCESS != vb21_private_key_unpack(&key, buf, len)) {
		rv = 1;
		goto done;
	}

	printf("Private key file:      %s\n", fname);
	printf("  Vboot API:           2.1\n");
	printf("  Desc:                \"%s\"\n", key->desc ? key->desc : "");
	printf("  Signature Algorithm: %d %s\n", key->sig_alg,
	       vb2_get_sig_algorithm_name(key->sig_alg));
	printf("  Hash Algorithm:      %d %s\n", key->hash_alg,
	       vb2_get_hash_algorithm_name(key->hash_alg));
	printf("  ID:                  ");
	print_bytes(&key->id, sizeof(key->id));
	printf("\n");
	if (vb2_private_key_sha1sum(key, &hash) &&
	    memcmp(&key->id, hash.sha1, sizeof(key->id))) {
		printf("  Key sha1sum:         ");
		print_bytes(hash.sha1, sizeof(hash.sha1));
		printf("\n");
	}
	vb2_free_private_key(key);
done:
	futil_unmap_and_close_file(fd, FILE_RO, buf, len);
	return rv;
}

static RSA *rsa_from_buffer(uint8_t *buf, uint32_t len)
{
	BIO *bp;
	RSA *rsa_key;

	bp = BIO_new_mem_buf(buf, len);
	if (!bp)
		return 0;

	rsa_key = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, NULL);
	if (!rsa_key) {
		if (BIO_reset(bp) < 0)
			return 0;
		rsa_key = PEM_read_bio_RSA_PUBKEY(bp, NULL, NULL, NULL);
	}
	if (!rsa_key) {
		BIO_free(bp);
		return 0;
	}

	BIO_free(bp);

	return rsa_key;
}

enum futil_file_type ft_recognize_pem(uint8_t *buf, uint32_t len)
{
	RSA *rsa_key = rsa_from_buffer(buf, len);

	if (rsa_key) {
		RSA_free(rsa_key);
		return FILE_TYPE_PEM;
	}

	return FILE_TYPE_UNKNOWN;
}

int ft_show_pem(const char *fname)
{
	RSA *rsa_key;
	uint8_t *keyb;
	uint32_t keyb_len;
	struct vb2_hash hash;
	int i, bits;
	const BIGNUM *rsa_key_n, *rsa_key_d;
	int fd = -1;
	uint8_t *buf;
	uint32_t len;
	int rv = 0;

	if (show_option.parseable) {
		ERROR("Parseable output not supported for this file.\n");
		return 1;
	}

	if (futil_open_and_map_file(fname, &fd, FILE_RO, &buf, &len))
		return 1;

	/* We're called only after ft_recognize_pem, so this should work. */
	rsa_key = rsa_from_buffer(buf, len);
	if (!rsa_key)
		FATAL("No RSA key found in buffer\n");

	/* Use to presence of the private exponent to decide if it's public */
	RSA_get0_key(rsa_key, &rsa_key_n, NULL, &rsa_key_d);
	printf("%s Key file:      %s\n", rsa_key_d ? "Private" : "Public", fname);

	bits = BN_num_bits(rsa_key_n);
	printf("  Key length:          %d\n", bits);

	if (vb_keyb_from_rsa(rsa_key, &keyb, &keyb_len)) {
		printf("  Key sha1sum:         <error>");
		RSA_free(rsa_key);
		rv = 1;
		goto done;
	}

	printf("  Key sha1sum:         ");
	vb2_hash_calculate(false, keyb, keyb_len, VB2_HASH_SHA1, &hash);
	for (i = 0; i < sizeof(hash.sha1); i++)
		printf("%02x", hash.sha1[i]);
	printf("\n");

	free(keyb);
	RSA_free(rsa_key);
done:
	futil_unmap_and_close_file(fd, FILE_RO, buf, len);
	return rv;
}
