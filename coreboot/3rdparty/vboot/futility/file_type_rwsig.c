/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Some instances of the Chrome OS embedded controller firmware can't do a
 * normal software sync handshake at boot, but will verify their own RW images
 * instead. This is typically done by putting a struct vb2_packed_key in the RO
 * image and a corresponding struct vb21_signature in the RW image.
 *
 * This file provides the basic implementation for that approach.
 */

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "2common.h"
#include "2rsa.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "file_type.h"
#include "fmap.h"
#include "futility.h"
#include "futility_options.h"
#include "host_common.h"
#include "host_common21.h"
#include "host_key21.h"
#include "host_misc.h"
#include "host_signature21.h"
#include "util_misc.h"

#define SIGNATURE_RSVD_SIZE 1024

static void show_sig(const char *fname, const struct vb21_signature *sig)
{
	printf("Signature:             %s\n", fname);
	printf("  Vboot API:           2.1\n");
	printf("  Desc:                \"%s\"\n", vb21_common_desc(sig));
	printf("  Signature Algorithm: %d %s\n", sig->sig_alg,
	       vb2_get_sig_algorithm_name(sig->sig_alg));
	printf("  Hash Algorithm:      %d %s\n", sig->hash_alg,
	       vb2_get_hash_algorithm_name(sig->hash_alg));
	printf("  Total size:          %#x (%d)\n", sig->c.total_size,
	       sig->c.total_size);
	printf("  ID:                  ");
	print_bytes(&sig->id, sizeof(sig->id));
	printf("\n");
	printf("  Data size:           %#x (%d)\n", sig->data_size,
	       sig->data_size);
}

int ft_show_rwsig(const char *fname)
{
	const struct vb21_packed_key *pkey = show_option.pkey;
	struct vb2_public_key key;
	uint8_t workbuf[VB2_VERIFY_DATA_WORKBUF_BYTES]
		__attribute__((aligned(VB2_WORKBUF_ALIGN)));
	uint32_t data_size, sig_size = SIGNATURE_RSVD_SIZE;
	uint32_t total_data_size = 0;
	uint8_t *data;
	FmapHeader *fmap;
	int i;
	int fd = -1;
	uint8_t *buf;
	uint32_t len;
	int rv = 1;

	if (futil_open_and_map_file(fname, &fd, FILE_RO, &buf, &len))
		return 1;

	VB2_DEBUG("name %s len 0x%08x (%d)\n", fname, len, len);

	/* Am I just looking at a signature file? */
	VB2_DEBUG("Looking for signature at 0x0\n");
	const struct vb21_signature *sig = (const struct vb21_signature *)buf;
	if (VB2_SUCCESS == vb21_verify_signature(sig, len)) {
		show_sig(fname, sig);
		if (!show_option.fv) {
			printf("No data available to verify\n");
			rv = show_option.strict;
			goto done;
		}
		data = show_option.fv;
		data_size = show_option.fv_size;
		total_data_size = show_option.fv_size;
	} else if ((fmap = fmap_find(buf, len))) {
		/* This looks like a full image. */
		FmapAreaHeader *fmaparea;

		VB2_DEBUG("Found an FMAP!\n");

		/* If no public key is provided, use the one packed in RO
		 * image, and print that. */
		if (!pkey) {
			pkey = (const struct vb21_packed_key *)
				fmap_find_by_name(buf, len, fmap, "KEY_RO", 0);

			if (pkey)
				show_vb21_pubkey_buf(fname, (uint8_t *)pkey,
						     pkey->c.total_size);
		}

		sig = (const struct vb21_signature *)
			fmap_find_by_name(buf, len, fmap, "SIG_RW", &fmaparea);
		if (!sig) {
			VB2_DEBUG("No SIG_RW in FMAP.\n");
			goto done;
		}

		sig_size = fmaparea->area_size;

		VB2_DEBUG("Looking for signature at %#tx (%#x)\n",
			  (uint8_t *)sig - buf, sig_size);

		if (VB2_SUCCESS != vb21_verify_signature(sig, sig_size))
			goto done;

		show_sig(fname, sig);
		data = fmap_find_by_name(buf, len, fmap, "EC_RW", &fmaparea);
		data_size = sig->data_size;
		/*
		 * TODO(crosbug.com/p/62231): EC_RW region should not include
		 * the signature.
		 */
		total_data_size = fmaparea->area_size - sig_size;

		if (!data) {
			VB2_DEBUG("No EC_RW in FMAP.\n");
			goto done;
		}
	} else {
		/* Or maybe this is just the RW portion, that does not
		 * contain a FMAP. */
		if (show_option.sig_size)
			sig_size = show_option.sig_size;

		VB2_DEBUG("Looking for signature at %#x\n", len - sig_size);

		if (len < sig_size) {
			VB2_DEBUG("File is too small\n");
			goto done;
		}

		sig = (const struct vb21_signature *)(buf + len - sig_size);
		if (VB2_SUCCESS == vb21_verify_signature(sig, sig_size)) {
			show_sig(fname, sig);
			data = buf;
			data_size = sig->data_size;
			total_data_size = len - sig_size;
		} else {
			goto done;
		}
	}

	if (!pkey) {
		printf("No public key available to verify with\n");
		rv = show_option.strict;
		goto done;
	}

	/* We already did this once, so it should work again */
	if (vb21_unpack_key(&key, (const uint8_t *)pkey, pkey->c.total_size)) {
		VB2_DEBUG("Can't unpack pubkey\n");
		goto done;
	}

	if (data_size > total_data_size) {
		VB2_DEBUG("Invalid signature data_size: bigger than total area size.\n");
		goto done;
	}

	/* The sig is destroyed by the verify operation, so make a copy */
	{
		uint8_t sigbuf[sig->c.total_size];
		memcpy(sigbuf, sig, sizeof(sigbuf));
		struct vb2_workbuf wb;

		vb2_workbuf_init(&wb, workbuf, sizeof(workbuf));

		if (vb21_verify_data(data, data_size,
				     (struct vb21_signature *)sigbuf,
				     (const struct vb2_public_key *)&key,
				     &wb)) {
			ERROR("Signature verification failed\n");
			goto done;
		}
	}

	/* Check that the rest of region is padded with 0xff. */
	for (i = data_size; i < total_data_size; i++) {
		if (data[i] != 0xff) {
			ERROR("Padding verification failed\n");
			goto done;
		}
	}

	printf("Signature verification succeeded.\n");
	rv = 0;
done:
	futil_unmap_and_close_file(fd, FILE_RO, buf, len);
	return rv;
}

int ft_sign_rwsig(const char *fname)
{
	struct vb21_signature *tmp_sig = 0;
	struct vb2_public_key *pubkey = 0;
	struct vb21_packed_key *packedkey = 0;
	uint8_t *keyb_data = 0;
	uint32_t keyb_size;
	uint8_t *data; /* data to be signed */
	uint32_t r, data_size, sig_size = SIGNATURE_RSVD_SIZE;
	int retval = 1;
	FmapHeader *fmap = NULL;
	FmapAreaHeader *fmaparea;
	struct vb21_signature *old_sig = 0;
	uint8_t *buf = NULL;
	uint32_t len;
	int fd = -1;

	if (futil_open_and_map_file(fname, &fd, FILE_MODE_SIGN(sign_option),
				    &buf, &len))
		return 1;

	data = buf;
	data_size = len;

	VB2_DEBUG("name %s len  0x%08x (%d)\n", fname, len, len);

	/* If we don't have a distinct OUTFILE, look for an existing sig */
	if (sign_option.inout_file_count < 2) {
		fmap = fmap_find(data, len);

		if (fmap) {
			/* This looks like a full image. */
			VB2_DEBUG("Found an FMAP!\n");

			old_sig = (struct vb21_signature *)
				fmap_find_by_name(buf, len, fmap, "SIG_RW",
						  &fmaparea);
			if (!old_sig) {
				VB2_DEBUG("No SIG_RW in FMAP.\n");
				goto done;
			}

			sig_size = fmaparea->area_size;

			VB2_DEBUG("Looking for signature at %#tx (%#x)\n",
				  (uint8_t *)old_sig - buf, sig_size);

			data = fmap_find_by_name(buf, len, fmap, "EC_RW",
						 &fmaparea);
			if (!data) {
				VB2_DEBUG("No EC_RW in FMAP.\n");
				goto done;
			}
		} else {
			/* Or maybe this is just the RW portion, that does not
			 * contain a FMAP. */
			if (sign_option.sig_size)
				sig_size = sign_option.sig_size;

			VB2_DEBUG("Looking for old signature at %#x\n",
				  len - sig_size);

			if (len < sig_size) {
				ERROR("File is too small\n");
				goto done;
			}

			/* Take a look */
			old_sig = (struct vb21_signature *)
				(buf + len - sig_size);
		}

		if (vb21_verify_signature(old_sig, sig_size)) {
			ERROR("Can't find a valid signature\n");
			goto done;
		}

		/* Use the same extent again */
		data_size = old_sig->data_size;

		VB2_DEBUG("Found sig: data_size is %#x (%d)\n", data_size,
			  data_size);
	}

	/* Unless overridden */
	if (sign_option.data_size)
		data_size = sign_option.data_size;

	/* Sign the blob */
	if (sign_option.prikey) {
		r = vb21_sign_data(&tmp_sig,
				   data, data_size, sign_option.prikey, 0);
		if (r) {
			ERROR("Unable to sign data (error 0x%08x)\n", r);
			goto done;
		}
	} else {
		VB2_DEBUG("Private key not provided. Copying previous signature\n");
		if (!old_sig) {
			/* This isn't necessary because no prikey mode runs only
			 * for fmap input or RW input */
			ERROR("Previous signature not found.\n");
			goto done;
		}
		tmp_sig = calloc(1, old_sig->c.total_size);
		if (!tmp_sig)
			goto done;
		memcpy(tmp_sig, old_sig, old_sig->c.total_size);
	}

	if (sign_option.inout_file_count < 2) {
		/* Overwrite the old signature */
		if (tmp_sig->c.total_size > sig_size) {
			ERROR("New sig is too large (%d > %d)\n",
			      tmp_sig->c.total_size, sig_size);
			goto done;
		}
		VB2_DEBUG("Replacing old signature with new one\n");
		memset(old_sig, 0xff, sig_size);
		memcpy(old_sig, tmp_sig, tmp_sig->c.total_size);
		if (fmap && sign_option.ecrw_out) {
			VB2_DEBUG("Writing %s (size=%d)\n",
				  sign_option.ecrw_out, fmaparea->area_size);
			if (vb2_write_file(sign_option.ecrw_out, data,
					   fmaparea->area_size))
				goto done;
		}
	} else {
		/* Write the signature to a new file */
		r = vb21_write_object(sign_option.outfile, tmp_sig);
		if (r) {
			ERROR("Unable to write sig (error 0x%08x)\n", r);
			goto done;
		}
	}

	/* For full images, let's replace the public key in RO. If prikey is
	 * not provided, skip it. */
	if (fmap && sign_option.prikey) {
		uint8_t *new_pubkey;
		uint8_t *pubkey_buf = 0;

		/* Create the public key */
		if (vb2_public_key_alloc(&pubkey,
					 sign_option.prikey->sig_alg)) {
			ERROR("Unable to allocate the public key\n");
			goto done;
		}

		/* Extract the keyb blob */
		if (vb_keyb_from_private_key(sign_option.prikey, &keyb_data, &keyb_size)) {
			ERROR("Couldn't extract the public key\n");
			goto done;
		}

		/*
		 * Copy the keyb blob to the public key's buffer, because that's
		 * where vb2_unpack_key_data() and vb2_public_key_pack() expect
		 * to find it.
		 */
		pubkey_buf = vb2_public_key_packed_data(pubkey);
		memcpy(pubkey_buf, keyb_data, keyb_size);

		/* Fill in the internal struct pointers */
		if (vb2_unpack_key_data(pubkey, pubkey_buf, keyb_size)) {
			ERROR("Unable to unpack the public key blob\n");
			goto done;
		}

		pubkey->hash_alg = sign_option.prikey->hash_alg;
		pubkey->version = sign_option.version_specified ?
			sign_option.version : 1;
		vb2_public_key_set_desc(pubkey, sign_option.prikey->desc);

		memcpy((struct vb2_id *)pubkey->id, &sign_option.prikey->id,
		       sizeof(*(pubkey->id)));

		if (vb21_public_key_pack(&packedkey, pubkey)) {
			goto done;
		}

		new_pubkey = fmap_find_by_name(buf, len, fmap, "KEY_RO",
					&fmaparea);
		if (!new_pubkey) {
			VB2_DEBUG("No KEY_RO in FMAP.\n");
			goto done;
		}
		/* Overwrite the old signature */
		if (packedkey->c.total_size > fmaparea->area_size) {
			ERROR("New sig is too large (%d > %d)\n",
			      packedkey->c.total_size, sig_size);
			goto done;
		}

		memset(new_pubkey, 0xff, fmaparea->area_size);
		memcpy(new_pubkey, packedkey, packedkey->c.total_size);
	}

	/* Finally */
	retval = 0;
done:
	futil_unmap_and_close_file(fd, FILE_MODE_SIGN(sign_option), buf, len);
	free(tmp_sig);
	if (pubkey)
		vb2_public_key_free(pubkey);
	free(packedkey);
	free(keyb_data);

	return retval;
}

enum futil_file_type ft_recognize_rwsig(uint8_t *buf, uint32_t len)
{
	const struct vb21_signature *sig = NULL;
	uint32_t sig_size;

	if (!vb21_verify_signature((const struct vb21_signature *)buf, len))
		return FILE_TYPE_RWSIG;

	FmapHeader *fmap = fmap_find(buf, len);
	if (fmap) {
		/* This looks like a full image. */
		FmapAreaHeader *fmaparea;

		sig = (const struct vb21_signature *)
			fmap_find_by_name(buf, len, fmap, "SIG_RW", &fmaparea);

		if (!sig)
			return FILE_TYPE_UNKNOWN;

		sig_size = fmaparea->area_size;
	} else {
		/* RW-only image */
		sig = (const struct vb21_signature *)
			(buf + len - SIGNATURE_RSVD_SIZE);
		sig_size = SIGNATURE_RSVD_SIZE;
	}

	if (len >= sig_size && !vb21_verify_signature(sig, sig_size))
		return FILE_TYPE_RWSIG;

	return FILE_TYPE_UNKNOWN;
}
