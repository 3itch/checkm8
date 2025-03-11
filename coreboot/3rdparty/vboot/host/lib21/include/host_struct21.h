/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Vboot 2.1 data structures
 *
 * Offsets should be padded to 32-bit boundaries, since some architectures
 * have trouble with accessing unaligned integers.
 */

#ifndef VBOOT_REFERENCE_VB21_STRUCT_H_
#define VBOOT_REFERENCE_VB21_STRUCT_H_

#include "2id.h"
#include "2sysincludes.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/*
 * Magic numbers used by vb21_struct_common.magic.
 *
 * All valid numbers should be listed here to avoid accidental overlap.
 * Numbers start at a large value, so that previous parsers (which stored
 * things like lengths and offsets at that field) will detect and reject new
 * structs as invalid.
 */
enum vb21_struct_common_magic {
	/* "Vb2I" = vb21_packed_private_key.c.magic */
	VB21_MAGIC_PACKED_PRIVATE_KEY	= 0x49326256,

	/* "Vb2P" = vb21_packed_key.c.magic */
	VB21_MAGIC_PACKED_KEY		= 0x50326256,

	/* "Vb2S" = vb21_signature.c.magic */
	VB21_MAGIC_SIGNATURE		= 0x53326256,
};


/*
 * Generic struct header for all vboot2.1 structs.  This makes it easy to
 * automatically parse and identify vboot structs (e.g., in futility).  This
 * must be the first member of the parent vboot2.1 struct.
 */
struct vb21_struct_common {
	/* Magic number; see vb21_struct_common_magic for expected values */
	uint32_t magic;

	/*
	 * Parent struct version; see each struct for the expected value.
	 *
	 * How to handle struct version mismatches, if the parser is version
	 * A.b and the data is version C.d:
	 *     1) If A.b == C.d, we're good.
	 *     2) If A != C, the data cannot be parsed at all.
	 *     3) If b < d, C.d is a newer version of data which is backwards-
	 *        compatible to old parsers.  We're good.
	 *     4) If b > d, C.d is an older version of data.  The parser should
	 *        use default values for fields added after version d.  We're
	 *        good.
	 *
	 * Struct versions start at 3.0, since the highest version of the old
	 * structures was 2.1.  This way, there is no possibility of collision
	 * for old code which depends on the version number.
	 */
	uint16_t struct_version_major;
	uint16_t struct_version_minor;

	/*
	 * Size of the parent structure and all its data, including the
	 * description and any necessary padding.  That is, all data must lie
	 * in a contiguous region of <total_size> bytes starting at the first
	 * byte of this header.
	 */
	uint32_t total_size;

	/*
	 * Size of the fixed portion of the parent structure.  If a description
	 * is present, it must start at this offset.
	 */
	uint32_t fixed_size;

	/*
	 * The object may contain an ASCII description following the fixed
	 * portion of the structure.  If it is present, it must be
	 * null-terminated, and padded with 0 (null) bytes to a multiple of 32
	 * bits.
	 *
	 * Size of ASCII description in bytes, counting null terminator and
	 * padding (if any).  Set 0 if no description is present.  If non-zero,
	 * there must be a null terminator (0) at offset (fixed_size +
	 * desc_size - 1).
	 */
	uint32_t desc_size;
} __attribute__((packed));

#define EXPECTED_VB21_STRUCT_COMMON_SIZE 20

/* Current version of vb21_packed_key struct */
#define VB21_PACKED_KEY_VERSION_MAJOR 3
#define VB21_PACKED_KEY_VERSION_MINOR 0

/*
 * Packed public key data
 *
 * The key data must be arranged like this:
 *     1) vb21_packed_key header struct h
 *     2) Key description (pointed to by h.c.fixed_size)
 *     3) Key data key (pointed to by h.key_offset)
 */
struct vb21_packed_key {
	/* Common header fields */
	struct vb21_struct_common c;

	/* Offset of key data from start of this struct */
	uint32_t key_offset;

	/* Size of key data in bytes (NOT strength of key in bits) */
	uint32_t key_size;

	/* Signature algorithm used by the key (enum vb2_signature_algorithm) */
	uint16_t sig_alg;

	/*
	 * Hash digest algorithm used with the key (enum vb2_hash_algorithm).
	 * This is explicitly specified as part of the key to prevent use of a
	 * strong key with a weak hash.
	 */
	uint16_t hash_alg;

	/* Key version */
	uint32_t key_version;

	/* Key ID */
	struct vb2_id id;
} __attribute__((packed));

#define EXPECTED_VB21_PACKED_KEY_SIZE					\
	(EXPECTED_VB21_STRUCT_COMMON_SIZE + 16 + EXPECTED_ID_SIZE)

/* Current version of vb21_packed_private_key struct */
#define VB21_PACKED_PRIVATE_KEY_VERSION_MAJOR 3
#define VB21_PACKED_PRIVATE_KEY_VERSION_MINOR 0

/*
 * Packed private key data
 *
 * The key data must be arranged like this:
 *     1) vb21_packed_private_key header struct h
 *     2) Key description (pointed to by h.c.fixed_size)
 *     3) Key data key (pointed to by h.key_offset)
 */
struct vb21_packed_private_key {
	/* Common header fields */
	struct vb21_struct_common c;

	/* Offset of key data from start of this struct */
	uint32_t key_offset;

	/* Size of key data in bytes (NOT strength of key in bits) */
	uint32_t key_size;

	/* Signature algorithm used by the key (enum vb2_signature_algorithm) */
	uint16_t sig_alg;

	/*
	 * Hash digest algorithm used with the key (enum vb2_hash_algorithm).
	 * This is explicitly specified as part of the key to prevent use of a
	 * strong key with a weak hash.
	 */
	uint16_t hash_alg;

	/* Key ID */
	struct vb2_id id;
} __attribute__((packed));

#define EXPECTED_VB21_PACKED_PRIVATE_KEY_SIZE				\
	(EXPECTED_VB21_STRUCT_COMMON_SIZE + 12 + EXPECTED_ID_SIZE)

/* Current version of vb21_signature struct */
#define VB21_SIGNATURE_VERSION_MAJOR 3
#define VB21_SIGNATURE_VERSION_MINOR 0

/*
 * Signature data
 *
 * The signature data must be arranged like this:
 *     1) vb21_signature header struct h
 *     2) Signature description (pointed to by h.c.fixed_size)
 *     3) Signature data (pointed to by h.sig_offset)
 */
struct vb21_signature {
	/* Common header fields */
	struct vb21_struct_common c;

	/* Offset of signature data from start of this struct */
	uint32_t sig_offset;

	/* Size of signature data in bytes */
	uint32_t sig_size;

	/* Size of the data block which was signed in bytes */
	uint32_t data_size;

	/* Signature algorithm used (enum vb2_signature_algorithm) */
	uint16_t sig_alg;

	/* Hash digest algorithm used (enum vb2_hash_algorithm) */
	uint16_t hash_alg;

	/*
	 * ID for the signature.
	 *
	 * If this is a keyblock signature entry, this is the ID of the key
	 * used to generate this signature.  This allows the firmware to
	 * quickly determine which signature block (if any) goes with the key
	 * being used by the firmware.
	 *
	 * If this is a preamble hash entry, this is the ID of the data type
	 * being hashed.  There is no key ID, because sig_alg=VB2_ALG_NONE.
	 */
	struct vb2_id id;
} __attribute__((packed));

#define EXPECTED_VB21_SIGNATURE_SIZE					\
	(EXPECTED_VB21_STRUCT_COMMON_SIZE + 16 + EXPECTED_ID_SIZE)

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* VBOOT_REFERENCE_VB21_STRUCT_H_ */
