#!/bin/bash -eux
# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

me="${0##*/}"
TMP="${me}.tmp"

# Work in scratch directory
cd "$OUTDIR"

KEYDIR="${SRCDIR}/tests/devkeys"
DATADIR="${SCRIPT_DIR}/futility/data"

# The input BIOS images are all signed with MP keys. We resign them with dev
# keys, which means we can precalculate the expected results. Note that the
# script does not change the root or recovery keys in the GBB.
INFILES="
${DATADIR}/bios_link_mp.bin
${DATADIR}/bios_peppy_mp.bin
"

# BIOS image containing CBFS RW/A and RW/B, and signed with developer keys.
GOOD_CBFS="${DATADIR}/bios_voxel_dev.bin"

# BIOS image containing CBFS RW/A and RW/B, and signed with developer keys.
INFILES="${INFILES}
${GOOD_CBFS}
"

# We also want to test that we can sign an image without any valid firmware
# preambles. That one won't be able to tell how much of the FW_MAIN region is
# the valid firmware, so it'll have to sign the entire region.
GOOD_VBLOCKS="${DATADIR}/bios_peppy_mp.bin"
ONEMORE=bios_peppy_mp_no_vblock.bin
CLEAN_B=bios_peppy_mp_clean_b_slot.bin
cp "${GOOD_VBLOCKS}" "${ONEMORE}"
cp "${GOOD_VBLOCKS}" "${CLEAN_B}"

GOOD_DEV="${DATADIR}/bios_peppy_dev.bin"

NO_B_SLOT_PATCH="${DATADIR}/bios_voxel_dev.no_b_slot.xxd.patch"

BAD_KEYBLOCK_PATCHES=(
"${DATADIR}/bios_peppy_dev.bad_keyblock_data_key_offset_too_big.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_keyblock_data_key_size_big.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_keyblock_hash_data_size_too_small.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_keyblock_hash_invalid_contents.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_keyblock_hash_offset_too_big.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_keyblock_hash_size_too_big.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_keyblock_invalid_magic.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_keyblock_invalid_major_version.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_keyblock_size_not_fully_signed.xxd.patch"
)

BAD_PREAMBLE_PATCHES=(
"${DATADIR}/bios_peppy_dev.bad_preamble_body_signature_offset_too_big.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_preamble_body_signature_size_too_big.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_preamble_header_version_major.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_preamble_header_version_minor.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_preamble_kernel_subkey_offset_too_big.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_preamble_kernel_subkey_size_too_big.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_preamble_signature_data_size_too_big.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_preamble_signature_data_size_too_small.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_preamble_signature_invalid_contents.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_preamble_signature_offset_too_big.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_preamble_signature_size_too_big.xxd.patch"
)

BAD_FMAP_KEYBLOCK_PATCHES=(
"${DATADIR}/bios_peppy_dev.bad_keyblock_fmap_too_small_for_whole.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_keyblock_fmap_too_small.xxd.patch"
)

BAD_FMAP_PREAMBLE_PATCHES=(
"${DATADIR}/bios_peppy_dev.bad_preamble_fmap_too_small_for_whole.xxd.patch"
"${DATADIR}/bios_peppy_dev.bad_preamble_fmap_too_small.xxd.patch"
)

"${FUTILITY}" load_fmap "${ONEMORE}" VBLOCK_A:/dev/urandom VBLOCK_B:/dev/zero
INFILES="${INFILES} ${ONEMORE}"

# args: xxd_patch_file input_file
function apply_xxd_patch {
  xxd -r "${1}" "${2}"
}

# args: file1 file2
function cmp_first_line {
  cmp <(head -n1 "${1}") <(head -n1 "${2}")
}

function cmp_last_line {
  cmp <(tail -n1 "${1}") <(tail -n1 "${2}")
}

set -o pipefail

count=0
for infile in $INFILES; do

  base=${infile##*/}

  : $(( count++ ))
  echo -n "${count} " 1>&3

  outfile="${TMP}.${base}.new"
  loemid="loem"
  loemdir="${TMP}.${base}_dir"

  mkdir -p "${loemdir}"

  "${FUTILITY}" sign \
    -K "${KEYDIR}" \
    -v 14 \
    -f 8 \
    -d "${loemdir}" \
    -l "${loemid}" \
    "${infile}" "${outfile}"

  # check the firmware version and preamble flags
  m=$("${FUTILITY}" verify --publickey "${KEYDIR}/root_key.vbpubk" \
        "${outfile}" | grep -c -E 'Firmware version: +14$|Preamble flags: +8$')
  [ "${m}" = "4" ]

  # check the sha1sums
  "${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" "${outfile}" \
    | grep ::sha1_sum:: | sort | cut -d: -f5- > "${TMP}.${base}.sha.new"
  cmp "${SCRIPT_DIR}/futility/data_${base}_expect.txt" "${TMP}.${base}.sha.new"

  # and the LOEM stuff
  "${FUTILITY}" dump_fmap -x "${outfile}" \
    "FW_MAIN_A:${loemdir}/fw_main_A" "FW_MAIN_B:${loemdir}/fw_main_B"

  "${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" \
    --fv "${loemdir}/fw_main_A" "${loemdir}/vblock_A.${loemid}" \
    | grep ::sha1_sum:: | sort | cut -d: -f3- > "${loemdir}/loem.sha.new"
  "${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" \
    --fv "${loemdir}/fw_main_B" "${loemdir}/vblock_B.${loemid}" \
    | grep ::sha1_sum:: | sort | cut -d: -f3- >> "${loemdir}/loem.sha.new"

  # the vblocks don't have root or recovery keys
  cmp <(grep -Ev "recovery_key|root_key" "${SCRIPT_DIR}/futility/data_${base}_expect.txt") \
  	"${loemdir}/loem.sha.new"

done

# Make sure that the BIOS with the good vblocks signed the right size.
GOOD_OUT="${TMP}.${GOOD_VBLOCKS##*/}.new"
MORE_OUT="${TMP}.${ONEMORE##*/}.new"
GOOD_CBFS_OUT="${TMP}.${GOOD_CBFS##*/}.new"

"${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" "${GOOD_OUT}" \
  | grep "::body::size::" | cut -d: -f9 > "${TMP}.good.body"
"${FUTILITY}" dump_fmap -p "${GOOD_OUT}" \
  | awk '/FW_MAIN_/ {print $3}' > "${TMP}.good.fw_main"
# This should fail because they're different
if cmp "${TMP}.good.body" "${TMP}.good.fw_main"; then false; fi

# Make sure that the BIOS with the bad vblocks signed the whole fw body
"${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" "${MORE_OUT}" \
  | grep "::body::size::" | cut -d: -f9 > "${TMP}.onemore.body"
"${FUTILITY}" dump_fmap -p "${MORE_OUT}" \
  | awk '/FW_MAIN_/ {print $3}' > "${TMP}.onemore.fw_main"
# These should match
cmp "${TMP}.onemore.body" "${TMP}.onemore.fw_main"
cmp "${TMP}.onemore.body" "${TMP}.good.fw_main"

"${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" \
    "${GOOD_CBFS_OUT}" \
  | grep "::body::size::" | cut -d: -f9 > "${TMP}.good_cbfs.body"
"${FUTILITY}" dump_fmap -p "${GOOD_CBFS_OUT}" \
  | awk '/FW_MAIN_/ {print $3}' > "${TMP}.good_cbfs.fw_main"
if cmp "${TMP}.good_cbfs.body" "${TMP}.good_cbfs.fw_main"; then false; fi


# Sign CBFS image after adding new files. Size should increase but still be
# smaller than FlashMap size.
: $(( count++ ))
echo -n "${count} " 1>&3

cp "${GOOD_CBFS_OUT}" "${GOOD_CBFS_OUT}.1"
truncate -s 512 "${TMP}.zero_512"
cbfstool "${GOOD_CBFS_OUT}.1" expand -r FW_MAIN_A,FW_MAIN_B
cbfstool "${GOOD_CBFS_OUT}.1" add \
  -r FW_MAIN_A,FW_MAIN_B -f "${TMP}.zero_512" -n new-data-file -t raw

"${FUTILITY}" sign \
  -s "${KEYDIR}/firmware_data_key.vbprivk" \
  -K "${KEYDIR}" \
  "${GOOD_CBFS_OUT}.1"

"${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" \
    "${GOOD_CBFS_OUT}.1" \
  | grep "::body::size::" | cut -d: -f9 > "${TMP}.good_cbfs.1.body"
"${FUTILITY}" dump_fmap -p "${GOOD_CBFS_OUT}" \
  | awk '/FW_MAIN_/ {print $3}' > "${TMP}.good_cbfs.1.fw_main"

# Check if size increased, but also if it was correctly truncated,
# so it does not span over whole FlashMap area.
[[ $(head -n1 "${TMP}.good_cbfs.body") \
  < $(head -n1 "${TMP}.good_cbfs.1.body") ]]
[[ $(tail -n1 "${TMP}.good_cbfs.body") \
  < $(tail -n1 "${TMP}.good_cbfs.1.body") ]]
[[ $(head -n1 "${TMP}.good_cbfs.1.body") \
  < $(head -n1 "${TMP}.good_cbfs.1.fw_main") ]]
[[ $(tail -n1 "${TMP}.good_cbfs.1.body") \
  < $(tail -n1 "${TMP}.good_cbfs.1.fw_main") ]]


# Sign image again but don't specify the version or the preamble flags.
# The firmware version and preamble flags should be preserved.
# NOTICE: Version preservation behavior changed from defaulting to 1.
: $(( count++ ))
echo -n "${count} " 1>&3

"${FUTILITY}" sign \
  -b "${KEYDIR}/firmware.keyblock" \
  -K "${KEYDIR}" \
  "${MORE_OUT}" "${MORE_OUT}.2"

m=$("${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" \
      "${MORE_OUT}.2" | grep -c -E 'firmware_version::14$|preamble::flags::8$')
[ "${m}" = "4" ]


# If the original preamble is not present, the preamble flags should be zero.
: $(( count++ ))
echo -n "${count} " 1>&3

"${FUTILITY}" load_fmap "${MORE_OUT}" VBLOCK_A:/dev/urandom VBLOCK_B:/dev/zero
"${FUTILITY}" sign \
  -k "${KEYDIR}/kernel_subkey.vbpubk" \
  -K "${KEYDIR}" \
  "${MORE_OUT}" "${MORE_OUT}.3"

m=$("${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" \
      "${MORE_OUT}.3" | grep -c -E 'firmware_version::1$|preamble::flags::0$')
[ "${m}" = "4" ]


# Check signing when B slot is empty
: $(( count++ ))
echo -n "${count} " 1>&3

"${FUTILITY}" load_fmap "${CLEAN_B}" VBLOCK_B:/dev/zero FW_MAIN_B:/dev/zero
"${FUTILITY}" sign \
  -s "${KEYDIR}/firmware_data_key.vbprivk" \
  -b "${KEYDIR}/firmware.keyblock" \
  -K "${KEYDIR}" \
  "${CLEAN_B}" "${CLEAN_B}.1"

"${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" "${CLEAN_B}.1" \
  | grep "::body::size::" | cut -d: -f9 > "${TMP}.clean_b.body"
"${FUTILITY}" dump_fmap -p "${CLEAN_B}.1" \
  | awk '/FW_MAIN_/ {print $3}' > "${TMP}.clean_b.fw_main"

# These should not be equal, as FW_MAIN_A size should be kept intact, when size
# of FW_MAIN_B should be taken from FlashMap.
if cmp "${TMP}.clean_b.body" "${TMP}.clean_b.fw_main" ; then false; fi
if cmp "${TMP}.clean_b.body" "${TMP}.good.body" ; then false; fi
cmp_first_line "${TMP}.clean_b.body" "${TMP}.good.body"
cmp_last_line "${TMP}.clean_b.body" "${TMP}.clean_b.fw_main"

# Version for slot A should be kept intact, while for B slot it should default
# to 1. All flags should be zero.
m=$("${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" \
        "${CLEAN_B}.1" \
      | grep -c -E 'firmware_version::1$|preamble::flags::0$|firmware_version::2$')
[ "${m}" = "4" ]

# Check signing when there is no B slot
: $(( count++ ))
echo -n "${count} " 1>&3

NO_B_SLOT="${TMP}.${GOOD_CBFS##*/}.no_b_slot"
NO_B_SLOT_SIGNED_IMG="${NO_B_SLOT}.signed"

cp "${GOOD_CBFS}" "${NO_B_SLOT}"
apply_xxd_patch "${NO_B_SLOT_PATCH}" "${NO_B_SLOT}"

"${FUTILITY}" sign \
  -s "${KEYDIR}/firmware_data_key.vbprivk" \
  -k "${KEYDIR}/kernel_subkey.vbpubk" \
  -K "${KEYDIR}" \
  -v 1 \
  "${NO_B_SLOT}" "${NO_B_SLOT_SIGNED_IMG}"

"${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" \
    "${NO_B_SLOT_SIGNED_IMG}" \
  | grep "::body::size::" | cut -d: -f9 > "${TMP}.no_b_slot.body"
"${FUTILITY}" dump_fmap -p "${NO_B_SLOT_SIGNED_IMG}" \
  | awk '/FW_MAIN_/ {print $3}' > "${TMP}.no_b_slot.fw_main"

if cmp "${TMP}.no_b_slot.body" "${TMP}.no_b_slot.fw_main" ; then false; fi
cmp "${TMP}.no_b_slot.body" <(tail -n1 "${TMP}.good_cbfs.body")

m=$("${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" \
        "${NO_B_SLOT_SIGNED_IMG}" \
      | grep -c -E 'firmware_version::1$|preamble::flags::0$')
[ "${m}" = "2" ]

# Check signing when cbfstool reports incorrect size
# Signing should fail, as it should not be possible for CBFS contents to be
# bigger than FlashMap size of the area
: $(( count++ ))
echo -n "${count} " 1>&3

CBFSTOOL_STUB="$(realpath "${TMP}.cbfs_stub.sh")"
echo -en 'echo "0xFFEEDD0"; exit 0;' > "${CBFSTOOL_STUB}"
chmod +x "${CBFSTOOL_STUB}"

if CBFSTOOL="${CBFSTOOL_STUB}" "${FUTILITY}" sign \
  -b "${KEYDIR}/firmware.keyblock" \
  -k "${KEYDIR}/kernel_subkey.vbpubk" \
  -K "${KEYDIR}" \
  -v 1 \
  "${GOOD_CBFS}" "${TMP}.1.${GOOD_CBFS##*/}"
then
  false
fi

# Redefine cbfstool stub to return valid value for FW_MAIN_A and invalid for
# FW_MAIN_B size. With this behavior futility should fail to sign this image,
# as cbfstool should never return incorrect size (larger than area).
cp "${GOOD_CBFS}" "${TMP}.good_cbfs.bin"
FW_MAIN_A_SIZE="$(printf '0x%x' \
  "$(cbfstool "${TMP}.good_cbfs.bin" truncate -r FW_MAIN_A)")"
MARK_FILE="$(realpath "${TMP}.mark1")"
rm -f "${MARK_FILE}"

cat << EOF > "${CBFSTOOL_STUB}"
#!/usr/bin/env bash
if ! [ -f "${MARK_FILE}" ]; then
  echo "${FW_MAIN_A_SIZE}";
  echo 1 > "${MARK_FILE}";
else
  echo 0xFFFFAA0;
fi
exit 0;
EOF

if CBFSTOOL="${CBFSTOOL_STUB}" "${FUTILITY}" sign \
  -K "${KEYDIR}" \
  -v 1 \
  "${GOOD_CBFS}" "${TMP}.2.${GOOD_CBFS##*/}"
then
  false
fi


# Check various incorrect values in VBLOCK (keyblock and preamble)
: $(( count++ ))
echo -n "${count} " 1>&3

bad_counter=1
for keyblock_patch in "${BAD_KEYBLOCK_PATCHES[@]}"; do
  echo -n "${count}.${bad_counter} " 1>&3
  BAD_IN="${TMP}.${GOOD_DEV##*/}.bad.${bad_counter}.in.bin"
  BAD_OUT="${TMP}.${GOOD_DEV##*/}.bad.${bad_counter}.out.bin"
  cp "${GOOD_DEV}" "${BAD_IN}"
  apply_xxd_patch "${keyblock_patch}" "${BAD_IN}"

  FUTIL_OUTPUT="$(if "${FUTILITY}" verify -P \
                        --publickey "${KEYDIR}/root_key.vbpubk" "${BAD_IN}"; \
                  then false; fi)"
  grep -q 'bios::VBLOCK_A::keyblock::invalid' <<< "${FUTIL_OUTPUT}"

  FUTIL_OUTPUT="$("${FUTILITY}" sign \
    -K "${KEYDIR}" \
    "${BAD_IN}" "${BAD_OUT}" 2>&1)"
   grep -q 'VBLOCK_A keyblock is invalid' <<< "${FUTIL_OUTPUT}"

  "${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" "${BAD_OUT}" \
    | grep "::body::size::" | cut -d: -f9 > "${BAD_OUT}.body"
  "${FUTILITY}" dump_fmap -p "${BAD_OUT}" \
    | awk '/FW_MAIN_/ {print $3}' > "${BAD_OUT}.fw_main"

  cmp "${BAD_OUT}.fw_main" "${TMP}.good.fw_main"
  cmp_first_line "${BAD_OUT}.body" "${TMP}.good.fw_main"
  cmp_last_line "${BAD_OUT}.body" "${TMP}.good.body"

  : $(( bad_counter++ ))
done

for vblock_patch in "${BAD_PREAMBLE_PATCHES[@]}"; do
  echo -n "${count}.${bad_counter} " 1>&3
  BAD_IN="${TMP}.${GOOD_DEV##*/}.bad.${bad_counter}.in.bin"
  BAD_OUT="${TMP}.${GOOD_DEV##*/}.bad.${bad_counter}.out.bin"
  cp "${GOOD_DEV}" "${BAD_IN}"
  apply_xxd_patch "${vblock_patch}" "${BAD_IN}"

  FUTIL_OUTPUT="$(if "${FUTILITY}" verify -P \
                       --publickey "${KEYDIR}/root_key.vbpubk" "${BAD_IN}"; \
                  then false; fi)"
  grep -q 'bios::VBLOCK_A::preamble::invalid' <<< "${FUTIL_OUTPUT}"

  FUTIL_OUTPUT="$("${FUTILITY}" sign \
    -K "${KEYDIR}" \
    "${BAD_IN}" "${BAD_OUT}" 2>&1)"
  grep -q 'VBLOCK_A preamble is invalid' <<< "${FUTIL_OUTPUT}"

  "${FUTILITY}" verify -P --publickey "${KEYDIR}/root_key.vbpubk" "${BAD_OUT}" \
    | grep "::body::size::" | cut -d: -f9 > "${BAD_OUT}.body"
  "${FUTILITY}" dump_fmap -p "${BAD_OUT}" \
    | awk '/FW_MAIN_/ {print $3}' > "${BAD_OUT}.fw_main"

  cmp "${BAD_OUT}.fw_main" "${TMP}.good.fw_main"
  cmp_first_line "${BAD_OUT}.body" "${TMP}.good.fw_main"
  cmp_last_line "${BAD_OUT}.body" "${TMP}.good.body"

  : $(( bad_counter++ ))
done

for vblock_patch in "${BAD_FMAP_KEYBLOCK_PATCHES[@]}"; do
  echo -n "${count}.${bad_counter} " 1>&3
  BAD_IN="${TMP}.${GOOD_DEV##*/}.bad.${bad_counter}.in.bin"
  BAD_OUT="${TMP}.${GOOD_DEV##*/}.bad.${bad_counter}.out.bin"
  cp "${GOOD_DEV}" "${BAD_IN}"
  apply_xxd_patch "${vblock_patch}" "${BAD_IN}"

  FUTIL_OUTPUT="$(if "${FUTILITY}" verify -P\
                       --publickey "${KEYDIR}/root_key.vbpubk" "${BAD_IN}"; \
                  then false; fi)"
  grep -q 'bios::VBLOCK_A::keyblock::invalid' <<< "${FUTIL_OUTPUT}"

  FUTIL_OUTPUT="$(if "${FUTILITY}" sign \
                       -K "${KEYDIR}" \
                       "${BAD_IN}" "${BAD_OUT}" 2>&1; \
                  then false; fi)"
  m="$(grep -c -E \
     'VBLOCK_A keyblock is invalid|Keyblock and preamble do not fit in VBLOCK' \
     <<< "${FUTIL_OUTPUT}")"
  [ "${m}" = "2" ]

  : $(( bad_counter++ ))
done

echo -n "${count}.${bad_counter} " 1>&3
BAD_IN="${TMP}.${GOOD_DEV##*/}.bad.${bad_counter}.in.bin"
BAD_OUT="${TMP}.${GOOD_DEV##*/}.bad.${bad_counter}.out.bin"
cp "${GOOD_DEV}" "${BAD_IN}"
apply_xxd_patch "${BAD_FMAP_PREAMBLE_PATCHES[0]}" "${BAD_IN}"

FUTIL_OUTPUT="$(if "${FUTILITY}" verify -P \
                     --publickey "${KEYDIR}/root_key.vbpubk" "${BAD_IN}"; \
                then false; fi)"
grep -q 'bios::VBLOCK_A::preamble::invalid' <<< "${FUTIL_OUTPUT}"

FUTIL_OUTPUT="$(if "${FUTILITY}" sign \
                     -K "${KEYDIR}" \
                     "${BAD_IN}" "${BAD_OUT}" 2>&1; \
                then false; fi)"
m="$(grep -c -E \
     'VBLOCK_A preamble is invalid|Keyblock and preamble do not fit in VBLOCK' \
     <<< "${FUTIL_OUTPUT}")"
[ "${m}" = "2" ]

: $(( bad_counter++ ))

echo -n "${count}.${bad_counter} " 1>&3
BAD_IN="${TMP}.${GOOD_DEV##*/}.bad.${bad_counter}.in.bin"
BAD_OUT="${TMP}.${GOOD_DEV##*/}.bad.${bad_counter}.out.bin"
cp "${GOOD_DEV}" "${BAD_IN}"
apply_xxd_patch "${BAD_FMAP_PREAMBLE_PATCHES[1]}" "${BAD_IN}"

FUTIL_OUTPUT="$(if "${FUTILITY}" verify -P \
                     --publickey "${KEYDIR}/root_key.vbpubk" "${BAD_IN}"; \
                then false; fi)"
grep -q 'bios::VBLOCK_A::preamble::invalid' <<< "${FUTIL_OUTPUT}"

FUTIL_OUTPUT="$(if "${FUTILITY}" sign \
                     -K "${KEYDIR}" \
                     "${BAD_IN}" "${BAD_OUT}" 2>&1; \
                then false; fi)"
m="$(grep -c -E \
       -e 'VBLOCK_A is invalid\. Keyblock and preamble do not fit' \
       -e 'Keyblock and preamble do not fit in VBLOCK' \
       <<< "${FUTIL_OUTPUT}")"
[ "${m}" = "2" ]

: $(( bad_counter++ ))


# cleanup
rm -rf "${TMP}"* "${ONEMORE}"
exit 0
