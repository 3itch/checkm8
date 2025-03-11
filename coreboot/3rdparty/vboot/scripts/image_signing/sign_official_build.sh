#!/bin/bash

# Copyright 2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Sign the final build image using the "official" keys.
#
# Prerequisite tools needed in the system path:
#
#  futility (from src/platform/vboot_reference)
#  verity (from src/platform2/verity)
#  load_kernel_test (from src/platform/vboot_reference)
#  dumpe2fs
#  e2fsck
#  sha1sum

# Load common constants and variables.
. "$(dirname "$0")/common.sh"
. "$(dirname "$0")/lib/keycfg.sh"

# Abort on errors.
set -e

# Our random local constants.
MINIOS_KERNEL_GUID="09845860-705F-4BB5-B16C-8A8A099CAF52"
FIRMWARE_VERSION=1
KERNEL_VERSION=1
V1_SUFFIX=".v1"

# Print usage string
usage() {
  cat <<EOF
Usage: ${PROG} <type> input_image /path/to/keys/dir [output_image] \
[version_file] [--cloud-signing]
where <type> is one of:
             base (sign a base image)
             recovery (sign a USB recovery image)
             factory (sign a factory install image)
             update_payload (sign a delta update hash)
             firmware (sign a firmware image)
             verify (verify an image including rootfs hashes)
             accessory_usbpd (sign USB-PD accessory firmware)
             accessory_rwsig (sign accessory RW firmware)
             gsc_firmware (sign a GSC firmware image)
             uefi_kernel (sign a UEFI kernel image)

output_image: File name of the signed output image
version_file: File name of where to read the kernel and firmware versions.
--cloud-signing: Instead of relying on a local key directory, retrieve keys
  from Cloud KMS.
--debug: Show more information for debugging purpose.

If you are signing an image, you must specify an [output_image] and
optionally, a [version_file].

EOF
  if [[ $# -gt 0 ]]; then
    error "$*"
    exit 1
  fi
  exit 0
}

# Verify we have as many arguments as we expect, else show usage & quit.
# Usage:
#  check_argc <number args> <exact number>
#  check_argc <number args> <lower bound> <upper bound>
check_argc() {
  case $# in
  2)
    if [[ $1 -ne $2 ]]; then
      usage "command takes exactly $2 args"
    fi
    ;;
  3)
    if [[ $1 -lt $2 || $1 -gt $3 ]]; then
      usage "command takes $2 to $3 args"
    fi
    ;;
  *)
    die "check_argc: incorrect number of arguments"
  esac
}

# Run futility as root with some preserved environment variables.
sudo_futility() {
  sudo "KMS_PKCS11_CONFIG=${KMS_PKCS11_CONFIG}" "${FUTILITY}" ${FUTILITY_EXTRA_FLAGS} "$@"
}

do_futility() {
  "${FUTILITY}" ${FUTILITY_EXTRA_FLAGS} "$@"
}

# TODO(gauravsh): These are duplicated from chromeos-setimage. We need
# to move all signing and rootfs code to one single place where it can be
# reused. crosbug.com/19543

# get_verity_arg <commandline> <key> -> <value>
get_verity_arg() {
  echo "$1" | sed -n "s/.*\b$2=\([^ \"]*\).*/\1/p"
}

# Get the dmparams parameters from a kernel config.
get_dmparams_from_config() {
  local kernel_config=$1
  echo "${kernel_config}" | sed -nre 's/.*dm="([^"]*)".*/\1/p'
}
# Get the verity root digest hash from a kernel config command line.
get_hash_from_config() {
  local kernel_config=$1
  local dm_config
  dm_config=$(get_dmparams_from_config "${kernel_config}")
  local vroot_dev
  vroot_dev=$(get_dm_device "${dm_config}" vroot)
  get_verity_arg "${vroot_dev}" root_hexdigest
}

# Get the mapped device and its args.
# Usage:
#   get_dm_device $dm_config [vboot|vroot]
# Assumes we have only one mapped device per device.
get_dm_device() {
  local dm=$1
  local device=$2
  echo "${dm}" | sed -nre "s/.*${device}[^,]*,([^,]*).*/\1/p"
}

# Set the mapped device and its args for a device.
# Usage:
#   set_dm_device $dm_config [vboot|vroot] args
# Assumes we have only one mapped device per device.
set_dm_device() {
  local dm=$1
  local device=$2
  local args=$3
  echo "${dm}" | sed -nre "s#(.*${device}[^,]*,)([^,]*)(.*)#\1${args}\3#p"
}

CALCULATED_KERNEL_CONFIG=
CALCULATED_DM_ARGS=
# Calculate rootfs hash of an image
# Args: ROOTFS_IMAGE KERNEL_CONFIG HASH_IMAGE
#
# rootfs calculation parameters are grabbed from KERNEL_CONFIG
#
# Updated dm-verity arguments (to be replaced in kernel config command line)
# with the new hash is stored in $CALCULATED_DM_ARGS and the new hash image is
# written to the file HASH_IMAGE.
calculate_rootfs_hash() {
  local rootfs_image=$1
  local kernel_config=$2
  local hash_image=$3
  local dm_config
  dm_config=$(get_dmparams_from_config "${kernel_config}")

  if [ -z "${dm_config}" ]; then
    warn "Couldn't grab dm_config. Aborting rootfs hash calculation."
    return 1
  fi
  local vroot_dev
  vroot_dev=$(get_dm_device "${dm_config}" vroot)

  # Extract the key-value parameters from the kernel command line.
  local rootfs_sectors
  rootfs_sectors=$(get_verity_arg "${vroot_dev}" hashstart)
  local verity_algorithm
  verity_algorithm=$(get_verity_arg "${vroot_dev}" alg)
  local root_dev
  root_dev=$(get_verity_arg "${vroot_dev}" payload)
  local hash_dev
  hash_dev=$(get_verity_arg "${vroot_dev}" hashtree)
  local salt
  salt=$(get_verity_arg "${vroot_dev}" salt)

  local salt_arg
  if [ -n "${salt}" ]; then
    salt_arg="salt=${salt}"
  fi

  # Run the verity tool on the rootfs partition.
  local table
  table=$(sudo verity mode=create \
    alg="${verity_algorithm}" \
    payload="${rootfs_image}" \
    payload_blocks=$((rootfs_sectors / 8)) \
    hashtree="${hash_image}" "${salt_arg}")
  # Reconstruct new kernel config command line and replace placeholders.
  table="$(echo "${table}" |
    sed -s "s|ROOT_DEV|${root_dev}|g;s|HASH_DEV|${hash_dev}|")"
  CALCULATED_DM_ARGS="$(set_dm_device "${dm_config}" vroot "${table}")"
  # shellcheck disable=SC2001
  CALCULATED_KERNEL_CONFIG="$(echo "${kernel_config}" |
    sed -e 's#\(.*dm="\)\([^"]*\)\(".*\)'"#\1${CALCULATED_DM_ARGS}\3#g")"
}

# Re-calculate rootfs hash, update rootfs and kernel command line(s).
# Args: LOOPDEV KERNEL \
#       KERN_A_KEYBLOCK KERN_A_PRIVKEY \
#       KERN_B_KEYBLOCK KERN_B_PRIVKEY SHOULD_SIGN_KERN_B \
#       KERN_C_KEYBLOCK KERN_C_PRIVKEY SHOULD_SIGN_KERN_C
#
# The rootfs is hashed by tool 'verity', and the hash data is stored after the
# rootfs. A hash of those hash data (also known as final verity hash) may be
# contained in kernel 2 or kernel 4 command line.
#
# This function reads dm-verity configuration from KERNEL, rebuilds the rootfs
# hash, and then resigns kernel A & B (& C if needed) by their keyblock and
# private key files.
update_rootfs_hash() {
  local loopdev="$1"  # Input image.
  local loop_kern="$2"  # Kernel that contains verity args.
  local kern_a_keyblock="$3"  # Keyblock file for kernel A.
  local kern_a_privkey="$4"  # Private key file for kernel A.
  local kern_b_keyblock="$5"  # Keyblock file for kernel B.
  local kern_b_privkey="$6"  # Private key file for kernel B.
  local should_sign_kern_b="$7"
  local kern_c_keyblock="$8"  # Keyblock file for kernel C.
  local kern_c_privkey="$9"  # Private key file for kernel C.
  local should_sign_kern_c="${10}"
  local loop_rootfs="${loopdev}p3"

  # Note even though there are two kernels, there is one place (after rootfs)
  # for hash data, so we must assume both kernel use same hash algorithm (i.e.,
  # DM config).
  info "Updating rootfs hash and updating config for Kernel partitions"

  # If we can't find dm parameters in the kernel config, bail out now.
  local kernel_config
  kernel_config=$(sudo_futility dump_kernel_config "${loop_kern}")
  local dm_config
  dm_config=$(get_dmparams_from_config "${kernel_config}")
  if [ -z "${dm_config}" ]; then
    error "Couldn't grab dm_config from kernel ${loop_kern}"
    error " (config: ${kernel_config})"
    return 1
  fi

  # check and clear need_to_resign tag
  local rootfs_dir
  rootfs_dir=$(make_temp_dir)
  sudo mount -o ro "${loop_rootfs}" "${rootfs_dir}"
  if has_needs_to_be_resigned_tag "${rootfs_dir}"; then
    # remount as RW
    sudo mount -o remount,rw "${rootfs_dir}"
    sudo rm -f "${rootfs_dir}/${TAG_NEEDS_TO_BE_SIGNED}"
  fi
  sudo umount "${rootfs_dir}"

  local hash_image
  hash_image=$(make_temp_file)

  # Disable rw mount support prior to hashing.
  disable_rw_mount "${loop_rootfs}"

  if ! calculate_rootfs_hash "${loop_rootfs}"  "${kernel_config}" \
    "${hash_image}"; then
    error "calculate_rootfs_hash failed!"
    error "Aborting rootfs hash update!"
    return 1
  fi

  local rootfs_blocks
  rootfs_blocks=$(sudo dumpe2fs "${loop_rootfs}" 2> /dev/null |
    grep "Block count" |
    tr -d ' ' |
    cut -f2 -d:)
  local rootfs_sectors=$((rootfs_blocks * 8))

  # Overwrite the appended hashes in the rootfs
  sudo dd if="${hash_image}" of="${loop_rootfs}" bs=512 \
    seek="${rootfs_sectors}" conv=notrunc 2>/dev/null

  # Update kernel command lines
  local dm_args="${CALCULATED_DM_ARGS}"
  local temp_config
  temp_config=$(make_temp_file)
  local kernelpart=
  local keyblock=
  local priv_key=
  local new_kernel_config=

  for kernelpart in 2 4 6; do
    loop_kern="${loopdev}p${kernelpart}"
    if ! new_kernel_config="$(
         sudo_futility dump_kernel_config "${loop_kern}" 2>/dev/null)" &&
       [[ "${kernelpart}" == 4 ]]; then
      # Legacy images don't have partition 4.
      info "Skipping empty kernel partition 4 (legacy images)."
      continue
    fi
    if [[ "${should_sign_kern_b}" == "false" && "${kernelpart}" == 4 ]]; then
      info "Skip signing kernel B."
      continue
    fi
    if [[ "${should_sign_kern_c}" == "false" && "${kernelpart}" == 6 ]]; then
      info "Skip signing kernel C."
      continue
    fi
    # shellcheck disable=SC2001
    new_kernel_config="$(echo "${new_kernel_config}" |
      sed -e 's#\(.*dm="\)\([^"]*\)\(".*\)'"#\1${dm_args}\3#g")"
    info "New config for kernel partition ${kernelpart} is:"
    echo "${new_kernel_config}" | tee "${temp_config}"
    # Re-calculate kernel partition signature and command line.
    if [[ "${kernelpart}" == 2 ]]; then
      keyblock="${kern_a_keyblock}"
      priv_key="${kern_a_privkey}"
    elif [[ "${kernelpart}" == 4 ]]; then
      keyblock="${kern_b_keyblock}"
      priv_key="${kern_b_privkey}"
    else
      keyblock="${kern_c_keyblock}"
      priv_key="${kern_c_privkey}"
    fi
    sudo_futility vbutil_kernel --repack "${loop_kern}" \
      --keyblock "${keyblock}" \
      --signprivate "${priv_key}" \
      --version "${KERNEL_VERSION}" \
      --oldblob "${loop_kern}" \
      --config "${temp_config}"
  done
}

# Update the SSD install-able vblock file on stateful partition.
# ARGS: Loopdev
# This is deprecated because all new images should have a SSD boot-able kernel
# in partition 4. However, the signer needs to be able to sign new & old images
# (crbug.com/449450#c13) so we will probably never remove this.
update_stateful_partition_vblock() {
  local loopdev="$1"
  local temp_out_vb
  temp_out_vb="$(make_temp_file)"

  local loop_kern="${loopdev}p4"
  if [[ -z "$(sudo_futility dump_kernel_config "${loop_kern}" \
        2>/dev/null)" ]]; then
    info "Building vmlinuz_hd.vblock from legacy image partition 2."
    loop_kern="${loopdev}p2"
  fi

  # vblock should always use kernel keyblock.
  sudo_futility vbutil_kernel --repack "${temp_out_vb}" \
    --keyblock "${KEYCFG_KERNEL_KEYBLOCK}" \
    --signprivate "${KEYCFG_KERNEL_VBPRIVK}" \
    --oldblob "${loop_kern}" \
    --vblockonly

  # Copy the installer vblock to the stateful partition.
  local stateful_dir
  stateful_dir=$(make_temp_dir)
  sudo mount "${loopdev}p1" "${stateful_dir}"
  sudo cp "${temp_out_vb}" "${stateful_dir}"/vmlinuz_hd.vblock
  sudo umount "${stateful_dir}"
}

# Do a validity check on the image's rootfs
# ARGS: Image
verify_image_rootfs() {
  local rootfs=$1
  # This flips the read-only compatibility flag, so that e2fsck does not
  # complain about unknown file system capabilities.
  enable_rw_mount "${rootfs}"
  info "Running e2fsck to check root file system for errors"
  sudo e2fsck -fn "${rootfs}" ||
    die "Root file system has errors!"
  # Flip the bit back so we don't break hashes.
  disable_rw_mount "${rootfs}"
}

# Repacks firmware updater bundle content from given folder.
# Args: INPUT_DIR TARGET_SCRIPT
repack_firmware_bundle() {
  local input_dir="$1"
  local target
  target="$(readlink -f "$2")"

  if [ ! -s "${target}" ]; then
    return 1
  elif grep -q '^##CUTHERE##' "${target}"; then
    # Bundle supports repacking (--repack, --sb_repack)
    # Workaround issue crosbug.com/p/33719
    sed -i \
      's/shar -Q -q -x -m -w/shar -Q -q -x -m --no-character-count/' \
      "${target}"
    "${target}" --repack "${input_dir}" ||
      "${target}" --sb_repack "${input_dir}" ||
        die "Updating firmware autoupdate (--repack) failed."
  else
    # Legacy bundle using uuencode + tar.gz.
    # Replace MD5 checksum in the firmware update payload.
    local newfd_checksum
    newfd_checksum="$(md5sum "${input_dir}"/bios.bin | cut -f 1 -d ' ')"
    local temp_version
    temp_version="$(make_temp_file)"
    cat "${input_dir}"/VERSION |
    sed -e "s#\(.*\)\ \(.*bios.bin.*\)#${newfd_checksum}\ \2#" > \
      "${temp_version}"
    mv "${temp_version}" "${input_dir}"/VERSION

    # Re-generate firmware_update.tgz and copy over encoded archive in
    # the original shell ball.
    sed -ine '/^begin .*firmware_package/,/end/D' "${target}"
    tar zcf - -C "${input_dir}" . |
      uuencode firmware_package.tgz >>"${target}"
  fi
}

# Sign a firmware in-place with the given keys.
# Args: FIRMWARE_IMAGE KEY_DIR FIRMWARE_VERSION [LOEM_OUTPUT_DIR]
sign_firmware() {
  local image=$1
  local key_dir=$2
  local firmware_version=$3
  local loem_output_dir=${4:-}

  # Resign the firmware with new keys, also replacing the root and recovery
  # public keys in the GBB.
  "${SCRIPT_DIR}/sign_firmware.sh" "${image}" "${key_dir}" "${image}" \
    "${firmware_version}" "${loem_output_dir}"
  info "Signed firmware image output to ${image}"
}

# Sign a delta update payload (usually created by paygen).
# Args: INPUT_IMAGE KEY_DIR OUTPUT_IMAGE
sign_update_payload() {
  local image=$1
  local key_info=$2
  local output=$3
  local key_output key_size

  if [[ "${key_info}" == "remote:"* ]]; then
    # get label from key_info with format "remote:<libkmsp11.so>:<slot>:<label>"
    IFS=":" read -r -a parsed_info <<< "${key_info}"
    if [[ "${#parsed_info[@]}" -ne 4 ]]; then
      die "Failed to parse key info '${key_info}'"
    fi
    local p11_module="${parsed_info[1]}"
    # We omit slot because the pkeyutl command will look in every keyring in the
    # config file for the named key.
    local key_label="${parsed_info[3]}"
    # Hashing algorithm is always SHA-256.
    PKCS11_MODULE_PATH="${p11_module}" openssl pkeyutl -pkeyopt \
      rsa_padding_mode:pkcs1 -pkeyopt digest:sha256 -engine pkcs11 \
      -keyform engine -sign --inkey "pkcs11:object=${key_label}" \
      -in "${image}" -out "${output}"
    return
  fi
  # Strip the prefix "local:"
  key_info="${key_info#local:}"
  # Maps key size to verified boot's algorithm id (for pad_digest_utility).
  # Hashing algorithm is always SHA-256.
  local algo algos=(
    [1024]=1
    [2048]=4
    [4096]=7
    [8192]=10
  )

  key_output=$(do_futility show "${key_info}")
  key_size=$(echo "${key_output}" | sed -n '/Key length/s/[^0-9]*//p')
  algo=${algos[${key_size}]}
  if [[ -z ${algo} ]]; then
    die "Unknown algorithm: futility output=${key_output}"
  fi

  pad_digest_utility "${algo}" "${image}" | \
    openssl rsautl -sign -pkcs -inkey "${key_info}" -out "${output}"
}

# Re-sign the firmware AU payload inside the image rootfs with a new keys.
# Args: LOOPDEV
resign_firmware_payload() {
  local loopdev="$1"

  if [ -n "${NO_FWUPDATE}" ]; then
    info "Skipping firmware update."
    return
  fi

  # Grab firmware image from the autoupdate bundle (shellball).
  local rootfs_dir
  rootfs_dir=$(make_temp_dir)
  mount_loop_image_partition "${loopdev}" 3 "${rootfs_dir}"

  local ret=0
  resign_firmware_shellball "${rootfs_dir}/usr/sbin/chromeos-firmwareupdate" || ret=$?
  sudo umount "${rootfs_dir}"
  if [[ "${ret}" == 0 ]]; then
    info "Re-signed firmware AU payload in ${loopdev}"
  else
    error "Couldn't sign firmware AU payload in ${loopdev}"
  fi
  return "${ret}"
}

# Re-sign the firmware AU payload provided with a new key.
# Args: firmware_bundle
resign_firmware_shellball() {
  local firmware_bundle=$1

  local shellball_dir
  shellball_dir=$(make_temp_dir)

  # extract_firmware_bundle can fail if the image has no firmware update.
  if ! extract_firmware_bundle "${firmware_bundle}" "${shellball_dir}"; then
    # Unmount now to prevent changes.
    info "Didn't find a firmware update. Not signing firmware."
    return
  fi
  info "Found a valid firmware update shellball."

  # For context on signing firmware for unified builds, see:
  #   go/cros-unibuild-signing
  #
  # This iterates over a signer_config.csv file, which contains the following:
  #   output_name,image,key_id               (header)
  #   santa,models/santa/bios.bin,SOME_OEM  (sample line)
  #
  # This dictates what output signature blocks to generate based on what
  # keys/binaries.
  #
  # It reuses the LOEM architecture already existing in the signer keysets,
  # but this could be revisited at a future date.
  #
  # Within signer_config.csv, it uses the key_id column to match the key
  # value in loem.ini (if present) and signs the corresponding firmware
  # image using that key.
  #
  # It then outputs the appropriate signature blocks based on the output_name.
  # The firmware updater scripts then detects what output_name to use at
  # runtime based on the platform.
  local signer_config="${shellball_dir}/signer_config.csv"
  if [[ -e "${signer_config}" ]]; then
    info "Using signer_config.csv to determine firmware signatures"
    info "See go/cros-unibuild-signing for details"
    {
      read # Burn the first line (header line)
      while IFS="," read -r output_name bios_image key_id ec_image brand_code
      do
        local extra_args=()
        local full_command=()

        rootkey="$(get_root_key_vbpubk)"

        info "Signing firmware image ${bios_image} for ${output_name}"

        # If there are OEM specific keys available, we're going to use them.
        # Otherwise, we're going to ignore key_id from the config file and
        # just use the common keys present in the keyset.
        #
        # The presence of the /keyset subdir in the shellball will indicate
        # whether dynamic signature blocks are available or not.
        # This is what updater4.sh currently uses to make the decision.
        if [[ -e "${KEY_DIR}/loem.ini" ]]; then
          local match
          local key_index

          # loem.ini has the format KEY_ID_VALUE = KEY_INDEX
          if ! match="$(grep -E "^[0-9]+ *= *${key_id}$" "${KEY_DIR}/loem.ini")"; then
            die "The loem key_id ${key_id} not found in loem.ini! (${KEY_DIR}/loem.ini)"
          fi

          # shellcheck disable=SC2001
          key_index="$(echo "${match}" | sed 's/ *= *.*$//g')"
          info "Detected key index from loem.ini as ${key_index} for ${key_id}"
          if [[ -z "${key_index}" ]]; then
            die "Failed to extract key_index ${key_id} in loem.ini file for" \
              "${output_name}"
          fi

          shellball_keyset_dir="${shellball_dir}/keyset"
          mkdir -p "${shellball_keyset_dir}"
          extra_args+=(
            --loemdir "${shellball_keyset_dir}"
            --loemid "${output_name}"
          )
          rootkey="$(get_root_key_vbpubk "${key_index}")"
          cp "${rootkey}" "${shellball_keyset_dir}/rootkey.${output_name}"
        fi

        info "Using root key: ${rootkey##*/}"

        local temp_fw
        temp_fw=$(make_temp_file)

        local signprivate
        local keyblock
        signprivate="$(get_firmware_vbprivk "${key_index}")"
        keyblock="$(get_firmware_keyblock "${key_index}")"

        # Path to bios.bin.
        local bios_path="${shellball_dir}/${bios_image}"

        echo "Before EC signing ${bios_path}: md5 =" \
          "$(md5sum "${bios_path}" | awk '{print $1}')"

        if [ -n "${ec_image}" ]; then
          # Path to ec.bin.
          local ec_path="${shellball_dir}/${ec_image}"

          # Resign ec.bin.
          if is_ec_rw_signed "${ec_path}"; then
            local rw_bin="EC_RW.bin"
            local rw_hash="EC_RW.hash"
            # futility writes byproduct files to CWD, so we cd to temp dir.
            pushd "$(make_temp_dir)" > /dev/null
            full_command=(
              do_futility sign
              --type rwsig
              --prikey "${KEYCFG_KEY_EC_EFS_VBPRIK2}"
              --ecrw_out "${rw_bin}"
              "${ec_path}"
            )
            echo "Signing EC with: ${full_command[*]}"
            "${full_command[@]}" || die "Failed to sign ${ec_path}"
            # Above command produces EC_RW.bin. Compute its hash.
            openssl dgst -sha256 -binary "${rw_bin}" > "${rw_hash}"
            # Store EC_RW.bin and its hash in bios.bin.
            store_file_in_cbfs "${bios_path}" "${rw_bin}" "ecrw" \
              || die "Failed to store file in ${bios_path}"
            store_file_in_cbfs "${bios_path}" "${rw_hash}" "ecrw.hash" \
              || die "Failed to store file in ${bios_path}"
            popd > /dev/null
            info "Signed EC image output to ${ec_path}"
          fi
        fi

        echo "After EC signing ${bios_path}: md5 =" \
          "$(md5sum "${bios_path}" | awk '{print $1}')"

        # Resign bios.bin.
        full_command=(
          do_futility sign
          --signprivate "${signprivate}"
          --keyblock "${keyblock}"
          --kernelkey "${KEYCFG_KERNEL_SUBKEY_VBPUBK}"
          --version "${FIRMWARE_VERSION}"
          "${extra_args[@]}"
          "${bios_path}"
          "${temp_fw}"
        )
        echo "Signing BIOS with: ${full_command[*]}"
        "${full_command[@]}"

        echo "After BIOS signing ${temp_fw}: md5 =" \
          "$(md5sum "${temp_fw}" | awk '{print $1}')"

        # For development phases, when the GBB can be updated still, set the
        # recovery and root keys in the image.
        full_command=(
          do_futility gbb
          -s
          --recoverykey="${KEYCFG_RECOVERY_KEY_VBPUBK}"
          --rootkey="${rootkey}" "${temp_fw}"
          "${bios_path}"
        )
        echo "Setting GBB with: ${full_command[*]}"
        "${full_command[@]}"

        echo "After setting GBB on ${bios_path}: md5 =" \
          "$(md5sum "${bios_path}" | awk '{print $1}')"

        if [[ -e "${shellball_dir}/models/guybrush" ]]; then
          echo "Not looking for RO_GSCVD on guybrush, b/263378945"
        elif futility dump_fmap -p "${bios_path}" | grep -q RO_GSCVD; then
          # Attempt AP RO verification signing only in case the FMAP includes
          # the RO_GSCVD section.
          local arv_root

          if [[ -z ${brand_code} ]]; then
            die "No brand code for ${bios_path} in signer_config.csv"
          fi

          arv_root="${KEYCFG_ARV_ROOT_VBPUBK}"
          if [[ ! -f ${arv_root} ]]; then
            die "No AP RO verification keys, could not create RO_GSCVD"
          fi

          # Resign the RO_GSCVD FMAP area.
          full_command=(
            do_futility gscvd
            --keyblock "${KEYCFG_ARV_PLATFORM_KEYBLOCK}"
            --platform_priv "${KEYCFG_ARV_PLATFORM_VBPRIVK}"
            --board_id "${brand_code}"
            --root_pub_key "${arv_root}"
            "${bios_path}"
          )
          if [[ -n ${shellball_keyset_dir} ]]; then
            full_command+=(
              --gscvd_out
              "${shellball_keyset_dir}/gscvd.${output_name}"
            )
          fi
          echo "Setting RO_GSCVD with: ${full_command[*]}"
          "${full_command[@]}"

          echo "After signing RO_GSCVD on ${bios_path}: md5 =" \
               "$(md5sum "${bios_path}" | awk '{print $1}')"
        else
          echo "No RO_GSCVD section in the image, skipping AP RO signing"
        fi
        info "Signed firmware image output to ${bios_path}"
      done
      unset IFS
    } < "${signer_config}"
  else
    local image_file sign_args=() loem_sfx loem_output_dir
    for image_file in "${shellball_dir}"/bios*.bin; do
      if [[ -e "${KEY_DIR}/loem.ini" ]]; then
        # Extract the extended details from "bios.bin" and use that in the
        # subdir for the keyset.
        loem_sfx=$(sed -r 's:.*/bios([^/]*)[.]bin$:\1:' <<<"${image_file}")
        loem_output_dir="${shellball_dir}/keyset${loem_sfx}"
        sign_args=( "${loem_output_dir}" )
        mkdir -p "${loem_output_dir}"
      fi
      sign_firmware "${image_file}" "${KEY_DIR}" "${FIRMWARE_VERSION}" \
        "${sign_args[@]}"
    done
  fi

  local signer_notes="${shellball_dir}/VERSION.signer"
  echo "" >"${signer_notes}"
  echo "Signed with keyset in $(readlink -f "${KEY_DIR}") ." >>"${signer_notes}"
  # record recovery_key
  key="${KEYCFG_RECOVERY_KEY_VBPUBK}"
  sha1=$(do_futility vbutil_key --unpack "${key}" \
    | grep sha1sum | cut -d" " -f9)
  echo "recovery: ${sha1}" >>"${signer_notes}"
  # record root_key(s)
  if [[ -d "${shellball_keyset_dir}"  ]]; then
    echo "List sha1sum of all loem/model's signatures:" >>"${signer_notes}"
    for key in "${shellball_keyset_dir}"/rootkey.*; do
      model="${key##*.}"
      sha1=$(do_futility vbutil_key --unpack "${key}" \
        | grep sha1sum | cut -d" " -f9)
      echo "  ${model}: ${sha1}" >>"${signer_notes}"
    done
  else
    echo "List sha1sum of single key's signature:" >>"${signer_notes}"
    key="$(get_root_key_vbpubk)"
    sha1=$(do_futility vbutil_key --unpack "${key}" \
      | grep sha1sum | cut -d" " -f9)
    echo "  root: ${sha1}" >>"${signer_notes}"
  fi

  local new_shellball
  new_shellball=$(make_temp_file)
  cp -f "${firmware_bundle}" "${new_shellball}"
  chmod a+rx "${new_shellball}"
  repack_firmware_bundle "${shellball_dir}" "${new_shellball}"
  sudo cp -f "${new_shellball}" "${firmware_bundle}"
  sudo chmod a+rx "${firmware_bundle}"
}

# Remove old container key if it exists.
# We can drop this logic once all devices that shipped R78 have gone EOL.
# So probably in like 2025.
remove_old_container_key() {
  local loopdev="$1"

  local rootfs_dir
  rootfs_dir=$(make_temp_dir)
  mount_loop_image_partition "${loopdev}" 3 "${rootfs_dir}"

  sudo rm -f "${rootfs_dir}/usr/share/misc/oci-container-key-pub.der"

  sudo umount "${rootfs_dir}"
}

# Re-sign Android image if exists.
resign_android_image_if_exists() {
  local loopdev="$1"

  local rootfs_dir
  rootfs_dir=$(make_temp_dir)
  mount_loop_image_partition "${loopdev}" 3 "${rootfs_dir}"

  local system_img
  system_img="$(echo "${rootfs_dir}"/opt/google/*/android/system.raw.img)"
  local arc_version
  arc_version=$(grep CHROMEOS_ARC_VERSION= \
    "${rootfs_dir}/etc/lsb-release" | cut -d= -f2)
  if [[ ! -e "${system_img}" || -z "${arc_version}" ]]; then
    info "ARC image not found.  Not signing Android APKs."
    sudo umount "${rootfs_dir}"
    return
  fi

  info "Found ARC image version '${arc_version}', re-signing APKs."
  "${SCRIPT_DIR}/sign_android_image.sh" "${rootfs_dir}" "${KEY_DIR}/android"

  if ! sudo umount "${rootfs_dir}"; then
    error "umount ${rootfs_dir} failed"
    sudo lsof -n "${rootfs_dir}"
    ps auxf
    return 1
  fi
  info "Re-signed Android image"
}

# Check whether the image's board is reven or not.
# Args: LOOPDEV
# Outputs: "true" if the board is reven, otherwise "false".
get_is_reven() {
  local loopdev="$1"
  local rootfs_dir
  local board

  rootfs_dir=$(make_temp_dir)
  mount_loop_image_partition "${loopdev}" 3 "${rootfs_dir}"

  board=$(get_board_from_lsb_release "${rootfs_dir}")

  sudo umount "${rootfs_dir}"

  # When run by the signer, the board name will look like
  # "reven-signed-mp-v2keys". Also accept plain "reven" for local
  # testing.
  if [[ "${board}" == "reven-signed"* || "${board}" == "reven" ]]; then
    echo "true"
  else
    echo "false"
  fi
}

# Sign UEFI binaries, if possible.
# Args: LOOPDEV IS_REVEN
sign_uefi_binaries() {
  local loopdev="$1"
  local is_reven="$2"
  local efi_glob="*.efi"

  if [[ ! -d "${KEY_DIR}/uefi" ]]; then
    return 0
  fi

  local esp_dir
  if ! esp_dir="$(mount_image_esp "${loopdev}")"; then
    error "Could not mount EFI partition for signing UEFI binaries"
    return 1
  elif [[ -z "${esp_dir}" ]]; then
    return 0
  fi
  if [[ "${is_reven}" == "false" ]]; then
    "${SCRIPT_DIR}/install_gsetup_certs.sh" "${esp_dir}" "${KEY_DIR}/uefi"
  else
    # b/205145491: the reven board's boot*.efi files are already signed,
    # change the glob so that they don't get resigned.
    efi_glob="grub*.efi"
  fi

  local sign_uefi_cmd=(
      "${SCRIPT_DIR}/sign_uefi.py"
      --private-key "${KEYCFG_UEFI_PRIVATE_KEY}"
      --sign-cert "${KEYCFG_UEFI_SIGN_CERT}"
      --verify-cert "${KEYCFG_UEFI_VERIFY_CERT}"
      --kernel-subkey-vbpubk "${KEYCFG_KERNEL_SUBKEY_VBPUBK}"
      --crdyshim-private-key "${KEYCFG_UEFI_CRDYSHIM_PRIVATE_KEY}"
      --efi-glob "${efi_glob}"
  )

  "${sign_uefi_cmd[@]}" --target-dir "${esp_dir}"
  sudo umount "${esp_dir}"

  local rootfs_dir
  rootfs_dir="$(make_temp_dir)"
  mount_loop_image_partition "${loopdev}" 3 "${rootfs_dir}"
  "${sign_uefi_cmd[@]}" --target-dir "${rootfs_dir}/boot"
  sudo umount "${rootfs_dir}"

  info "Signed UEFI binaries"
  return 0
}

# Verify the signatures of UEFI binaries.
# Args: LOOPDEV
verify_uefi_signatures() {
  local loopdev="$1"
  local succeeded=1

  if [[ ! -d "${KEY_DIR}/uefi" ]]; then
    return 0
  fi

  local esp_dir
  if ! esp_dir="$(mount_image_esp "${loopdev}")"; then
    error "Could not mount EFI partition for verifying UEFI signatures"
    return 1
  elif [[ -z "${esp_dir}" ]]; then
    return 0
  fi
  "${SCRIPT_DIR}/verify_uefi.sh" "${esp_dir}" "${esp_dir}" \
      "${KEY_DIR}/uefi" || succeeded=0

  local rootfs_dir
  rootfs_dir="$(make_temp_dir)"
  mount_loop_image_partition_ro "${loopdev}" 3 "${rootfs_dir}"
  "${SCRIPT_DIR}/verify_uefi.sh" "${rootfs_dir}/boot" "${esp_dir}" \
      "${KEY_DIR}/uefi" || succeeded=0
  sudo umount "${rootfs_dir}"

  sudo umount "${esp_dir}"

  if [[ "${succeeded}" == "0" ]]; then
    die "UEFI signature verification failed"
  fi
}

# Sign a GSC firmware image with the given keys.
# Args: CONTAINER KEY_DIR [OUTPUT_CONTAINER]
sign_gsc_firmware() {
  local image=$1
  local key_dir=$2
  local output=$3

  "${SCRIPT_DIR}/sign_gsc_firmware.sh" \
    "${image}" "${key_dir}" "${output}"
}

# Verify an image including rootfs hash using the specified keys.
verify_image() {
  local loopdev
  loopdev=$(loopback_partscan "${INPUT_IMAGE}")
  local loop_rootfs="${loopdev}p3"

  info "Verifying RootFS hash..."
  # What we get from image.
  local kernel_config
  # What we calculate from the rootfs.
  local new_kernel_config
  # Depending on the type of image, the verity parameters may
  # exist in either kernel partition 2 or kernel partition 4
  local partnum
  for partnum in 2 4; do
    info "Considering Kernel partition ${partnum}"
    kernel_config=$(sudo_futility dump_kernel_config \
      "${loopdev}p${partnum}")
    local hash_image
    hash_image=$(make_temp_file)
    if ! calculate_rootfs_hash "${loop_rootfs}" "${kernel_config}" \
      "${hash_image}"; then
      info "Trying next kernel partition."
      continue
    fi
    new_kernel_config="${CALCULATED_KERNEL_CONFIG}"
    break
  done

  # Note: If calculate_rootfs_hash succeeded above, these should
  # be non-empty.
  expected_hash=$(get_hash_from_config "${new_kernel_config}")
  got_hash=$(get_hash_from_config "${kernel_config}")

  if [ -z "${expected_hash}" ] || [ -z "${got_hash}" ]; then
    die "Couldn't verify RootFS hash on the image."
  fi

  if [ ! "${got_hash}" = "${expected_hash}" ]; then
    cat <<EOF
FAILED: RootFS hash is incorrect.
Expected: ${expected_hash}
Got: ${got_hash}
EOF
    exit 1
  else
    info "PASS: RootFS hash is correct (${expected_hash})"
  fi

  # Now try and verify kernel partition signature.
  set +e
  local try_key="${KEYCFG_RECOVERY_KEY_VBPUBK}"
  info "Testing key verification..."
  # The recovery key is only used in the recovery mode.
  echo -n "With Recovery Key (Recovery Mode ON, Dev Mode OFF): " && \
  { load_kernel_test "${INPUT_IMAGE}" "${try_key}" -b 2 >/dev/null 2>&1 && \
    echo "YES"; } || echo "NO"
  echo -n "With Recovery Key (Recovery Mode ON, Dev Mode ON): " && \
  { load_kernel_test "${INPUT_IMAGE}" "${try_key}" -b 3 >/dev/null 2>&1 && \
    echo "YES"; } || echo "NO"

  try_key="${KEYCFG_KERNEL_SUBKEY_VBPUBK}"
  # The SSD key is only used in non-recovery mode.
  echo -n "With SSD Key (Recovery Mode OFF, Dev Mode OFF): " && \
  { load_kernel_test "${INPUT_IMAGE}" "${try_key}" -b 0 >/dev/null 2>&1  && \
    echo "YES"; } || echo "NO"
  echo -n "With SSD Key (Recovery Mode OFF, Dev Mode ON): " && \
  { load_kernel_test "${INPUT_IMAGE}" "${try_key}" -b 1 >/dev/null 2>&1 && \
    echo "YES"; } || echo "NO"
  set -e

  verify_image_rootfs "${loop_rootfs}"

  verify_uefi_signatures "${INPUT_IMAGE}"

  # TODO(gauravsh): Check embedded firmware AU signatures.
}

# Re-calculate recovery kernel hash.
# Args: LOOPDEV RECOVERY_KERNEL_PARTITION KEYBLOCK PRIVKEY
update_recovery_kernel_hash() {
  local loopdev="$1"
  local recovery_kernel_partition="$2"
  local keyblock="$3"
  local privkey="$4"

  local loop_recovery_kernel="${loopdev}p${recovery_kernel_partition}"
  local loop_kernb="${loopdev}p4"

  # Update the kernel B hash in the recovery kernel command line.
  local old_kernel_config
  old_kernel_config="$(sudo_futility \
    dump_kernel_config "${loop_recovery_kernel}")"
  local old_kernb_hash
  old_kernb_hash="$(echo "${old_kernel_config}" |
    sed -nEe "s#.*kern_b_hash=([a-z0-9]*).*#\1#p")"
  local new_kernb_hash
  if [[ "${#old_kernb_hash}" -lt 64 ]]; then
    new_kernb_hash=$(sudo sha1sum "${loop_kernb}" | cut -f1 -d' ')
  else
    new_kernb_hash=$(sudo sha256sum "${loop_kernb}" | cut -f1 -d' ')
  fi

  new_kernel_config=$(make_temp_file)
  # shellcheck disable=SC2001
  echo "${old_kernel_config}" |
    sed -e "s#\(kern_b_hash=\)[a-z0-9]*#\1${new_kernb_hash}#" \
      > "${new_kernel_config}"
  info "New config for kernel partition ${recovery_kernel_partition} is"
  cat "${new_kernel_config}"

  # Re-calculate kernel partition signature and command line.
  sudo_futility vbutil_kernel --repack "${loop_recovery_kernel}" \
    --keyblock "${keyblock}" \
    --signprivate "${privkey}" \
    --version "${KERNEL_VERSION}" \
    --oldblob "${loop_recovery_kernel}" \
    --config "${new_kernel_config}"
}

# Resign a single miniOS kernel partition.
# Args: LOOP_MINIOS KEYBLOCK PRIVKEY
resign_minios_kernel() {
  local loop_minios="$1"
  local keyblock="$2"
  local priv_key="$3"

  if sudo_futility dump_kernel_config "${loop_minios}"; then
    # Delay checking that keyblock exists until we are certain of a valid miniOS
    # partition. Images that don't support miniOS might not provide these.
    # (This check is repeated twice, but that's okay.)
    # Update (9/3/24): we no longer check if the private key exists on disk
    # because it may live in Cloud KMS instead, opting instead to let futility
    # below fail if the key is missing.
    if [[ ! -e "${keyblock}" ]]; then
      error "Resign miniOS: keyblock doesn't exist: ${keyblock}"
      return 1
    fi

    # Assume this is a miniOS kernel.
    local minios_kernel_version=$((KERNEL_VERSION >> 24))
    if sudo_futility vbutil_kernel --repack "${loop_minios}" \
        --keyblock "${keyblock}" \
        --signprivate "${priv_key}" \
        --version "${minios_kernel_version}" \
        --oldblob "${loop_minios}"; then
      echo
      info "Resign miniOS ${loop_minios}: done"
    else
      error "Resign miniOS ${loop_minios}: failed"
      return 1
    fi
  else
    info "Skipping empty miniOS partition ${loop_minios}."
  fi
}

# Get the partition type of the loop device.
get_partition_type() {
  local loopdev=$1
  local device=$2
  # Prefer cgpt, fall back on lsblk.
  if command -v cgpt &> /dev/null; then
    echo "$(cgpt show -i "${device}" -t "${loopdev}")"
  else
    echo "$(sudo lsblk -rnb -o PARTTYPE "${loopdev}p${device}")"
  fi
}

# Re-sign miniOS kernels with new keys.
# Args: LOOPDEV MINIOS_A_KEYBLOCK MINIOS_B_KEYBLOCK PRIVKEY
resign_minios_kernels() {
  local loopdev="$1"
  local minios_a_keyblock="$2"
  local minios_b_keyblock="$3"
  local priv_key="$4"

  info "Searching for miniOS kernels to resign..."

  # Attempt to sign miniOS A and miniOS B partitions, one at a time.
  # miniOS A - loop device 9.
  local loop_minios_a="${loopdev}p9"
  local part_type_a
  part_type_a="$(get_partition_type "${loopdev}" 9)"
  # miniOS B - loop device 10.
  local loop_minios_b="${loopdev}p10"
  local part_type_b
  part_type_b="$(get_partition_type "${loopdev}" 10)"

  # Make sure the loop devices have a miniOS partition type.
  if [[ "${part_type_a^^}" == "${MINIOS_KERNEL_GUID}" ]]; then
    if ! resign_minios_kernel "${loop_minios_a}" "${minios_a_keyblock}" "${priv_key}"; then
      return 1
    fi
  fi
  if [[ "${part_type_b^^}" == "${MINIOS_KERNEL_GUID}" ]]; then
    if ! resign_minios_kernel "${loop_minios_b}" "${minios_b_keyblock}" "${priv_key}"; then
      return 1
    fi
  fi
}

# Update the legacy bootloader templates in EFI partition if available.
# Args: LOOPDEV KERNEL
update_legacy_bootloader() {
  local loopdev="$1"
  local loop_kern="$2"

  local esp_dir
  if ! esp_dir="$(mount_image_esp "${loopdev}")"; then
    error "Could not mount EFI partition for updating legacy bootloader cfg."
    return 1
  elif [[ -z "${esp_dir}" ]]; then
    info "Not updating legacy bootloader configs: ${loopdev}"
    return 0
  fi

  # If we can't find the dm parameter in the kernel config, bail out now.
  local kernel_config
  kernel_config=$(sudo_futility dump_kernel_config "${loop_kern}")
  local root_hexdigest
  root_hexdigest="$(get_hash_from_config "${kernel_config}")"
  if [[ -z "${root_hexdigest}" ]]; then
    error "Couldn't grab root_digest from kernel partition ${loop_kern}"
    error " (config: ${kernel_config})"
    return 1
  fi
  # Update syslinux configs for legacy BIOS systems.
  if [[ -d "${esp_dir}/syslinux" ]]; then
    local cfg=("${esp_dir}"/syslinux/*.cfg)
    if ! sudo sed -i -r \
      "s/\broot_hexdigest=[a-z0-9]+/root_hexdigest=${root_hexdigest}/g" \
      "${cfg[@]}"; then
        error "Updating syslinux configs failed: '${cfg[*]}'"
        return 1
    fi
  fi
  # Update grub configs for EFI systems.
  local grub_cfg="${esp_dir}/efi/boot/grub.cfg"
  if [[ -f "${grub_cfg}" ]]; then
    if ! sudo sed -i -r \
      "s/\broot_hexdigest=[a-z0-9]+/root_hexdigest=${root_hexdigest}/g" \
      "${grub_cfg}"; then
        error "Updating grub config failed: '${grub_cfg}'"
        return 1
    fi
  fi
}

# Sign an image file with proper keys.
# Args: IMAGE_TYPE INPUT OUTPUT DM_PARTNO KERN_A_KEYBLOCK KERN_A_PRIVKEY \
#       KERN_B_KEYBLOCK KERN_B_PRIVKEY KERN_C_KEYBLOCK KERN_C_PRIVKEY \
#       MINIOS_KEYBLOCK MINIOS_KEYBLOCK_V1 MINIOS_PRIVKEY
#
# A ChromiumOS image file (INPUT) always contains 2 partitions (kernel A & B).
# This function will rebuild hash data by DM_PARTNO, resign kernel partitions by
# their KEYBLOCK and PRIVKEY files, and then write to OUTPUT file. Note some
# special images (specified by IMAGE_TYPE, like 'recovery' or 'factory_install')
# may have additional steps (ex, tweaking verity hash or not stripping files)
# when generating output file.
# Some recovery images also have a kernel C, which is identical to kernel A,
# but signed with a different key (see b/266502803).
sign_image_file() {
  local image_type="$1"
  local input="$2"
  local output="$3"
  local dm_partno="$4"
  local kernA_keyblock="$5"
  local kernA_privkey="$6"
  local kernB_keyblock="$7"
  local kernB_privkey="$8"
  local kernC_keyblock="$9"
  local kernC_privkey="${10}"
  local minios_keyblock="${11}"
  local minios_keyblock_v1="${12}"
  local minios_privkey="${13}"

  info "Preparing ${image_type} image..."
  cp --sparse=always "${input}" "${output}"

  local loopdev
  loopdev=$(loopback_partscan "${output}")
  local loop_kern="${loopdev}p${dm_partno}"
  local loop_rootfs="${loopdev}p3"
  local is_reven
  is_reven=$(get_is_reven "${loopdev}")

  # b/266502803: Some devices have a second recovery key which is used to sign:
  # - a second recovery kernel KERN-C in recovery images
  # - a second installer kernel KERN-B in factory images
  # If a device does not have a second recovery key, then these additional
  # kernels are not signed. If they are present, they will remain in the image
  # signed with dev keys.
  #
  # Sign KERN-B unless it's a factory image and this device doesn't have a
  # second recovery key.
  local should_sign_kernB="true"
  if [[ "${image_type}" == "factory_install" &&
        ! -f "${kernB_keyblock}" ]]; then
    should_sign_kernB="false"
  fi
  # Sign KERN-C unless this image type doesn't have KERN-C, or it's a
  # recovery image and this device doesn't have a second recovery key.
  local should_sign_kernC="true"
  if [[ -z "${kernC_keyblock}" ||
        ( "${image_type}" == "recovery" && ! -f "${kernC_keyblock}" ) ]]; then
    should_sign_kernC="false"
  fi

  # The reven board needs to produce recovery images since some
  # downstream tools (e.g. the Chromebook Recovery Utility) expect
  # them. However, reven's recovery images are not like other boards
  # since reven is installed on generic PC hardware, and "recovery"
  # actually means reinstalling.
  #
  # Installation occurs via liveboot, which loads the 'A' partitions.
  # The UEFI bootloader expects the kernel partition to be signed with
  # the normal board key, not the recovery key, so for reven we sign
  # recovery images like base images: using the non-recovery key for
  # both the 'A' and 'B' partitions.
  local sign_recovery_like_base="${is_reven}"

  if [[ "${image_type}" == "recovery" &&
        "${sign_recovery_like_base}" == "true" ]]; then
    kernA_keyblock="${kernB_keyblock}"
    kernA_privkey="${kernB_privkey}"
  fi

  resign_firmware_payload "${loopdev}"
  remove_old_container_key "${loopdev}"
  resign_android_image_if_exists "${loopdev}"
  sign_uefi_binaries "${loopdev}" "${is_reven}"
  # We do NOT strip /boot for factory installer, since some devices need it to
  # boot EFI. crbug.com/260512 would obsolete this requirement.
  #
  # We also do NOT strip /boot for legacy BIOS or EFI devices.  This is because
  # "cros_installer postinst" on BIOS or EFI systems relies on presence of
  # /boot in rootfs to update kernel.  We infer the BIOS type from the kernel
  # config.
  local loop_kerna="${loopdev}p2"
  local kerna_config
  kerna_config="$(sudo_futility dump_kernel_config "${loop_kerna}")"
  if [[ "${image_type}" != "factory_install" &&
        " ${kerna_config} " != *" cros_legacy "* &&
        " ${kerna_config} " != *" cros_efi "* ]]; then
    "${SCRIPT_DIR}/strip_boot_from_image.sh" --image "${loop_rootfs}"
  fi
  update_rootfs_hash "${loopdev}" "${loop_kern}" \
    "${kernA_keyblock}" "${kernA_privkey}" \
    "${kernB_keyblock}" "${kernB_privkey}" "${should_sign_kernB}" \
    "${kernC_keyblock}" "${kernC_privkey}" "${should_sign_kernC}"
  update_stateful_partition_vblock "${loopdev}"
  if [[ "${image_type}" == "recovery" &&
        "${sign_recovery_like_base}" == "false" ]]; then
    update_recovery_kernel_hash "${loopdev}" 2 "${kernA_keyblock}" \
      "${kernA_privkey}"
    if [[ "${should_sign_kernC}" == "true" ]]; then
      update_recovery_kernel_hash "${loopdev}" 6 "${kernC_keyblock}" \
        "${kernC_privkey}"
    fi
  fi

  if [[ -n "${minios_keyblock}" ]]; then
    # b/266502803: If it's a recovery image and minios_kernel.v1.keyblock
    # exists, sign MINIOS-A with minios_kernel.v1.keyblock and MINIOS-B with
    # minios_kernel.keyblock. Otherwise, sign both with minios_kernel.keyblock.
    local miniosA_keyblock="${minios_keyblock}"
    local miniosB_keyblock="${minios_keyblock}"
    if [[ -f "${minios_keyblock_v1}" ]]; then
      miniosA_keyblock="${minios_keyblock_v1}"
    fi

    if ! resign_minios_kernels "${loopdev}" "${miniosA_keyblock}" \
        "${miniosB_keyblock}" "${minios_privkey}"; then
      return 1
    fi
  fi

  if ! update_legacy_bootloader "${loopdev}" "${loop_kern}"; then
    # Error is already logged.
    return 1
  fi
  info "Signed ${image_type} image output to ${output}"
}

# Sign a UEFI kernel kernel image with proper keys.
# Args: INPUT OUTPUT
sign_uefi_kernel() {
  local input="$1"
  local output="$2"

  info "Preparing UEFI kernel image..."
  cp --sparse=always "${input}" "${output}"

  "${SCRIPT_DIR}/sign_uefi.py" \
    --target-file "${output}" \
    --private-key "${KEYCFG_UEFI_PRIVATE_KEY}" \
    --sign-cert "${KEYCFG_UEFI_SIGN_CERT}" \
    --verify-cert "${KEYCFG_UEFI_VERIFY_CERT}" \
    --kernel-subkey-vbpubk "${KEYCFG_KERNEL_SUBKEY_VBPUBK}" \
    --crdyshim-private-key "${KEYCFG_UEFI_CRDYSHIM_PRIVATE_KEY}"
}

main() {
  # Add to the path since some tools reside here and may not be in the non-root
  # system path.
  PATH+=:/usr/sbin:/sbin

  # Make sure the tools we need are available.
  local prereqs
  for prereqs in ${FUTILITY} verity load_kernel_test dumpe2fs e2fsck sha1sum; do
    type -P "${prereqs}" &>/dev/null || \
      die "${prereqs} tool not found."
  done

  # Parse arguments with positional and optional options.
  local script_args=()
  FUTILITY_EXTRA_FLAGS=""
  while [[ "$#" -gt 0 ]]; do
    case $1 in
      --debug)
        FUTILITY_EXTRA_FLAGS+="--debug "
        ;;
      -h|--help)
        usage
        ;;
      --)
        shift
        break
        ;;
      -*)
        usage "Unknown option: $1"
        ;;
      *)
        script_args+=("$1")
        ;;
    esac
    shift
  done

  set -- "${script_args[@]}"

  TYPE=$1
  INPUT_IMAGE=$2
  KEY_DIR=$3
  OUTPUT_IMAGE=$4
  VERSION_FILE=$5

  setup_keycfg "${KEY_DIR}"

  # Verification
  case ${TYPE} in
  dump_config)
    check_argc $# 2
    loopdev=$(loopback_partscan "${INPUT_IMAGE}")
    for partnum in 2 4; do
      info "kernel config in partition number ${partnum}:"
      sudo_futility dump_kernel_config "${loopdev}p${partnum}"
      echo
    done
    exit 0
    ;;
  verify)
    check_argc $# 2
    verify_image
    exit 0
    ;;
  *)
    # All other signing commands take 4 to 5 args.
    if [ -z "${OUTPUT_IMAGE}" ]; then
      # Friendlier message.
      usage "Missing output image name"
    fi
    check_argc $# 4 5
    ;;
  esac

  # If a version file was specified, read the firmware and kernel
  # versions from there.
  if [ -n "${VERSION_FILE}" ]; then
    FIRMWARE_VERSION=$(sed -n 's#^firmware_version=\(.*\)#\1#pg' \
      "${VERSION_FILE}")
    KERNEL_VERSION=$(sed -n 's#^kernel_version=\(.*\)#\1#pg' "${VERSION_FILE}")
  fi
  info "Using firmware version: ${FIRMWARE_VERSION}"
  info "Using kernel version: ${KERNEL_VERSION}"

  # Make all modifications on output copy.
  if [[ "${TYPE}" == "base" ]]; then
    sign_image_file "base" "${INPUT_IMAGE}" "${OUTPUT_IMAGE}" 2 \
      "${KEYCFG_KERNEL_KEYBLOCK}" \
      "${KEYCFG_KERNEL_VBPRIVK}" \
      "${KEYCFG_KERNEL_KEYBLOCK}" \
      "${KEYCFG_KERNEL_VBPRIVK}" \
      "" \
      "" \
      "${KEYCFG_MINIOS_KERNEL_KEYBLOCK}" \
      "" \
      "${KEYCFG_MINIOS_KERNEL_VBPRIVK}"
  elif [[ "${TYPE}" == "recovery" ]]; then
    sign_image_file "recovery" "${INPUT_IMAGE}" "${OUTPUT_IMAGE}" 4 \
      "${KEYCFG_RECOVERY_KERNEL_KEYBLOCK}" \
      "${KEYCFG_RECOVERY_KERNEL_VBPRIVK}" \
      "${KEYCFG_KERNEL_KEYBLOCK}" \
      "${KEYCFG_KERNEL_VBPRIVK}" \
      "${KEYCFG_RECOVERY_KERNEL_V1_KEYBLOCK}" \
      "${KEYCFG_RECOVERY_KERNEL_VBPRIVK}" \
      "${KEYCFG_MINIOS_KERNEL_KEYBLOCK}" \
      "${KEYCFG_MINIOS_KERNEL_V1_KEYBLOCK}" \
      "${KEYCFG_MINIOS_KERNEL_VBPRIVK}"
  elif [[ "${TYPE}" == "factory" ]]; then
    sign_image_file "factory_install" "${INPUT_IMAGE}" "${OUTPUT_IMAGE}" 2 \
      "${KEYCFG_INSTALLER_KERNEL_KEYBLOCK}" \
      "${KEYCFG_INSTALLER_KERNEL_VBPRIVK}" \
      "${KEYCFG_INSTALLER_KERNEL_V1_KEYBLOCK}" \
      "${KEYCFG_INSTALLER_KERNEL_VBPRIVK}" \
      "" \
      "" \
      "" \
      "" \
      ""
  elif [[ "${TYPE}" == "firmware" ]]; then
    if [[ -e "${KEY_DIR}/loem.ini" ]]; then
      die "LOEM signing not implemented yet for firmware images"
    fi
    cp "${INPUT_IMAGE}" "${OUTPUT_IMAGE}"
    sign_firmware "${OUTPUT_IMAGE}" "${KEY_DIR}" "${FIRMWARE_VERSION}"
  elif [[ "${TYPE}" == "shellball" ]]; then
    cp "${INPUT_IMAGE}" "${OUTPUT_IMAGE}"
    resign_firmware_shellball "${OUTPUT_IMAGE}"
    info "Signed firmware shellball ${OUTPUT_IMAGE}"
  elif [[ "${TYPE}" == "update_payload" ]]; then
    sign_update_payload "${INPUT_IMAGE}" "${KEYCFG_UPDATE_KEY_PEM}" "${OUTPUT_IMAGE}"
  elif [[ "${TYPE}" == "accessory_usbpd" ]]; then
    KEY_NAME="${KEY_DIR}/key_$(basename "$(dirname "${INPUT_IMAGE}")")"
    if [[ ! -e "${KEY_NAME}.pem" ]]; then
      KEY_NAME="${KEY_DIR}/key"
    fi
    cp "${INPUT_IMAGE}" "${OUTPUT_IMAGE}"
    do_futility sign --type usbpd1 --pem "${KEY_NAME}.pem" "${OUTPUT_IMAGE}"
  elif [[ "${TYPE}" == "accessory_rwsig" ]]; then
    # If KEYCFG_ACCESSORY_RWSIG_VBPRIK2 is non-empty, use it.
    if [[ -n "${KEYCFG_ACCESSORY_RWSIG_VBPRIK2}" ]]; then
      PRIV_KEY="${KEYCFG_ACCESSORY_RWSIG_VBPRIK2}"
    # If one key is present in this container, assume it's the right one.
    # See crbug.com/863464
    else
      shopt -s nullglob
      KEYS=( "${KEY_DIR}"/*.vbprik2 )
      shopt -u nullglob
      if [[ ${#KEYS[@]} -eq 1 ]]; then
        PRIV_KEY="${KEYS[0]}"
      else
        die "Expected exactly one key present in keyset for accessory_rwsig"
      fi
    fi
    cp "${INPUT_IMAGE}" "${OUTPUT_IMAGE}"
    do_futility sign --type rwsig --prikey "${PRIV_KEY}" \
             --version "${FIRMWARE_VERSION}" "${OUTPUT_IMAGE}"
  elif [[ "${TYPE}" == "gsc_firmware" ]]; then
    sign_gsc_firmware "${INPUT_IMAGE}" "${KEY_DIR}" "${OUTPUT_IMAGE}"
  elif [[ "${TYPE}" == "hps_firmware" ]]; then
    hps-sign-rom --input "${INPUT_IMAGE}" --output "${OUTPUT_IMAGE}" \
      --private-key "${KEY_DIR}/key_hps.priv.pem"
  elif [[ "${TYPE}" == "uefi_kernel" ]]; then
      sign_uefi_kernel "${INPUT_IMAGE}" "${OUTPUT_IMAGE}"
  elif [[ "${TYPE}" == "recovery_kernel" ]]; then
    cp "${INPUT_IMAGE}" "${OUTPUT_IMAGE}"
    if [[ -f "${KEYCFG_RECOVERY_KERNEL_V1_KEYBLOCK}" ]]; then
      local output_image_v1="${OUTPUT_IMAGE}${V1_SUFFIX}"
      cp "${OUTPUT_IMAGE}" "${output_image_v1}"
      do_futility sign -b "${KEYCFG_RECOVERY_KERNEL_V1_KEYBLOCK}" -s \
        "${KEYCFG_RECOVERY_KERNEL_VBPRIVK}" "${output_image_v1}"
    fi
    do_futility sign -b "${KEYCFG_RECOVERY_KERNEL_KEYBLOCK}" -s \
      "${KEYCFG_RECOVERY_KERNEL_VBPRIVK}" "${OUTPUT_IMAGE}"
  else
    die "Invalid type ${TYPE}"
  fi
}
main "$@"
