#!/bin/bash
# Copyright 2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Generate .vbpubk and .vbprivk pairs for use by developer builds. These should
# be exactly like the real keys except that the private keys aren't secret.

# Load common constants and functions.
# shellcheck source=common.sh
. "$(dirname "$0")/common.sh"

usage() {
  cat <<EOF
Usage: ${PROG} [options]

Options:
  --android              Also generate android keys
  --uefi                 Also generate UEFI keys
  --8k                   Use 8k keys instead of 4k (enables options below)
  --8k-root              Use 8k key size for the root key
  --8k-recovery          Use 8k key size for the recovery key
  --8k-recovery-kernel   Use 8k key size for the recovery kernel data
  --8k-installer-kernel  Use 8k key size for the installer kernel data
  --key-name <name>      Name of the keyset (for key.versions)
  --output <dir>         Where to write the keys (default is cwd)
  --arv-root-path <dir>  Path to AP RO verificaton root key directory,
                         defaults to ./${ARV_ROOT_DIR}
  --arv-root-uri <uri>   URI to remote AP RO verification root key (stored in
                         GCP, accessed using CloudKMS).
EOF

  if [[ $# -ne 0 ]]; then
    die "unknown option $*"
  else
    exit 0
  fi
}

main() {
  set -e

  local android_keys="false"
  local uefi_keys="false"
  local root_key_algoid=${ROOT_KEY_ALGOID}
  local recovery_key_algoid=${RECOVERY_KEY_ALGOID}
  local recovery_kernel_algoid=${RECOVERY_KERNEL_ALGOID}
  local minios_kernel_algoid=${MINIOS_KERNEL_ALGOID}
  local installer_kernel_algoid=${INSTALLER_KERNEL_ALGOID}
  local keyname
  local output_dir="${PWD}" setperms="false"
  local arv_root_path=""
  local arv_root_uri=""

  while [[ $# -gt 0 ]]; do
    case $1 in
    --android)
      echo "Will also generate Android keys."
      android_keys="true"
      ;;

    --uefi)
      echo "Will also generate UEFI keys."
      uefi_keys="true"
      ;;

    --8k)
      root_key_algoid=${RSA8192_SHA512_ALGOID}
      recovery_key_algoid=${RSA8192_SHA512_ALGOID}
      recovery_kernel_algoid=${RSA8192_SHA512_ALGOID}
      installer_kernel_algoid=${RSA8192_SHA512_ALGOID}
      ;;
    --8k-root)
      root_key_algoid=${RSA8192_SHA512_ALGOID}
      ;;
    --8k-recovery)
      recovery_key_algoid=${RSA8192_SHA512_ALGOID}
      ;;
    --8k-recovery-kernel)
      recovery_kernel_algoid=${RSA8192_SHA512_ALGOID}
      ;;
    --8k-installer-kernel)
      installer_kernel_algoid=${RSA8192_SHA512_ALGOID}
      ;;

    --4k)
      root_key_algoid=${RSA4096_SHA512_ALGOID}
      recovery_key_algoid=${RSA4096_SHA512_ALGOID}
      recovery_kernel_algoid=${RSA4096_SHA512_ALGOID}
      installer_kernel_algoid=${RSA4096_SHA512_ALGOID}
      ;;
    --4k-root)
      root_key_algoid=${RSA4096_SHA512_ALGOID}
      ;;
    --4k-recovery)
      recovery_key_algoid=${RSA4096_SHA512_ALGOID}
      ;;
    --4k-recovery-kernel)
      recovery_kernel_algoid=${RSA4096_SHA512_ALGOID}
      ;;
    --4k-installer-kernel)
      installer_kernel_algoid=${RSA4096_SHA512_ALGOID}
      ;;

    --arv-root-path)
      arv_root_path="$(readlink -f "$2")"
      shift
      ;;
    --arv-root-uri)
      arv_root_uri="$2"
      shift
      ;;

    --key-name)
      keyname="$2"
      shift
      ;;

    --output)
      output_dir="$2"
      setperms="true"
      if [[ -d "${output_dir}" ]]; then
        die "output dir (${output_dir}) already exists"
      fi
      shift
      ;;

    -h|--help)
      usage
      ;;
    *)
      usage "$1"
      ;;
    esac
    shift
  done

  mkdir -p "${output_dir}"
  cd "${output_dir}"
  if [[ "${setperms}" == "true" ]]; then
    chmod 700 .
  fi

  if [[ -z "${arv_root_uri}" ]]; then
    if [[ -z "${arv_root_path}" ]]; then
      # If not explicitly set, expect AP RO verification root key directory one
      # level above the output directory where the specific board keys are going
      # to be placed.
      arv_root_path="$(readlink -f "../${ARV_ROOT_DIR}")"
    fi

    if [[ ! -d "${arv_root_path}" ]]; then
      die "AP RO root key directory \"${arv_root_path}\" not found." \
          "Run make_arv_root.sh to create it or specify --arv-root-path."
      exit 1
    fi
  fi

  if [[ ! -e "${VERSION_FILE}" ]]; then
    echo "No version file found. Creating default ${VERSION_FILE}."
    (
      if [[ -n "${keyname}" ]]; then
        echo "name=${keyname}"
      fi
      printf '%s_version=1\n' {firmware,kernel}{_key,}
    ) > "${VERSION_FILE}"
  fi

  local fkey_version ksubkey_version kdatakey_version

  # Get the key versions for normal keypairs
  fkey_version=$(get_version "firmware_key_version")
  # Firmware version is the kernel subkey version.
  ksubkey_version=$(get_version "firmware_version")
  # Kernel data key version is the kernel key version.
  kdatakey_version=$(get_version "kernel_key_version")

  # Create the normal keypairs
  make_pair root_key                 ${root_key_algoid}
  make_pair firmware_data_key        ${FIRMWARE_DATAKEY_ALGOID} ${fkey_version}
  make_pair kernel_subkey            ${KERNEL_SUBKEY_ALGOID} ${ksubkey_version}
  make_pair kernel_data_key          ${KERNEL_DATAKEY_ALGOID} ${kdatakey_version}

  # Create the recovery and factory installer keypairs
  make_pair recovery_key             ${recovery_key_algoid}
  make_pair recovery_kernel_data_key ${recovery_kernel_algoid}
  make_pair minios_kernel_data_key   ${minios_kernel_algoid}
  make_pair installer_kernel_data_key ${installer_kernel_algoid}
  make_pair arv_platform "${ARV_PLATFORM_ALGOID}"

  # Make sure there is a copy of the AP RO
  # verification root public key in the keyset directory.
  cp "${arv_root_path}/${ARV_ROOT_NAME_BASE}.vbpubk" .

  # Create the firmware keyblock for use only in Normal mode. This is redundant,
  # since it's never even checked during Recovery mode.
  make_keyblock firmware ${FIRMWARE_KEYBLOCK_MODE} firmware_data_key root_key

  # Create the recovery kernel keyblock for use only in Recovery mode.
  make_keyblock recovery_kernel ${RECOVERY_KERNEL_KEYBLOCK_MODE} recovery_kernel_data_key recovery_key

  # Create the miniOS kernel keyblock for use only in miniOS mode.
  make_keyblock minios_kernel ${MINIOS_KERNEL_KEYBLOCK_MODE} minios_kernel_data_key recovery_key

  # Create the normal kernel keyblock for use only in Normal mode.
  make_keyblock kernel ${KERNEL_KEYBLOCK_MODE} kernel_data_key kernel_subkey

  # Create the installer keyblock for use in Developer + Recovery mode
  # For use in Factory Install and Developer Mode install shims.
  make_keyblock installer_kernel ${INSTALLER_KERNEL_KEYBLOCK_MODE} installer_kernel_data_key recovery_key

  # Create AP RO verification platform keyblock.
  make_keyblock arv_platform "${ARV_KEYBLOCK_MODE}" arv_platform \
                "${arv_root_path}/${ARV_ROOT_NAME_BASE}" "${arv_root_uri}"

  # Copy AP RO verification root public key into the output directory, it is
  # necessary for AP RO verification signing.
  cp "${arv_root_path}/arv_root.vbpubk" . ||  die "Failed to copy"

  if [[ "${android_keys}" == "true" ]]; then
    mkdir android
    "${SCRIPT_DIR}"/create_new_android_keys.sh android
  fi

  if [[ "${uefi_keys}" == "true" ]]; then
    mkdir -p uefi
    "${SCRIPT_DIR}"/uefi/create_new_crdyshim_key.sh uefi
    "${SCRIPT_DIR}"/uefi/create_new_uefi_keys.sh --output uefi
  fi

  if [[ "${setperms}" == "true" ]]; then
    find -type f -exec chmod 400 {} +
    find -type d -exec chmod 500 {} +
  fi

  # CAUTION: The public parts of most of these blobs must be compiled into the
  # firmware, which is built separately (and some of which can't be changed after
  # manufacturing). If you update these keys, you must coordinate the changes
  # with the BIOS people or you'll be unable to boot the resulting images.
}
main "$@"
