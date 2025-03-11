#!/bin/bash

# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

. "$(dirname "$0")/common.sh"
. "$(dirname "$0")/lib/sign_android_lib.sh"
load_shflags || exit 1
SCRIPT_DIR="${SCRIPT_DIR:-$(dirname "$0")}"

DEFINE_boolean use_apksigner "${FLAGS_FALSE}" \
  "Use apksigner instead of signapk for APK signing"

FLAGS_HELP="
Usage: $PROG /path/to/cros_root_fs/dir /path/to/keys/dir [--use_apksigner]

Re-sign framework apks in an Android system image.  The image itself does not
need to be signed since it is shipped with Chrome OS image, which is already
signed.

Android has many ``framework apks'' that are signed with different framework
keys, depends on the purpose of the apk.  During development, apks are signed
with the debug one.  This script is to re-sign those apks with corresponding
release key.  It also handles some of the consequences of the key changes, such
as sepolicy update.
It can also sign using cloud kms keys based on env variables present for it.
"

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

set -e

# Re-sign framework apks with the corresponding release keys.  Only apk with
# known key fingerprint are re-signed.  We should not re-sign non-framework
# apks.
sign_framework_apks() {
  local system_mnt="$1"
  local key_dir="$2"
  local working_dir="$3"
  local flavor_prop=""
  local keyset=""

  # Generate key config directory.
  local gen_key_config_dir
  gen_key_config_dir="$(make_temp_dir)"
  local gcloud_provider_class="sun.security.pkcs11.SunPKCS11"

  if [[ -n ${KEYCFG_ANDROID_CLOUD_KEY_PREFIX} ]]; then
    info "Using cloud signing as cloud key prefix is present."

    if [[ "${FLAGS_use_apksigner}" == "${FLAGS_FALSE}" ]]; then
      die "use_apksigner flag is required when using gcloud to sign."
    fi

    # Generate config file needed for gcloud to run the KMS signing.
    if ! "${SCRIPT_DIR}/lib/generate_android_cloud_config.py" \
      -o="${gen_key_config_dir}/";
    then
      die "Unable to generate config for cloud signing, exiting."
    fi
  fi

  if ! flavor_prop=$(android_get_build_flavor_prop \
    "${system_mnt}/system/build.prop"); then
    die "Failed to extract build flavor property from \
'${system_mnt}/system/build.prop'."
  fi
  info "Found build flavor property '${flavor_prop}'."
  if ! keyset=$(android_choose_signing_keyset "${flavor_prop}"); then
    die "Unknown build flavor property '${flavor_prop}'."
  fi
  info "Expecting signing keyset '${keyset}'."

  if [[ "${FLAGS_use_apksigner}" == "${FLAGS_FALSE}" ]]; then
    info "Using signapk to sign the Framework apk's."
  else
    info "Using apksigner to sign the Framework apk's."
  fi

  if ! image_content_integrity_check "${system_mnt}" "${working_dir}" \
                                     "Prepare apks signing"; then
    return 1
  fi

  # Counters for validity check.
  local counter_platform=0
  local counter_media=0
  local counter_shared=0
  local counter_releasekey=0
  local counter_networkstack=0
  local counter_total=0

  local apk
  while read -d $'\0' -r apk; do
    local sha1=""
    local keyname=""

    sha1=$(unzip -p "${apk}" META-INF/CERT.RSA | \
      keytool -printcert | awk '/^\s*SHA1:/ {print $2}')

    if  ! keyname=$(android_choose_key "${sha1}" "${keyset}"); then
      die "Failed to choose signing key for APK '${apk}' (SHA1 '${sha1}') in \
build flavor '${flavor_prop}'."
    fi
    if [[ -z "${keyname}" ]]; then
      continue
    fi

    info "Re-signing (${keyname}) ${apk}"

    local temp_dir="$(make_temp_dir)"
    local temp_apk="${temp_dir}/temp.apk"
    local signed_apk="${temp_dir}/signed.apk"

    # Follow the standard manual signing process.  See
    # https://developer.android.com/studio/publish/app-signing.html.
    cp -a "${apk}" "${temp_apk}"
    # Explicitly remove existing signature.
    zip -q "${temp_apk}" -d "META-INF/*"

    if [ "${FLAGS_use_apksigner}" = "$FLAGS_FALSE" ]; then
      # Signapk now creates signature of APK Signature Scheme v2. No further APK
      # changes should happen afterward.  Also note that signapk now takes care
      # of zipalign.
      signapk "${key_dir}/$keyname.x509.pem" "${key_dir}/$keyname.pk8" \
          "${temp_apk}" "${signed_apk}" > /dev/null
    else
      # Key rotation: old key can sign a new key and generate a lineage file.
      # Provided the lineage file, Android P can honor the new key. Lineage file
      # can be generated similar to the following command:
      #
      # apksigner rotate --out media.lineage --old-signer --key old-media.pk8
      # --cert old-media.x509.pem --new-signer --key new-media.pk8 --cert
      # new-media.x509.pem

      local extra_flags
      local lineage_file="${key_dir}/${keyname}.lineage"
      local apksigner_min_sdk_version=28
      local temp_zipaligned_apk="${temp_dir}/temp_zipaligned.apk"

      # If using apksigner zipalign needs to be done before signing.
      if ! zipalign -p -f 4 "${temp_apk}" "${temp_zipaligned_apk}"; then
        die "Zipalign failed to align the apk."
      fi

      if [[ -f ${lineage_file} ]]; then
        extra_flags="--lineage ${lineage_file}"
      fi

      if [[ -n ${KEYCFG_ANDROID_CLOUD_KEY_PREFIX} ]]; then
        KMS_PKCS11_CONFIG="${key_dir}/${keyname}_config.yaml" \
          apksigner sign --v3-signing-enabled true \
          --min-sdk-version="${apksigner_min_sdk_version}" \
          --provider-class "${gcloud_provider_class}" \
          --provider-arg "${gen_key_config_dir}/pkcs11_java.cfg" --ks "NONE" \
          --ks-type "PKCS11" \
          --ks-key-alias "${KEYCFG_ANDROID_CLOUD_KEY_PREFIX}${keyname}" \
          --ks-pass pass:\"\" \
          --in "${temp_zipaligned_apk}" --out "${signed_apk}"  \
          ${extra_flags}
      else
        # b/349826228: explicitly disabling v1/v2 signing due to lineage error
        apksigner sign --key "${key_dir}/${keyname}.pk8" \
          --cert "${key_dir}/${keyname}.x509.pem" \
          --v1-signing-enabled false --v2-signing-enabled false \
          --in "${temp_zipaligned_apk}" --out "${signed_apk}" \
          ${extra_flags}
      fi
    fi
    if ! image_content_integrity_check "${system_mnt}" "${working_dir}" \
                                       "sign apk ${signed_apk}"; then
      return 1
    fi

    # Copy the content instead of mv to avoid owner/mode changes.
    #TODO(b/331944273): Fail when copy of apk fails.
    sudo cp "${signed_apk}" "${apk}" && rm -f "${signed_apk}"

    # Set timestamp rounded to second since squash file system has resolution
    # in seconds. Required in order for the packages cache generator output is
    # compatible with the packed file system.
    sudo touch "${apk}" -t "$(date +%m%d%H%M.%S)"

    : $(( counter_${keyname} += 1 ))
    : $(( counter_total += 1 ))
    if ! image_content_integrity_check "${system_mnt}" "${working_dir}" \
                                       "update re-signed apk ${apk}"; then
      return 1
    fi
  done < <(sudo find "${system_mnt}/system" -type f -name '*.apk' -print0)

  info "Found ${counter_platform} platform APKs."
  info "Found ${counter_media} media APKs."
  info "Found ${counter_shared} shared APKs."
  info "Found ${counter_releasekey} release APKs."
  info "Found ${counter_networkstack} networkstack APKs."
  info "Found ${counter_total} total APKs."
  # Validity check.
  if [[ ${counter_platform} -lt 2 || ${counter_media} -lt 2 ||
        ${counter_shared} -lt 2 || ${counter_releasekey} -lt 2 ||
        ${counter_total} -lt 25 ]]; then
    die "Number of re-signed package seems to be wrong"
  fi

  return 0
}

# Extracts certificate from the provided public key.
get_cert() {
  # Full path to public key to read and extract certificate. It must exist.
  local public_key=$1
  local cert=$(sed -E '/(BEGIN|END) CERTIFICATE/d' \
    "${public_key}" | tr -d '\n' \
    | base64 --decode | hexdump -v -e '/1 "%02x"')

  if [[ -z "${cert}" ]]; then
    die "Unable to get the public platform key"
  fi
  echo "${cert}"
}

# Extract certificate from the provided certificate yaml file.
get_cert_from_yaml() {
  # Full path to the yaml file. It must exist, and must have exactly 1 cert.
  local public_key=$1
  local cert
  cert=$(awk '/(BEGIN CERTIFICATE)/,/(END CERTIFICATE)/' \
    "${public_key}" | sed -E '/(BEGIN|END) CERTIFICATE/d' | \
    tr -d ' ' | tr -d '\n' | base64 --decode | hexdump -v -e '/1 "%02x"')
  if [[ -z "${cert}" ]]; then
    die "Unable to get the public platform key"
  fi
  echo "${cert}"
}

# Replaces particular certificate in mac_permissions xml file with new one.
# Note, this does not fail if particular entry is not found. For example
# network_stack does not exist in P.
change_cert() {
  # Type of signer entry to process. Could be platform, media or network_stack.
  local type=$1
  # New certificate encoded to string. This replaces old one.
  local cert=$2
  # *mac_permissions xml file to modify, plat_mac_permissions.xml for example.
  local xml=$3
  local pattern="(<signer signature=\")\w+(\"><seinfo value=\"${type})"
  sudo sed -i -E "s/${pattern}/\1${cert}"'\2/g' "${xml}"
}

# Platform key is part of the SELinux policy.  Since we are re-signing framework
# apks, we need to replace the key in the policy as well.
update_sepolicy() {
  local system_mnt=$1
  local key_dir=$2

  info "Start updating sepolicy"

  local new_platform_cert
  local new_media_cert
  local new_network_stack_cert

  if [[ -n ${KEYCFG_ANDROID_CLOUD_KEY_PREFIX} ]]; then
    local platform_cert_yaml="${key_dir}/platform_config.yaml"
    local media_cert_yaml="${key_dir}/media_config.yaml"
    local network_cert_yaml="${key_dir}/networkstack_config.yaml"

    new_platform_cert=$(get_cert_from_yaml "${platform_cert_yaml}")
    new_media_cert=$(get_cert_from_yaml "${media_cert_yaml}")
    new_network_stack_cert=$(get_cert_from_yaml "${network_cert_yaml}")
  else
    local public_platform_key="${key_dir}/platform.x509.pem"
    local public_media_key="${key_dir}/media.x509.pem"
    local public_network_stack_key="${key_dir}/networkstack.x509.pem"

    new_platform_cert=$(get_cert "${public_platform_key}")
    new_media_cert=$(get_cert "${public_media_key}")
    new_network_stack_cert=$(get_cert "${public_network_stack_key}")
  fi

  shopt -s nullglob
  local xml_list=( "${system_mnt}"/system/etc/**/*mac_permissions.xml )
  shopt -u nullglob
  if [[ "${#xml_list[@]}" -ne 1 ]]; then
    die "Unexpected number of *mac_permissions.xml: ${#xml_list[@]}\n \
      ${xml_list[*]}"
  fi

  local xml="${xml_list[0]}"
  local orig=$(make_temp_file)
  cp "${xml}" "${orig}"

  change_cert "platform" "${new_platform_cert}" "${xml}"
  change_cert "media" "${new_media_cert}" "${xml}"
  change_cert "network_stack" "${new_network_stack_cert}" "${xml}"

  # Validity check.
  if cmp "${xml}" "${orig}"; then
    die "Failed to replace SELinux policy cert"
  fi
}

replace_ota_cert_cloud() {
  local system_mnt=$1
  local key_dir=$2
  local keyname=$3

  info "Replacing OTA cert for cloud"

  local temp_cert
  temp_cert=$(make_temp_file)
  local cert
  cert=$(awk '/(BEGIN CERTIFICATE)/,/(END CERTIFICATE)/' \
    "${key_dir}/${keyname}_config.yaml" | sed 's/^\s*//')
  echo "${cert}" > "${temp_cert}"

  local ota_zip="${system_mnt}/system/etc/security/otacerts.zip"

  local temp_dir
  temp_dir=$(make_temp_dir)
  pushd "${temp_dir}" > /dev/null
  cp "${temp_cert}" "${keyname}.x509.pem"
  local temp_zip
  temp_zip=$(make_temp_file)
  zip -q -r "${temp_zip}.zip" .
  # Copy the content instead of mv to avoid owner/mode changes.
  sudo cp "${temp_zip}.zip" "${ota_zip}"
  popd > /dev/null
}

# Replace the debug key in OTA cert with release key.
replace_ota_cert() {
  local system_mnt=$1
  local release_cert=$2
  local ota_zip="${system_mnt}/system/etc/security/otacerts.zip"

  info "Replacing OTA cert"

  local temp_dir=$(make_temp_dir)
  pushd "${temp_dir}" > /dev/null
  cp "${release_cert}" .
  local temp_zip=$(make_temp_file)
  zip -q -r "${temp_zip}.zip" .
  # Copy the content instead of mv to avoid owner/mode changes.
  sudo cp "${temp_zip}.zip" "${ota_zip}"
  popd > /dev/null
}

# Snapshot file properties in a directory recursively.
snapshot_file_properties() {
  local dir=$1
  sudo find "${dir}" -exec stat -c '%n:%u:%g:%a' {} + | sort
}

# Snapshot capabilities in a directory recursively.
snapshot_capabilities() {
  local dir=$1
  sudo find "${dir}" -exec getcap {} + | sort
}

# Apply capabilities to files in |dir| as specified by |capabilities_list|.
# See b/179170462.
apply_capabilities() {
  local dir=$1
  local capabilities_list=$2
  local entry

  while read -ra entry; do
    if [[ ${#entry[@]} -lt 2 ]]; then
      error "Unexpected output in capabilities_list of '${entry[*]}'"
      return 1
    fi
    # Output of getcap is either |{file} {capabilities}| or
    # |{file} = {capabilities}|, so take the first and last element of each
    # line.
    info "Setting capabilities ${entry[${#entry[@]}-1]} for ${entry[0]}"
    sudo setcap "${entry[${#entry[@]}-1]}" "${entry[0]}"
  done < "${capabilities_list}"

  return 0
}

# Integrity check that capabilities are unchanged.
capabilities_integrity_check() {
  local system_mnt=$1
  local working_dir=$2
  snapshot_capabilities "${system_mnt}" > "${working_dir}/capabilities.new"
  local d
  if ! d=$(diff "${working_dir}"/capabilities.{orig,new}); then
    error "Unexpected change of capabilities, diff \n${d}"
    return 1
  fi

  return 0
}

# Integrity check that image content is unchanged.
image_content_integrity_check() {
  local system_mnt=$1
  local working_dir=$2
  local reason=$3
  snapshot_file_properties "${system_mnt}" > "${working_dir}/properties.new"
  local d
  if ! d=$(diff "${working_dir}"/properties.{orig,new}); then
    error "Unexpected change of file property, diff due to ${reason}\n${d}"
    return 1
  fi

  return 0
}

list_files_in_squashfs_image() {
  local unsquashfs=$1
  local system_img=$2
  "${unsquashfs}" -l "${system_img}" | grep ^squashfs-root
}

# This function is needed to set the VB meta digest parameter for
# Verified Boot. The value is calculated by calculating the hash
# of hashes of the system and vendor images. It will be written
# to a file in the same directory as the system image and will be
# read by ARC Keymint. See ​​go/arc-vboot-param-design for more details.
write_arcvm_vbmeta_digest() {
  local android_dir=$1
  local system_img_path=$2
  local vendor_img_path=$3

  local vbmeta_digest_path="${android_dir}/arcvm_vbmeta_digest.sha256"

  # Calculate hashes of the system and vendor images.
  local system_img_hash vendor_img_hash combined_hash vbmeta_digest
  if ! system_img_hash=$(sha256sum -b "${system_img_path}"); then
    warn "Error calculating system image hash"
    return 1
  fi
  if ! vendor_img_hash=$(sha256sum -b "${vendor_img_path}"); then
    warn "Error calculating vendor image hash"
    return 1
  fi

  # Cut off the end of sha256sum output since it includes the file name.
  system_img_hash="$(echo -n "${system_img_hash}" | awk '{print $1}')"
  vendor_img_hash="$(echo -n "${vendor_img_hash}" | awk '{print $1}')"

  # Combine the two hashes and calculate the hash of that value.
  combined_hash=$(printf "%s%s" "${system_img_hash}" "${vendor_img_hash}")
  if ! vbmeta_digest=$(echo -n "${combined_hash}" | sha256sum -b); then
    warn "Error calculating the hash of the combined hash of the images"
    return 1
  fi

  vbmeta_digest="$(echo -n "${vbmeta_digest}" | awk '{print $1}')"

  # If there is an existing digest, compare the two values.
  if [[ -f "${vbmeta_digest_path}" ]]; then
    local prev_vbmeta_digest
    prev_vbmeta_digest=$(cat "${vbmeta_digest_path}")
    if [[ "${vbmeta_digest}" == "${prev_vbmeta_digest}" ]]; then
      warn "Error: existing and re-calculated digests are the same"
      return 1
    fi
  fi

  info "Writing re-calculated VB meta digest to arcvm_vbmeta_digest.sha256"
  echo -n "${vbmeta_digest}" > "${vbmeta_digest_path}"
  return 0
}

sign_android_internal() {
  local root_fs_dir=$1
  local key_dir=$2

  # Detect vm/container type and set environment correspondingly.
  # Keep this aligned with
  # src/private-overlays/project-cheets-private/scripts/board_specific_setup.sh
  local system_image=""
  local selinux_dir="${root_fs_dir}/etc/selinux"
  local file_contexts=""
  local vm_candidate="${root_fs_dir}/opt/google/vms/android/system.raw.img"
  local container_candidate=(
      "${root_fs_dir}/opt/google/containers/android/system.raw.img")
  if [[ -f "${vm_candidate}" ]]; then
    system_image="${vm_candidate}"
    file_contexts="${selinux_dir}/arc/contexts/files/android_file_contexts_vm"
  elif [[ -f "${container_candidate}" ]]; then
    system_image="${container_candidate}"
    file_contexts="${selinux_dir}/arc/contexts/files/android_file_contexts"
  else
    die "System image does not exist"
  fi

  local android_system_image="$(echo \
    "${root_fs_dir}"/opt/google/*/android/system.raw.img)"
  local android_dir=$(dirname "${android_system_image}")
  local system_img="${android_dir}/system.raw.img"

  # Use the versions in $PATH rather than the system ones.
  # squashfs-tools
  local unsquashfs mksquashfs
  unsquashfs=$(which unsquashfs)
  mksquashfs=$(which mksquashfs)

  # erofs-utils
  local dump_erofs fsck_erofs mkfs_erofs
  dump_erofs=$(which dump.erofs)
  fsck_erofs=$(which fsck.erofs)
  mkfs_erofs=$(which mkfs.erofs)

  if [[ $# -lt 2 || $# -gt 3 ]]; then
    flags_help
    die "command requires 2 input args and can take 1 optional arguments."
  fi

  if [[ ! -f "${system_img}" ]]; then
    die "System image does not exist: ${system_img}"
  fi

  local image_type
  local output_squashfs output_erofs
  if output_squashfs=$("${unsquashfs}" -s "${system_img}" 2>&1); then
    image_type="squashfs"
  elif output_erofs=$("${dump_erofs}" "${system_img}" 2>&1); then
    image_type="erofs"
  else
    die "Can't detect the image type of ARC system image\n" \
        "output_squashfs: ${output_squashfs}\n" \
        "output_erofs: ${output_erofs}"
  fi
  info "Detected ARC system image type: ${image_type}"

  # Detect image compression flags.
  local compression_flags=()
  local compression_flags_path="${android_dir}/image_compression_flags"
  if [[ -f "${compression_flags_path}" ]]; then
    # The file contains a line such as:
    # mkfs.erofs -z lz4hc -C32768
    read -r -a tokens <"${compression_flags_path}"
    if [[ ("${image_type}" == "squashfs" && "${tokens[0]}" != "mksquashfs") ||
          ("${image_type}" == "erofs" && "${tokens[0]}" != "mkfs.erofs") ]]; then
      die "Compression tool '${tokens[0]}' found in image_compression_flags" \
          "doesn't match detected image type '${image_type}'"
    fi
    compression_flags=("${tokens[@]:1}")
    info "Detected compression flags: ${compression_flags[*]}"
  else
    if [[ "${image_type}" == "erofs" ]]; then
      compression_flags=(-z lz4hc -C32768)
    elif [[ "${image_type}" == "squashfs" ]]; then
      local compression
      compression="$("${unsquashfs}" -s "${system_img}" \
        | awk '$1 == "Compression" {print $2}')"
      case "${compression}" in
        "gzip")
          compression_flags=(-comp gzip)
          ;;
        "lz4")
          compression_flags=(-comp lz4 -Xhc -b 256K)
          ;;
        "zstd")
          compression_flags=(-comp zstd -b 256K)
          ;;
        *)
          die "Unexpected compression type: ${compression}"
          ;;
      esac
    fi
    info "image_compression_flags does not exist." \
         "(This is expected for versions older than R121-15679.)" \
         "Using default compression flags: ${compression_flags[*]}"
  fi

  if ! type -P zipalign &>/dev/null || ! type -P signapk &>/dev/null \
    || ! type -P apksigner &>/dev/null; then
    # TODO(victorhsieh): Make this an error.  This is not treating as error
    # just to make an unrelated test pass by skipping this signing.
    warn "Skip signing Android apks (some of executables are not found)."
    exit 0
  fi

  local working_dir=$(make_temp_dir)
  local system_mnt="${working_dir}/mnt"
  local system_capabilities_orig="${working_dir}/capabilities.orig"

  if [[ "${image_type}" == "squashfs" ]]; then
    # Extract with xattrs so we can read and audit capabilities.
    # See b/179170462.
    info "Unpacking squashfs system image with xattrs to ${system_mnt}"
    sudo "${unsquashfs}" -x -f -no-progress -d "${system_mnt}" "${system_img}"
    snapshot_capabilities "${system_mnt}" > "${system_capabilities_orig}"
    sudo rm -rf "${system_mnt}"

    info "Unpacking squashfs system image without xattrs to ${system_mnt}"
    list_files_in_squashfs_image "${unsquashfs}" "${system_img}" > \
        "${working_dir}/image_file_list.orig"
    sudo "${unsquashfs}" -no-xattrs -f -no-progress -d \
        "${system_mnt}" "${system_img}"

  elif [[ "${image_type}" == "erofs" ]]; then
    info "Unpacking erofs system image to ${system_mnt}"
    sudo "${fsck_erofs}" "--extract=${system_mnt}" "${system_img}"

    # Use /system/etc/capabilities_list, as fsck.erofs does not yet support
    # extraction with xattrs.
    local capabilities_list="${system_mnt}/system/etc/capabilities_list"
    if [[ ! -f "${capabilities_list}" ]]; then
      die "${capabilities_list} does not exist"
    fi

    # Add ${system_mnt} as a prefix.
    # Example of a line: "/system/bin/run-as cap_setgid,cap_setuid=ep"
    sudo sed "s|^|${system_mnt}|" "${capabilities_list}" > \
        "${system_capabilities_orig}"

    # List all files inside the image.
    sudo find "${system_mnt}" > "${working_dir}/image_file_list.orig"
  fi

  # Override apksigner flag if file is available, ref b/307968835.
  local use_apksigner_file_path
  use_apksigner_file_path="${system_mnt}/system/etc/signing_use_apksigner"
  if [[ -f "${use_apksigner_file_path}" ]]; then
    info "Changing apksigner flag from ${FLAGS_use_apksigner} to True"
    FLAGS_use_apksigner=${FLAGS_TRUE}
  fi

  snapshot_file_properties "${system_mnt}" > "${working_dir}/properties.orig"

  if ! sign_framework_apks "${system_mnt}" "${key_dir}" "${working_dir}"; then
    return 1
  fi

  if ! image_content_integrity_check "${system_mnt}" "${working_dir}" \
                                     "sign_framework_apks"; then
    return 1
  fi

  update_sepolicy "${system_mnt}" "${key_dir}"
  if ! image_content_integrity_check "${system_mnt}" "${working_dir}" \
                                      "update_sepolicy"; then
    return 1
  fi

  local ota_cert_kn="releasekey"

  if [[ -n ${KEYCFG_ANDROID_CLOUD_KEY_PREFIX} ]]; then
    replace_ota_cert_cloud "${system_mnt}" "${key_dir}" "${ota_cert_kn}"
  else
    replace_ota_cert "${system_mnt}" "${key_dir}/${ota_cert_kn}.x509.pem"
  fi

  if ! image_content_integrity_check "${system_mnt}" "${working_dir}" \
                                     "replace_ota_cert"; then
    return 1
  fi

  # Packages cache needs to be regenerated when the key and timestamp are
  # changed for apks.
  local packages_cache="${system_mnt}/system/etc/packages_cache.xml"
  local file_hash_cache="${system_mnt}/system/etc/file_hash_cache"
  if [[ -f "${packages_cache}" ]]; then
    if type -P aapt &>/dev/null; then
      info "Regenerating packages cache ${packages_cache}"
      # For the validity check.
      local packages_before=$(grep "<package " "${packages_cache}" | wc -l)
      local vendor_mnt=$(make_temp_dir)
      local vendor_img="${android_dir}/vendor.raw.img"

      if [[ "${image_type}" == "squashfs" ]]; then
        info "Unpacking squashfs vendor image to ${vendor_mnt}/vendor"
        # Vendor image is not updated during this step. However we have to
        # include vendor apks to re-generated packages cache which exists in
        # one file for both system and vendor images.
        sudo "${unsquashfs}" -x -f -no-progress -d "${vendor_mnt}/vendor" \
            "${vendor_img}"
      elif [[ "${image_type}" == "erofs" ]]; then
        info "Unpacking erofs vendor image to ${vendor_mnt}/vendor"
        sudo "${fsck_erofs}" "--extract=${vendor_mnt}/vendor" "${vendor_img}"
      fi

      if ! sudo arc_generate_packages_cache "${system_mnt}" "${vendor_mnt}" \
          "${working_dir}/packages_cache.xml" \
          "${working_dir}/file_hash_cache"; then
        die "Failed to generate packages cache."
      fi
      sudo cp "${working_dir}/packages_cache.xml" "${packages_cache}"
      sudo cp "${working_dir}/file_hash_cache" "${file_hash_cache}"
      # Set android-root as an owner.
      sudo chown 655360:655360 "${packages_cache}"
      local packages_after=$(grep "<package " "${packages_cache}" | wc -l)
      if [[ "${packages_before}" != "${packages_after}" ]]; then
        die "failed to verify the packages count after the regeneration of " \
            "the packages cache. Expected ${packages_before} but found " \
            "${packages_after} packages in pacakges_cache.xml"
      fi
    else
      warn "aapt tool could not be found. Could not regenerate the packages " \
           "cache. Outdated pacakges_cache.xml is removed."
      sudo rm "${packages_cache}"
    fi
  else
    info "Packages cache ${packages_cache} does not exist. Skip regeneration."
  fi

  # Apply original capabilities to system image and verify correctness.
  if ! apply_capabilities "${system_mnt}" "${system_capabilities_orig}"; then
    return 1
  fi
  if ! capabilities_integrity_check "${system_mnt}" "${working_dir}"; then
    return 1
  fi

  local old_size=$(stat -c '%s' "${system_img}")
  # Remove old system image to prevent mksquashfs tries to merge both images.
  sudo rm -rf "${system_img}"

  if [[ "${image_type}" == "squashfs" ]]; then
    info "Repacking squashfs image with ${compression_flags[*]}"
    if ! sudo "${mksquashfs}" "${system_mnt}" "${system_img}" \
         -context-file "${file_contexts}" -mount-point "/" \
         -no-progress "${compression_flags[@]}"; then
      die "mksquashfs failed"
    fi

    list_files_in_squashfs_image "${unsquashfs}" "${system_img}" > \
        "${working_dir}/image_file_list.new"

  elif [[ "${image_type}" == "erofs" ]]; then
    # List all files inside the image.
    sudo find "${system_mnt}" > "${working_dir}/image_file_list.new"

    info "Repacking erofs image with ${compression_flags[*]}"
    if ! sudo "${mkfs_erofs}" "${compression_flags[@]}" \
         --file-contexts "${file_contexts}" \
         "${system_img}" "${system_mnt}"; then
      die "mkfs.erofs failed"
    fi
  fi

  local new_size
  new_size=$(stat -c '%s' "${system_img}")
  info "Android system image size change: ${old_size} -> ${new_size}"

  # Calculate the hash of the system and vendor images and store the value
  # in a file. The digest was initially calculated and written when the
  # image was built. This recalculates the digest of the signed image and
  # replaces the original value.
  # Any changes to the images must occur before this method.
  if ! write_arcvm_vbmeta_digest "${android_dir}" "${system_img}" "${vendor_img}"; then
    warn "ARCVM vbmeta digest was not overwritten"
  fi

  if d=$(grep -v -F -x -f "${working_dir}"/image_file_list.{new,orig}); then
    # If we have a line in image_file_list.orig which does not appear in
    # image_file_list.new, it means some files are removed during signing
    # process. Here we have already deleted the original Android image so
    # cannot retry.
    die "Unexpected change of file list\n${d}"
  fi

  return 0
}

main() {
  # TODO(b/175081695): Remove retries once root problem is fixed.
  local attempts
  for (( attempts = 1; attempts <= 3; ++attempts )); do
    if sign_android_internal "$@"; then
      exit 0
    fi
    warn "Could not sign android image due to recoverable error, will retry," \
         "attempt # ${attempts}."
    warn "@@@ALERT@@@"
    lsof -n
    dmesg
    mount
  done
  die "Unable to sign Android image; giving up."
}

main "$@"
