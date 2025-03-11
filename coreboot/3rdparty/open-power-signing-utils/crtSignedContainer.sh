#!/bin/bash
#
# Script to create a signed container.  Intended for op-build integration.
#

# Defaults, initial values
P=${0##*/}

SIGN_MODE=local
KMS=signframework

HW_KEY_ARGS=""
SW_KEY_ARGS=""
HW_SIG_ARGS=""
SW_SIG_ARGS=""
VERIFY_ARGS=""
DEBUG_ARGS=""
ADDL_ARGS=""

RC=0

#
# Functions
#
usage () {
    echo ""
    echo "	Options:"
    echo "	-h, --help              display this message and exit"
    echo "	-v, --verbose           show verbose output"
    echo "	-d, --debug             show additional debug output"
    echo "	-w, --wrap              column to wrap long output in verbose mode"
    echo "	-a, --hwKeyA            file containing HW key A private key in PEM format"
    echo "	-b, --hwKeyB            file containing HW key B private key in PEM format"
    echo "	-c, --hwKeyC            file containing HW key C private key in PEM format"
    echo "	-p, --swKeyP            file containing SW key P private key in PEM format"
    echo "	-q, --swKeyQ            file containing SW key Q private key in PEM format"
    echo "	-r, --swKeyR            file containing SW key R private key in PEM format"
    echo "	-l, --protectedPayload  file containing the payload to be signed"
    echo "	-i, --out               file to write containerized payload"
    echo "	-o, --code-start-offset code start offset for software header in hex"
    echo "	-f, --flags             prefix header flags in hex"
    echo "	-F, --sw-flags          prefix software header flags in hex"
    echo "	-m, --mode              signing mode: local, independent or production"
    echo "	-k, --kms               key management system for retrieving keys and signatures"
    echo "	                        (choices are \"signframework\" or \"pkcs11\")"
    echo "	-s, --scratchDir        scratch directory to use for file caching, etc."
    echo "	-L, --label             name or identifier of the module being built (8 char max)"
    echo "	    --contrHdrOut       file write container header only (w/o payload)"
    echo "	    --archiveOut        file or directory to write archive (tarball) of artifacts"
    echo "	                        if directory, must end in '/'.  for PWD, use '.'"
    echo "	    --archiveIn         file containing archive of artifacts to import to cache"
    echo "	    --validate          validate the container after build"
    echo "	    --verify            verify the container after build, against the provided"
    echo "	                        value, or filename containing value, of the HW Keys hash"
    echo "	    --sign-project-config   INI file containing configuration properties (options"
    echo "	                            set here override those set via cmdline or environment)"
    echo "	-S, --security-version  Integer, sets the security version container field"
    echo ""
    exit 1
}

die () {
    echo "$P: $*" 1>&2
    exit 1
}

is_private_key () {
    openssl ec -pubout -in "$1" &>/dev/null
}

is_public_key () {
    openssl ec -pubin -pubout -in "$1" &>/dev/null
}

is_raw_key () {
    # A RAW p521 pubkey will be 133 bytes with a leading byte of 0x04,
    # indicating an uncompressed key.
    test "$1" && \
        test "$(stat -c%s "$1")" -eq 133 && \
        [[ $(dd if="$1" bs=1 count=1 2>/dev/null) == $'\004' ]]
}

to_lower () {
    echo "$1" | tr A-Z a-z
}

to_upper () {
    echo "$1" | tr a-z A-Z
}

is_path_full () {
    # If a path has a leading slash, it's a full path, not relative
    echo "$1" | egrep -q ^/
}

is_path_dir () {
    # If a path has a trailing slash, it's a dir, not a file
    echo "$1" | egrep -q /$
}

make_bool () {
    # Sanitize boolean values so that on input:
    # - True = set to "true" or "y", case insensitive
    # - False = set to any other string, or unset
    # On output:
    # - True = set to a non-zero length string
    # - False = set to a zero length string
    if [ "$(to_lower "$1")" == true ] || [ "$(to_lower "$1")" == y ]
    then
        echo true
    else
        echo ""
    fi
}

is_cmd_available () {
    command -v "$1" &>/dev/null
}

get_date_string () {
    # Convert a seconds-since-epoch value to presentation format
    local d
    d=$(date -d @"$1" 2>/dev/null) && echo "$d" && return

    is_cmd_available perl && \
        d=$(perl -le "print scalar localtime $1" 2>/dev/null) && \
            echo "$d" && return

    d=$1 && echo "$d"
}

exportArchive () {
    # If project basename is set, prepare the export for import to a system
    # using the same project basename.
    if [ "$SIGN_MODE" == "local" ] ||  [ "$SIGN_MODE" == "independent" ]
    then
        if [ "$SF_HW_SIGNING_PROJECT_BASE" ]
        then
            echo "--> $P: Exporting HW keys and sigs for project: $SF_HW_SIGNING_PROJECT_BASE"
            cd "$T" || die "Cannot cd to $T"
            for KEY in a b c; do
                cp -p &>/dev/null "HW_key_$KEY.pub" \
                    "project.${SF_HW_SIGNING_PROJECT_BASE}_${KEY}.HW_key_${KEY}.pub"
                cp -p &>/dev/null "HW_key_$KEY.raw" \
                    "project.${SF_HW_SIGNING_PROJECT_BASE}_${KEY}.HW_key_${KEY}.raw"
                cp -p &>/dev/null "HW_key_$KEY.sig" \
                    "project.${SF_HW_SIGNING_PROJECT_BASE}_${KEY}.HW_sig_${KEY}.sig"
                cp -p &>/dev/null "HW_key_$KEY.raw" \
                    "project.${SF_HW_SIGNING_PROJECT_BASE}_${KEY}.HW_sig_${KEY}.raw"
            done
        fi
        if [ "$SF_FW_SIGNING_PROJECT_BASE" ]
        then
            echo "--> $P: Exporting FW keys and sigs for project: $SF_FW_SIGNING_PROJECT_BASE"
            cd "$T" || die "Cannot cd to $T"
            for KEY in p q r; do
                cp -p &>/dev/null "SW_key_$KEY.pub" \
                    "project.${SF_FW_SIGNING_PROJECT_BASE}_${KEY}.SW_key_${KEY}.pub"
                cp -p &>/dev/null "SW_key_$KEY.raw" \
                    "project.${SF_FW_SIGNING_PROJECT_BASE}_${KEY}.SW_key_${KEY}.raw"
                mv &>/dev/null "SW_key_$KEY.sig" \
                    "project.${SF_FW_SIGNING_PROJECT_BASE}_${KEY}.SW_sig_${KEY}.sig"
            done
        fi
    fi

	# Create the archive.
    cd "$SB_SCRATCH_DIR" || die "Cannot cd to $SB_SCRATCH_DIR"
    if tar -zcf "$SB_ARCHIVE_OUT" "$buildID/$LABEL/"; then
        echo "--> $P: Archive saved to: $SB_ARCHIVE_OUT"
    else
        echo "--> $P: Error $? saving archive to: $SB_ARCHIVE_OUT"
    fi
}

importArchive () {
    echo "--> $P: Importing archive: $1..."

    test ! -f "$1" && die "archiveIn file not found: $1"

    if ! is_path_full "$1"; then
        local f="$PWD/$1"
    else
        local f="$1"
    fi

    local previous_wd="$PWD"
    cd "$TOPDIR" || die "Cannot cd to $TOPDIR"

    archpath=$(tar -tf "$f" | head -1)
    archdir=$(echo "$archpath" | cut -d/ -f1)
    archsubdir=$(echo "$archpath" | cut -d/ -f2)

    test -z "$archdir" -o -z "$archsubdir" && \
        die "Cannot determine archive content for $f"

    if [ -d "$archsubdir" ]; then
        # We already have this subdir in the cache, make a backup
        rm -rf "$archsubdir.save"
        cp -rp "$archsubdir" "$archsubdir.save"
    else
        # We don't yet have a subdir by this name, create it
        mkdir "$archsubdir"
    fi

    if ! tar -xf "$f"; then
        echo "--> $P: Error $? unpacking archive: $f"
    fi

    # Move the unpacked files and remove the temporary archive directory
    mv "$archdir/$archsubdir/"* "$archsubdir/"
    rmdir "$archdir/$archsubdir/"
    rmdir "$archdir/"
    cd "$previous_wd" || die "Cannot cd back to ${previous_wd}, is it gone?"
}

checkKey () {
    # The variable name
    local keyname="$1"
    # The variable's value, typically the filename holding the key
    local k="${!keyname}"

    if [ "$k" ]; then
        # Handle the special values __skip, __get, __getkey and __getsig
        test "$k" == __skip && return
        test "$k" == __get && return
        test "$k" == __getkey && return
        test "$k" == __getsig && return

        # If it's a file, determine what kind of key it contains
        if [ -f "$k" ]; then
            if is_private_key "$k"; then
                test "$SB_VERBOSE" && \
                    echo "--> $P: Key $keyname is a private ECDSA key"
            elif is_public_key "$k"; then
                test "$SB_VERBOSE" && \
                    echo "--> $P: Key $keyname is a public ECDSA key"
            elif is_raw_key "$k"; then
                test "$SB_VERBOSE" && \
                    echo "--> $P: Key $keyname is a RAW public ECDSA key"
            else
                die "Key $keyname is neither a public nor private key"
            fi
        else
            die "Can't open file: $k for $keyname"
        fi
    fi
}

parseIni () {
    local IFS=" ="
    local section property value

    while read -r property value
    do
        if echo "$property" | egrep -q "^;"
        then
            # This is a comment, skip it
            continue
        elif echo "$property" | egrep -q "\[.*]"
        then
            # This is a section header, read it
            section=$(echo "$property" | tr -d [] )
        elif test "$value"
        then
            # This is a property, set it
            eval "${section}_${property}=\"$value\""
        fi
    done < "$1"
}

findArtifact () {
    local f
    local found
    local scope

    for f in "$@"
    do
        # If filename starts with ./ search only this component cache.
        if [ "${f:0:2}" == "./" ]
        then
            f="${f:2}"
            scope=local
        else
            scope=global
        fi

        # Look for artifact in the local cache
        found=$(find "$T" -name "$f" | head -1)
        if [ "$found" ]; then
            echo "$f"
            return
        fi

        test "$scope" == "local" && continue

        # Look elsewhere in the cache
        found=$(find "$TOPDIR" -name "$f" | head -1)
        if [ "$found" ]; then
            cp -p "$found" "$T/"
            echo "$f"
            return
        fi
    done
}

#
# Main
#

# Convert long options to short
for arg in "$@"; do
  shift
  case "$arg" in
    "--help")       set -- "$@" "-h" ;;
    "--verbose")    set -- "$@" "-v" ;;
    "--debug")      set -- "$@" "-d" ;;
    "--wrap")       set -- "$@" "-w" ;;
    "--hwPrivKeyA") set -- "$@" "-a" ;;
    "--hwPrivKeyB") set -- "$@" "-b" ;;
    "--hwPrivKeyC") set -- "$@" "-c" ;;
    "--swPrivKeyP") set -- "$@" "-p" ;;
    "--swPrivKeyQ") set -- "$@" "-q" ;;
    "--swPrivKeyR") set -- "$@" "-r" ;;
    "--hwKeyA") set -- "$@" "-a" ;;
    "--hwKeyB") set -- "$@" "-b" ;;
    "--hwKeyC") set -- "$@" "-c" ;;
    "--swKeyP") set -- "$@" "-p" ;;
    "--swKeyQ") set -- "$@" "-q" ;;
    "--swKeyR") set -- "$@" "-r" ;;
    "--flags")      set -- "$@" "-f" ;;
    "--sw-flags")   set -- "$@" "-F" ;;
    "--code-start-offset") set -- "$@" "-o" ;;
    "--protectedPayload")  set -- "$@" "-l" ;;
    "--out")        set -- "$@" "-i" ;;
    "--kms")        set -- "$@" "-k" ;;
    "--mode")       set -- "$@" "-m" ;;
    "--scratchDir") set -- "$@" "-s" ;;
    "--label")      set -- "$@" "-L" ;;
    "--sign-project-FW-token")   set -- "$@" "-L" ;;
    "--sign-project-config")   set -- "$@" "-4" ;;
    "--security-version")   set -- "$@" "-S" ;;
    "--contrHdrOut") set -- "$@" "-5" ;;
    "--archiveIn")  set -- "$@" "-6" ;;
    "--archiveOut") set -- "$@" "-7" ;;
    "--validate")   set -- "$@" "-8" ;;
    "--verify")     set -- "$@" "-9" ;;
    *)              set -- "$@" "$arg"
  esac
done

# Process command-line arguments
while getopts -- ?hdvw:a:b:c:p:q:r:f:F:o:l:i:m:k:s:L:S:4:5:6:7:89: opt
do
  case "${opt:?}" in
    v) SB_VERBOSE="TRUE";;
    d) SB_DEBUG="TRUE";;
    w) SB_WRAP="$OPTARG";;
    a) HW_KEY_A="$OPTARG";;
    b) HW_KEY_B="$OPTARG";;
    c) HW_KEY_C="$OPTARG";;
    p) SW_KEY_P="$OPTARG";;
    q) SW_KEY_Q="$OPTARG";;
    r) SW_KEY_R="$OPTARG";;
    f) HW_FLAGS="$OPTARG";;
    F) SW_FLAGS="$OPTARG";;
    o) CS_OFFSET="$OPTARG";;
    l) PAYLOAD="$OPTARG";;
    i) OUTPUT="$OPTARG";;
    k) KMS="$(to_lower "$OPTARG")";;
    m) SIGN_MODE="$(to_lower "$OPTARG")";;
    s) SB_SCRATCH_DIR="$OPTARG";;
    L) LABEL="$OPTARG";;
    S) SECURITY_VERSION="$OPTARG";;
    4) PROJECT_INI="$OPTARG";;
    5) SB_CONTR_HDR_OUT="$OPTARG";;
    6) SB_ARCHIVE_IN="$OPTARG";;
    7) SB_ARCHIVE_OUT="$OPTARG";;
    8) SB_VALIDATE="TRUE";;
    9) SB_VERIFY="$OPTARG";;
    h|\?) usage;;
  esac
done

# Check required programs
for p in date egrep tar openssl create-container print-container
do
    is_cmd_available $p || \
        die "Required command \"$p\" not available or not found in PATH"
done

# Sanitize boolean values
SB_VERBOSE="$(make_bool "$SB_VERBOSE")"
SB_DEBUG="$(make_bool "$SB_DEBUG")"

# These are the only env vars that override a command line option
test "$SB_KMS" && KMS="$(to_lower "$SB_KMS")"
test "$SB_SIGN_MODE" && SIGN_MODE="$(to_lower "$SB_SIGN_MODE")"
test "$SB_PROJECT_INI" && PROJECT_INI="$SB_PROJECT_INI"

# What op-build calls development mode, we call local mode
test "$SIGN_MODE" == development && SIGN_MODE=local

echo "--> $P: Signing mode: $SIGN_MODE"

#
# Parse INI file
#
if [ "$(to_upper "$LABEL")" == SBKTRAND ]
then
    # Key transition container may have its own ini file
    test "$SB_PROJECT_INI_TRANS" && PROJECT_INI=$SB_PROJECT_INI_TRANS
fi

if [ "$PROJECT_INI" ]
then
    test ! -f "$PROJECT_INI" && die "Can't open INI file: $PROJECT_INI"

    signer_userid=""
    signer_sshkey_file=""
    signer_epwd_file=""
    server_hostname=""
    signtool_validate=""
    signtool_verify=""
    signtool_verify_trans=""
    signtool_pass_on_validation_error=""
    signproject_hw_signing_project_basename=""
    signproject_fw_signing_project_basename=""
    signproject_getpubkey_project_basename=""
    pkcs11_module=""
    pkcs11_token=""

    echo "--> $P: Parsing INI file: $PROJECT_INI"
    parseIni "$PROJECT_INI"

    test "$signer_userid" && SF_USER="$signer_userid"
    test "$signer_sshkey_file" && SF_SSHKEY="$signer_sshkey_file"
    test "$signer_epwd_file" && SF_EPWD="$signer_epwd_file"
    test "$server_hostname" && SF_SERVER="$server_hostname"

    test "$signtool_validate" && SB_VALIDATE="$signtool_validate"
    test "$signtool_verify" && SB_VERIFY="$signtool_verify"
    test "$signtool_verify_trans" && SB_VERIFY_TRANS="$signtool_verify_trans"
    test "$signtool_pass_on_validation_error" && \
        SB_PASS_ON_ERROR="$signtool_pass_on_validation_error"

    test "$signproject_hw_signing_project_basename" && \
        SF_HW_SIGNING_PROJECT_BASE="$signproject_hw_signing_project_basename"
    test "$signproject_fw_signing_project_basename" && \
        SF_FW_SIGNING_PROJECT_BASE="$signproject_fw_signing_project_basename"
    test "$signproject_getpubkey_project_basename" && \
        SF_GETPUBKEY_PROJECT_BASE="$signproject_getpubkey_project_basename"

    test "$pkcs11_module" && SB_PKCS11_MODULE="$pkcs11_module"
    test "$pkcs11_token" && SB_PKCS11_TOKEN="$pkcs11_token"
fi

#
# Check required arguments
#
if [ -z "$PAYLOAD" ] || [ "$PAYLOAD" == __none ]
then
    PAYLOAD=/dev/zero
elif [ ! -f "$PAYLOAD" ]; then
    die "Can't open payload file: $PAYLOAD"
fi

if [ "$SIGN_MODE" == "production" ]
then
    test -z "$SF_USER" && die "Production mode selected but no signer userid provided"
    test -z "$SF_SSHKEY" && die "Production mode selected but no signer ssh key provided"
    test -z "$SF_EPWD" && die "Production mode selected but no signer ePWD provided"
    test -z "$SF_SERVER" && die "Production mode selected but no signframework server provided"
    is_cmd_available sf_client || \
        die "Required command \"sf_client\" not available or not found in PATH"
fi

# Check input keys
for KEY in HW_KEY_A HW_KEY_B HW_KEY_C; do
    checkKey $KEY
done

for KEY in SW_KEY_P SW_KEY_Q SW_KEY_R; do
    checkKey $KEY
done

#
# Set cache directory
#
: "${TMPDIR:=/tmp}"
: "${SB_SCRATCH_DIR:=$TMPDIR}"
: "${SB_KEEP_CACHE:=false}"
: "${LABEL:=IMAGE}"

moniker="SIGNTOOL"

test ! -d "$SB_SCRATCH_DIR" && die "Scratch directory not found: $SB_SCRATCH_DIR"

TOPDIR=$(ls -1dt "$SB_SCRATCH_DIR"/${moniker}_* 2>/dev/null | head -1)

if [ "$TOPDIR" ]; then
    buildID="${TOPDIR##*/}"
    timestamp="${buildID##*_}"
    echo "--> $P: Using existing cache dir: $TOPDIR, created: $(get_date_string "$timestamp")"
else
    buildID="${moniker}_$(date +%s)"
    TOPDIR="$SB_SCRATCH_DIR/$buildID"
    echo "--> $P: Creating new cache dir: $TOPDIR"
    mkdir "$TOPDIR"
fi

T="$TOPDIR/$LABEL"

if [ -d "$T" ]; then
    echo "--> $P: Using existing cache subdir: $T"
else
    echo "--> $P: Creating new cache subdir: $T"
    mkdir "$T"
fi

# Set a scratch file for output, if none provided.
if [ -z "$OUTPUT" ] || [ "$OUTPUT" == __none ]
then
    OUTPUT="$SB_SCRATCH_DIR/$(to_lower "$buildID").scratch.out.img"
    OUTPUT_SCRATCH=true
else
    OUTPUT_SCRATCH=false
fi

#
# If --archiveOut requested, construct the path and check it now
#
if [ "$SB_ARCHIVE_OUT" ]; then

    path=$SB_ARCHIVE_OUT

    test "$path" == . && path=${PWD}/

    if ! is_path_full "$path"; then
        # Path is a relative path, prepend PWD
        path=${PWD}/${path}
    fi

    if is_path_dir "$path"; then
        # Path is a directory, append default filename
        path=${path}$(to_lower "$buildID")_${LABEL}.tgz
    fi

    test ! -d "${path%/*}" && die "archiveOut directory not found: ${path%/*}/"

    SB_ARCHIVE_OUT=$path
fi

#
# If --archiveIn requested, import the file(s) now
#
if [ "$SB_ARCHIVE_IN" ]
then
    IFS=","
    for f in $SB_ARCHIVE_IN
    do
        f="${f# }"; f="${f% }" # strip leading or trailing space
        importArchive "$f"
    done
    unset IFS
fi

#
# Set arguments for (program) execution
#
test "$SB_VERBOSE" && DEBUG_ARGS=" -v"
test "$SB_DEBUG" && DEBUG_ARGS="$DEBUG_ARGS -d"
test "$SB_WRAP" && DEBUG_ARGS="$DEBUG_ARGS -w $SB_WRAP"
test "$HW_FLAGS" && ADDL_ARGS="$ADDL_ARGS --hw-flags $HW_FLAGS"
test "$SW_FLAGS" && ADDL_ARGS="$ADDL_ARGS --sw-flags $SW_FLAGS"
test "$CS_OFFSET" && ADDL_ARGS="$ADDL_ARGS --sw-cs-offset $CS_OFFSET"
test "$LABEL" && ADDL_ARGS="$ADDL_ARGS --label $LABEL"
test "$SECURITY_VERSION" && ADDL_ARGS="$ADDL_ARGS --security-version $SECURITY_VERSION"
test "$SB_CONTR_HDR_OUT" && CONTR_HDR_OUT_OPT="--dumpContrHdr"

test "$SB_VERBOSE" && SF_DEBUG_ARGS=" -v"
test "$SB_DEBUG" && SF_DEBUG_ARGS="$SF_DEBUG_ARGS -d -stdout"

#
# Set defaults for signframework project basenames
#
if [ "$SIGN_MODE" == "production" ]
then
: "${SF_HW_SIGNING_PROJECT_BASE:=sign_ecc_pwr_hw_key}"
: "${SF_FW_SIGNING_PROJECT_BASE:=sign_ecc_pwr_fw_key_op_bld}"
: "${SF_GETPUBKEY_PROJECT_BASE:=getpubkeyecc}"
fi

#
# Set defaults for PKCS11
#
: "${SB_PKCS11_MODULE:=/usr/lib64/pkcs11/libsofthsm2.so}"
: "${SB_PKCS11_TOKEN:=P9Signing}"

#
# Get the public keys
#
if [ "$SIGN_MODE" == "local" ] || [ "$SIGN_MODE" == "independent" ]
then
    for KEY in a b c; do
        # This will evaluate the value of HW_KEY_A, HW_KEY_B, HW_KEY_C
        varname=HW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && continue
        test "$KEYFILE" == __skip && continue
        if [ "$KEYFILE" == __get ] || [ "$KEYFILE" == __getkey ]
        then
            # We expect a key of of this signing project to be imported.
            test -z "$SF_HW_SIGNING_PROJECT_BASE" && \
                die "__get or __getkey requested but no project basename provided for HW key $(to_upper $KEY)."

            SF_PROJECT=${SF_HW_SIGNING_PROJECT_BASE}_${KEY}
            KEYFILE_BASE=project.$SF_PROJECT.HW_key_$KEY

            KEYFILE=$(findArtifact "$KEYFILE_BASE.pub" "$KEYFILE_BASE.raw")

            if [ "$KEYFILE" ]; then
                test "$SB_VERBOSE" && msg=" ($KEYFILE)"
                echo "--> $P: Found key for HW key $(to_upper $KEY).${msg}"
                KEYFILE="$T/$KEYFILE"
            else
                die "__get or __getkey requested but no imported key found for HW key $(to_upper $KEY)."
            fi
        else
            # The user provided KEYFILE should point to file on disk.
            # Copy the pubkey to the cache.
            if [ -f "$KEYFILE" ]; then
                if is_private_key "$KEYFILE"; then
                    openssl ec -in "$KEYFILE" -pubout -out "$T/HW_key_$KEY.pub" &>/dev/null
                elif is_public_key "$KEYFILE"; then
                    cp -p "$KEYFILE" "$T/HW_key_$KEY.pub"
                elif is_raw_key "$KEYFILE"; then
                    cp -p "$KEYFILE" "$T/HW_key_$KEY.raw"
                fi
            fi
        fi

        # Add to HW_KEY_ARGS
        HW_KEY_ARGS="$HW_KEY_ARGS -$KEY $KEYFILE"
    done

    for KEY in p q r; do
        # Find the value of SW_KEY_P, SW_KEY_Q, SW_KEY_R
        varname=SW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && break
        test "$KEYFILE" == __skip && break
        if [ "$KEYFILE" == __get ] || [ "$KEYFILE" == __getkey ]
        then
            # We expect a key of of this signing project to be imported.
            test -z "$SF_FW_SIGNING_PROJECT_BASE" && \
                die "__get or __getkey requested but no project basename provided for SW key $(to_upper $KEY)."

            SF_PROJECT=${SF_FW_SIGNING_PROJECT_BASE}_${KEY}
            KEYFILE_BASE=project.$SF_PROJECT.SW_key_$KEY

            KEYFILE=$(findArtifact "$KEYFILE_BASE.pub" "$KEYFILE_BASE.raw")

            if [ "$KEYFILE" ]; then
                test "$SB_VERBOSE" && msg=" ($KEYFILE)"
                echo "--> $P: Found key for SW key $(to_upper $KEY).${msg}"
                KEYFILE="$T/$KEYFILE"
            else
                die "__get or __getkey requested but no imported key found for SW key $(to_upper $KEY)."
            fi
        else
            # The user provided KEYFILE should point to file on disk.
            # Copy the pubkey to the cache.
            if [ -f "$KEYFILE" ]; then
                if is_private_key "$KEYFILE"; then
                    openssl ec -in "$KEYFILE" -pubout -out "$T/SW_key_$KEY.pub" &>/dev/null
                elif is_public_key "$KEYFILE"; then
                    cp -p "$KEYFILE" "$T/SW_key_$KEY.pub"
                elif is_raw_key "$KEYFILE"; then
                    cp -p "$KEYFILE" "$T/SW_key_$KEY.raw"
                fi
            fi
        fi

        # Add to SW_KEY_ARGS
        SW_KEY_ARGS="$SW_KEY_ARGS -$KEY $KEYFILE"
    done

elif [ "$SIGN_MODE" == "production" ]
then
    for KEY in a b c; do
        varname=HW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && continue
        test "$KEYFILE" == __skip && continue
        test "$KEYFILE" == __getsig && continue
        # TODO: Add full support for user-specified keys in Production mode.
        # Currently we use it only to check if __skip was specified.

        SF_PROJECT=${SF_HW_SIGNING_PROJECT_BASE}_${KEY}
        KEYFILE_BASE=project.$SF_PROJECT.HW_key_$KEY

        KEYFILE=$(findArtifact "$KEYFILE_BASE.pub" "$KEYFILE_BASE.raw")

        if [ "$KEYFILE" ]; then
            test "$SB_VERBOSE" && msg=" ($KEYFILE)"
            echo "--> $P: Found key for HW key $(to_upper $KEY).${msg}"
        else
            # No key found, request one.
            echo "--> $P: Requesting public key for HW key $(to_upper $KEY)..."

            if [ "$KMS" == "signframework" ]
            then
                # Output is pubkey in raw format
                KEYFILE="$KEYFILE_BASE.raw"
                sf_client $SF_DEBUG_ARGS -project "$SF_GETPUBKEY_PROJECT_BASE" \
                          -param "-signproject $SF_PROJECT" \
                          -epwd "$SF_EPWD" -comments "Requesting $SF_PROJECT" \
                          -url sftp://$SF_USER@$SF_SERVER -pkey "$SF_SSHKEY" \
                          -o "$T/$KEYFILE"

            elif [ "$KMS" == "pkcs11" ]
            then
                # Output is pubkey in PEM format
                KEYFILE="$KEYFILE_BASE.pub"
                pkcs11-tool --module $SB_PKCS11_MODULE \
                            --token-label $SB_PKCS11_TOKEN \
                            --read-object --type pubkey --label $SF_PROJECT | \
                    openssl ec -inform der -pubin -pubout -out "$T/$KEYFILE" &>/dev/null

            else
                die "Unsupported KMS: $KMS"
            fi

            rc=$?
            test $rc -ne 0 && die "Call to KMS client failed with error: $rc"

            test "$(find "$T" -name $KEYFILE)" || \
                die "Unable to retrieve HW key $(to_upper $KEY)."

            echo "--> $P: Retrieved public key for HW key $(to_upper $KEY)."
        fi

        # Add to HW_KEY_ARGS
        HW_KEY_ARGS="$HW_KEY_ARGS -$KEY $T/$KEYFILE"
    done

    for KEY in p q r; do
        varname=SW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && break
        test "$KEYFILE" == __skip && break
        test "$KEYFILE" == __getsig && continue

        SF_PROJECT=${SF_FW_SIGNING_PROJECT_BASE}_${KEY}
        KEYFILE_BASE=project.$SF_PROJECT.SW_key_$KEY

        KEYFILE=$(findArtifact "$KEYFILE_BASE.pub" "$KEYFILE_BASE.raw")

        if [ "$KEYFILE" ]; then
            test "$SB_VERBOSE" && msg=" ($KEYFILE)"
            echo "--> $P: Found key for SW key $(to_upper $KEY).${msg}"
        else
            # No key found, request one.
            echo "--> $P: Requesting public key for SW key $(to_upper $KEY)..."

            if [ "$KMS" == "signframework" ]
            then
                KEYFILE="$KEYFILE_BASE.raw"
                sf_client $SF_DEBUG_ARGS -project "$SF_GETPUBKEY_PROJECT_BASE" \
                          -param "-signproject $SF_PROJECT" \
                          -epwd "$SF_EPWD" -comments "Requesting $SF_PROJECT" \
                          -url sftp://$SF_USER@$SF_SERVER -pkey "$SF_SSHKEY" \
                          -o "$T/$KEYFILE"

            elif [ "$KMS" == "pkcs11" ]
            then
                KEYFILE="$KEYFILE_BASE.pub"
                pkcs11-tool --module $SB_PKCS11_MODULE \
                            --token-label $SB_PKCS11_TOKEN \
                            --read-object --type pubkey --label $SF_PROJECT | \
                    openssl ec -inform der -pubin -pubout -out "$T/$KEYFILE" &>/dev/null
            fi

            rc=$?
            test $rc -ne 0 && die "Call to KMS client failed with error: $rc"

            test "$(find "$T" -name $KEYFILE)" || \
                die "Unable to retrieve SW key $(to_upper $KEY)."

            echo "--> $P: Retrieved public key for SW key $(to_upper $KEY)."
        fi

        # Add to SW_KEY_ARGS
        SW_KEY_ARGS="$SW_KEY_ARGS -$KEY $T/$KEYFILE"
    done

elif [ "$SIGN_MODE" ]
then
    die "Unsupported mode: $SIGN_MODE"
fi

#
# Build enough of the container to create the Prefix and Software headers
#
if [ "$SIGN_MODE" == "independent" ] && [ "$SB_ARCHIVE_IN" ]
then
    echo "--> $P: Attempting to re-use existing signing requests..."
    # TODO: check that prefix_hdr and software_hdr files are available...
else
    echo "--> $P: Generating signing requests..."
    create-container $HW_KEY_ARGS $SW_KEY_ARGS \
                     --payload "$PAYLOAD" --imagefile "$OUTPUT" \
                     --dumpPrefixHdr "$T/prefix_hdr" \
                     --dumpSwHdr "$T/software_hdr" \
                     $DEBUG_ARGS \
                     $ADDL_ARGS
    rc=$?

    test $rc -ne 0 && die "Call to create-container failed with error: $rc"
fi

#
# Prepare the HW and SW key signatures
#
FOUND=""

if [ "$SIGN_MODE" == "local" ] || [ "$SIGN_MODE" == "independent" ]
then
    for KEY in a b c; do
        varname=HW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && continue
        test "$KEYFILE" == __skip && continue

        if [ "$KEYFILE" == __get ] || [ "$KEYFILE" == __getsig ]
        then
            # We expect a sig of of this signing project to be imported.
            test -z "$SF_HW_SIGNING_PROJECT_BASE" && \
                die "__get or __getsig requested but no project basename provided for HW key $(to_upper $KEY)."

            SF_PROJECT=${SF_HW_SIGNING_PROJECT_BASE}_${KEY}
            SIGFILE_BASE=project.$SF_PROJECT.HW_sig_$KEY

            SIGFILE=$(findArtifact "$SIGFILE_BASE.sig" "$SIGFILE_BASE.raw")

            if [ "$SIGFILE" ]; then
                test "$SB_VERBOSE" && msg=" ($SIGFILE)"
                echo "--> $P: Found sig for HW key $(to_upper $KEY).${msg}"
            else
                die "__get or __getsig requested but no imported sig found for HW key $(to_upper $KEY)."
            fi

            FOUND="${FOUND}$(to_upper $KEY),"
            HW_SIG_ARGS="$HW_SIG_ARGS -$(to_upper $KEY) $T/$SIGFILE"
            continue
        fi

        # Look for signature in the local cache dir.
        SIGFILE=HW_key_$KEY.sig

        if [ -f "$T/$SIGFILE" ]
        then
            test "$SB_VERBOSE" && msg=" ($SIGFILE)"
            echo "--> $P: Found signature for HW key $(to_upper $KEY).${msg}"
        else
            # Check elsewhere in the cache.
            if [ "$SIGN_MODE" == "independent" ] && [ "$SB_ARCHIVE_IN" ]
            then
                SIGFOUND=$(find "$TOPDIR" -type f -name $SIGFILE | head -1)
            else
                SIGFOUND=""
            fi

            if [ "$SIGFOUND" ]
            then
                test "$SB_VERBOSE" && msg=" ($SIGFILE)"
                echo "--> $P: Found signature for HW key $(to_upper $KEY).${msg}"
                cp -p "$SIGFOUND" "$T/"
            else
                # If no signature found, try to generate one.
                if [ -f "$KEYFILE" ] && is_private_key "$KEYFILE"
                then
                    echo "--> $P: Generating signature for HW key $(to_upper $KEY)..."
                    openssl dgst -SHA512 -sign "$KEYFILE" "$T/prefix_hdr" > "$T/$SIGFILE"
                    rc=$?
                    test $rc -ne 0 && die "Call to openssl failed with error: $rc"
                else
                    echo "--> $P: No signature found and no private key available for HW key $(to_upper $KEY), skipping."
                    continue
                fi
            fi
        fi

        FOUND="${FOUND}$(to_upper $KEY),"
        HW_SIG_ARGS="$HW_SIG_ARGS -$(to_upper $KEY) $T/$SIGFILE"
    done

    for KEY in p q r; do
        SIGFILE=SW_key_$KEY.sig
        varname=SW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && break
        test "$KEYFILE" == __skip && break

        # Look for a signature in the local cache dir, if found use it.
        # (but never reuse a sig for SBKT, the payload is always regenerated)
        if [ -f "$T/$SIGFILE" ] && \
           [ "$(to_upper "$LABEL")" != SBKT ] && \
           [ "$(to_upper "$LABEL")" != SBKTRAND ]
        then
            test "$SB_VERBOSE" && msg=" ($SIGFILE)"
            echo "--> $P: Found signature for SW key $(to_upper $KEY).${msg}"
        elif test -f "$KEYFILE" && is_private_key "$KEYFILE"
        then
            # No signature found, try to generate one.
            echo "--> $P: Generating signature for SW key $(to_upper $KEY)..."
            openssl dgst -SHA512 -sign "$KEYFILE" "$T/software_hdr" > "$T/$SIGFILE"
            rc=$?
            test $rc -ne 0 && die "Call to openssl failed with error: $rc"
        else
            echo "--> $P: No signature found and no private key available for SW key $(to_upper $KEY), skipping."
            continue
        fi

        FOUND="${FOUND}$(to_upper $KEY),"
        SW_SIG_ARGS="$SW_SIG_ARGS -$(to_upper $KEY) $T/$SIGFILE"
    done

elif [ "$SIGN_MODE" == "production" ]
then
    for KEY in a b c; do
        varname=HW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && continue
        test "$KEYFILE" == __skip && continue
        # TODO: Add full support for user-specified keys in Production mode.
        # Currently we use it only to check if __skip or __getkey was specified.

        SF_PROJECT=${SF_HW_SIGNING_PROJECT_BASE}_${KEY}
        SIGFILE_BASE=project.$SF_PROJECT.HW_sig_$KEY

        SIGFILE=$(findArtifact "$SIGFILE_BASE.sig" "$SIGFILE_BASE.raw")

        if [ "$SIGFILE" ]; then
            test "$SB_VERBOSE" && msg=" ($SIGFILE)"
            echo "--> $P: Found sig for HW key $(to_upper $KEY).${msg}"
        else
            # No signature found, request one.
            test "$KEYFILE" == __getkey && break  # (unless instructed not to)
            echo "--> $P: Requesting signature for HW key $(to_upper $KEY)..."

            if [ "$KMS" == "signframework" ]
            then
                # Output is signature in raw format
                SIGFILE="$SIGFILE_BASE.raw"
                sf_client $SF_DEBUG_ARGS -project $SF_PROJECT -epwd "$SF_EPWD" \
                          -comments "Requesting sig for $SF_PROJECT" \
                          -url sftp://$SF_USER@$SF_SERVER -pkey "$SF_SSHKEY" \
                          -payload  "$T/prefix_hdr" -o "$T/$SIGFILE"

            elif [ "$KMS" == "pkcs11" ]
            then
                # Output is signature in DER format
                SIGFILE="$SIGFILE_BASE.sig"
                /bin/openssl dgst -engine pkcs11 -keyform engine \
                             -sign "pkcs11:token=$SB_PKCS11_TOKEN;object=$SF_PROJECT" \
                             -sha512 -out "$T/$SIGFILE" "$T/prefix_hdr"
            fi

            rc=$?
            test $rc -ne 0 && die "Call to KMS client failed with error: $rc"

            test "$(find "$T" -name $SIGFILE)" || \
                die "Unable to retrieve sig for HW key $(to_upper $KEY)."

            echo "--> $P: Retrieved signature for HW key $(to_upper $KEY)."
        fi

        FOUND="${FOUND}$(to_upper $KEY),"
        HW_SIG_ARGS="$HW_SIG_ARGS -$(to_upper $KEY) $T/$SIGFILE"
    done

    for KEY in p q r; do
        varname=SW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && break
        test "$KEYFILE" == __skip && break

        SF_PROJECT=${SF_FW_SIGNING_PROJECT_BASE}_${KEY}
        SIGFILE_BASE=project.$SF_PROJECT.SW_sig_$KEY

        # Look for a signature in the local cache dir, if found use it.
        # (but never reuse a sig for SBKT, the payload is always regenerated)
        if [ "$(to_upper "$LABEL")" == SBKT ] || \
           [ "$(to_upper "$LABEL")" == SBKTRAND ]
        then
            SIGFILE=""
        else
            SIGFILE=$(findArtifact "./$SIGFILE_BASE.sig" "./$SIGFILE_BASE.raw")
        fi

        if [ "$SIGFILE" ]; then
            test "$SB_VERBOSE" && msg=" ($SIGFILE)"
            echo "--> $P: Found sig for SW key $(to_upper $KEY).${msg}"
        else
            # No signature found, request one.
            test "$KEYFILE" == __getkey && break  # (unless instructed not to)
            echo "--> $P: Requesting signature for SW key $(to_upper $KEY)..."

            if [ "$KMS" == "signframework" ]
            then
                # Output is signature in raw format
                SIGFILE="$SIGFILE_BASE.raw"
                sf_client $SF_DEBUG_ARGS -project $SF_PROJECT -epwd "$SF_EPWD" \
                          -comments "Requesting sig for $LABEL from $SF_PROJECT" \
                          -url sftp://$SF_USER@$SF_SERVER -pkey "$SF_SSHKEY" \
                          -payload "$T/software_hdr.md.bin" -o "$T/$SIGFILE"

            elif [ "$KMS" == "pkcs11" ]
            then
                # Output is signature in DER format
                SIGFILE="$SIGFILE_BASE.sig"
                /bin/openssl dgst -engine pkcs11 -keyform engine \
                             -sign "pkcs11:token=$SB_PKCS11_TOKEN;object=$SF_PROJECT" \
                             -sha512 -out "$T/$SIGFILE" "$T/software_hdr"
            fi

            rc=$?
            test $rc -ne 0 && die "Call to KMS client failed with error: $rc"

            test "$(find "$T" -name $SIGFILE)" || \
                die "Unable to retrieve sig for SW key $(to_upper $KEY)."

            echo "--> $P: Retrieved signature for SW key $(to_upper $KEY)."
        fi

        FOUND="${FOUND}$(to_upper $KEY),"
        SW_SIG_ARGS="$SW_SIG_ARGS -$(to_upper $KEY) $T/$SIGFILE"
    done
fi

#
# Build the full container
#
if [ "$HW_SIG_ARGS" ] || [ "$SW_SIG_ARGS" ]; then
    echo "--> $P: Have signatures for keys $FOUND adding to container..."
    create-container $HW_KEY_ARGS $SW_KEY_ARGS \
                     $HW_SIG_ARGS $SW_SIG_ARGS \
                     --payload "$PAYLOAD" --imagefile "$OUTPUT" \
                     $DEBUG_ARGS $ADDL_ARGS \
                     $CONTR_HDR_OUT_OPT "$SB_CONTR_HDR_OUT"
    rc=$?

    test $rc -ne 0 && die "Call to create-container failed with error: $rc"

    test "$SB_CONTR_HDR_OUT" && \
        echo "--> $P: Container header saved to: $SB_CONTR_HDR_OUT"

else
    echo "--> $P: No signatures available."
fi

echo "--> $P: Container $LABEL build completed."

#
# Export archive
#
test "$SB_ARCHIVE_OUT" && exportArchive "$SB_ARCHIVE_OUT"

#
# Validate, verify the container
#
if [ "$(to_upper $SB_VALIDATE)" != Y ] && \
   [ "$(to_upper $SB_VALIDATE)" != TRUE ]
then
    SB_VALIDATE=""
fi

if [ "$(to_upper $SB_PASS_ON_ERROR)" != Y ] && \
   [ "$(to_upper $SB_PASS_ON_ERROR)" != TRUE ]
then
    SB_PASS_ON_ERROR=""
fi

if [ "$(to_upper "$LABEL")" == SBKTRAND ]
then
    # Key transition container may have its own verify value
    test "$SB_VERIFY_TRANS" && SB_VERIFY=$SB_VERIFY_TRANS
fi

test "$SB_VALIDATE" && VALIDATE_OPT="--validate"
test "$SB_VERIFY" && VERIFY_OPT="--verify" && VERIFY_ARGS="$SB_VERIFY"

if [ "$VALIDATE_OPT" ] || [ "$VERIFY_OPT" ]; then
    echo
    print-container --imagefile "$OUTPUT" --no-print \
                    $DEBUG_ARGS $VALIDATE_OPT $VERIFY_OPT "$VERIFY_ARGS"

    test $? -ne 0 && test -z $SB_PASS_ON_ERROR && RC=1
fi

#
# Cleanup
#
if [ $SB_KEEP_CACHE == false ]; then
    test "$SB_VERBOSE" && \
        echo "--> $P: Removing cache dir: $TOPDIR"
    rm -rf "$TOPDIR"
fi

if [ $OUTPUT_SCRATCH == true ]; then
    rm "$OUTPUT"
fi

exit $RC
