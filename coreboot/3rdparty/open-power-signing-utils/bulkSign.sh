#!/bin/bash
#
# Script to handle signing requests in bulk.
# Intended for stand-alone independent mode signing.
#

# Defaults, initial values
P=${0##*/}

DEBUG_ARGS=""

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
    echo "	    --archiveOut        file or directory to write archive (tarball) of artifacts"
    echo "	                        if directory, must end in '/'.  for PWD, use '.'"
    echo "	    --archiveIn         directory holding signing request archive files"
    echo "	                        value, or filename containing value, of the HW Keys hash"
    echo ""
    exit 1
}

die () {
    echo "$P: $*" 1>&2
    exit 1
}

is_cmd_available () {
    command -v "$1" &>/dev/null
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
    "--hwKeyA")     set -- "$@" "-a" ;;
    "--hwKeyB")     set -- "$@" "-b" ;;
    "--hwKeyC")     set -- "$@" "-c" ;;
    "--swKeyP")     set -- "$@" "-p" ;;
    "--swKeyQ")     set -- "$@" "-q" ;;
    "--swKeyR")     set -- "$@" "-r" ;;
    "--archiveIn")  set -- "$@" "-6" ;;
    "--archiveOut") set -- "$@" "-7" ;;
    *)              set -- "$@" "$arg"
  esac
done

# Process command-line arguments
while getopts -- ?hdvw:a:b:c:p:q:r:6:7: opt
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
    6) SB_ARCHIVE_IN="$OPTARG";;
    7) SB_ARCHIVE_OUT="$OPTARG";;
    h|\?) usage;;
  esac
done

# Check required programs
for p in crtSignedContainer.sh create-container print-container
do
    is_cmd_available $p || \
        die "Required command \"$p\" not available or not found in PATH"
done

#
# Set arguments for (program) execution
#
test "$SB_VERBOSE" && DEBUG_ARGS=" -v"
test "$SB_DEBUG" && DEBUG_ARGS="$DEBUG_ARGS -d"
test "$SB_WRAP" && DEBUG_ARGS="$DEBUG_ARGS -w $SB_WRAP"

#
# Bulk-sign all requests in the specified directory
#
cd "$SB_ARCHIVE_IN" || die "Cannot cd to $SB_ARCHIVE_IN"

for f in *.tgz
do
    label="$(echo "$f" | cut -d '.' -f1 | cut -d '_' -f3-)"
    echo "Handling signing request \"$f\" with label: $label"
    crtSignedContainer.sh -m independent \
        -a "$HW_KEY_A" -b "$HW_KEY_B" -c "$HW_KEY_C" \
        -p "$SW_KEY_P" -q "$SW_KEY_Q" -r "$SW_KEY_R" \
        --archiveOut "$SB_ARCHIVE_OUT" --archiveIn "$f" \
        --label "$label" $DEBUG_ARGS
done

exit $RC
