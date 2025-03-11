#!/bin/bash

[ "$#" -gt "1" ] && echo "Too many args." && exit 1
[ "$#" -lt "1" ] && set -- "$@" "lite"

case "$(echo "$1" | tr "[:upper:]" "[:lower:]")" in
  lite|light)
    make clean
    ;;
  gnu)
    make clean
    rm -f compile config.guess config.sub depcomp install-sh ltmain.sh missing
    rm -f config.status config.h config.h.in* config.log configure
    rm -f libtool Makefile.in Makefile stamp-h1
    rm -rf -- autom4te.cache/ *.m4 m4/*
    ;;
  *)
    echo "Unknown build type: $1"
    exit 1
    ;;
esac
