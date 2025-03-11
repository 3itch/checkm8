#!/bin/bash

set -e

export PREFIX="$PWD"
export TARGET=i686-elf
export PATH="$PREFIX/bin:$PATH"

################### BINUTILS

wget https://ftp.gnu.org/gnu/binutils/binutils-2.41.tar.gz

tar -xzf binutils-2.41.tar.gz

cd binutils-2.41

mkdir build-binutils

cd build-binutils

../configure --target=$TARGET --prefix="$PREFIX" --disable-nls --disable-werror

make

make install

################### GCC

wget https://ftp.gnu.org/gnu/gcc/gcc-13.2.0/gcc-13.2.0.tar.gz

tar -xzf gcc-13.2.0.tar.gz

cd gcc-13.2.0

./contrib/download_prerequisites

mkdir build-gcc

cd build-gcc

../configure --target=$TARGET --prefix="$PREFIX" --disable-nls --enable-languages=c --without-headers

make all-gcc
make all-target-libgcc
make install-gcc
make install-target-libgcc

echo 'export PATH="$PWD/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
