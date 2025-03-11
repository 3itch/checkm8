# autoconf script

AC_PREREQ([2.65])
AC_INIT(sb-signtool, 0.9-preview, matthew.vaught@ibm.com)
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Check for headers
AC_HEADER_STDC

# Check endianness
AC_MSG_CHECKING([system endianness])
AC_PREPROC_IFELSE(
  [AC_LANG_PROGRAM([[#include <endian.h>]],
		   [[#if __BYTE_ORDER != __LITTLE_ENDIAN]]
		   [[#error]]
		   [[#endif]])],
  endian=little
  little_endian=1
  big_endian=0)

AC_PREPROC_IFELSE(
  [AC_LANG_PROGRAM([[#include <endian.h>]],
		   [[#if __BYTE_ORDER != __BIG_ENDIAN]]
		   [[#error]]
		   [[#endif]])],
  endian=big
  little_endian=0
  big_endian=1)

if test x"$endian" != "xbig" -a x"$endian" != "xlittle"; then
  AC_MSG_ERROR([Can't determine endianness; is endian.h present?])
fi
AC_MSG_RESULT($endian)
AC_DEFINE_UNQUOTED(HAVE_LITTLE_ENDIAN, $little_endian, [Little-endian system])
AC_DEFINE_UNQUOTED(HAVE_BIG_ENDIAN, $big_endian, [Big-endian system])

# Openssl checks
PKG_CHECK_MODULES(OPENSSL, [ openssl >= 1.0.1 ])
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)
AC_CHECK_HEADER(unistd.h)
AC_CHECK_HEADERS(openssl/ec.h)
AC_CHECK_HEADERS(openssl/ecdsa.h)
AC_CHECK_HEADERS(openssl/pem.h)
AC_CHECK_HEADERS(openssl/sha.h)

# Compiler flags
AM_CPPFLAGS="-Wall -Wextra"
AC_SUBST(AM_CPPFLAGS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

# Done.
echo
echo	"Configuration: done."
echo
