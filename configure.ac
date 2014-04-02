AC_INIT(curlftpfs, 0.9.2)
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

PKG_CHECK_MODULES(GLIB, [glib-2.0])
PKG_CHECK_MODULES(FUSE, [fuse >= 2.2])

LIBCURL_CHECK_CONFIG([yes], [7.17.0], [], [AC_MSG_ERROR(["libcurl not found"])])
if test "$libcurl_protocol_FTP" != yes; then
	AC_MSG_ERROR(["We need libcurl with support for FTP protocol."])
fi

CFLAGS="$CFLAGS -Wall -W -Wno-sign-compare -D_REENTRANT $GLIB_CFLAGS $FUSE_CFLAGS $LIBCURL_CPPFLAGS"
LIBS="$GLIB_LIBS $FUSE_LIBS $LIBCURL"

have_fuse_opt_parse=no
AC_CHECK_FUNC([fuse_opt_parse], [have_fuse_opt_parse=yes])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h netinet/in.h stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_HEADER_TIME
AC_STRUCT_TM
#AC_TYPE_UINT32_T
#AC_TYPE_UINT64_T
#AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STRFTIME
AC_FUNC_UTIME_NULL
AC_CHECK_FUNCS([ftruncate getpass memmove memset mkdir realpath rmdir select strchr strdup strrchr strstr strtoull utime])

# Check for iconv
AM_ICONV

if test "$have_fuse_opt_parse" = no; then
	CFLAGS="$CFLAGS -Icompat -I../compat"
fi
AM_CONDITIONAL(FUSE_OPT_COMPAT, test "$have_fuse_opt_parse" = no)

AC_CONFIG_FILES([Makefile compat/Makefile tests/Makefile doc/Makefile])
AC_OUTPUT
