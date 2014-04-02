## Process this file with automake to produce Makefile.in
SUBDIRS = compat doc

DIST_SUBDIRS = $(SUBDIRS) tests

LIBICONV = @LIBICONV@

AM_CPPFLAGS = -DFUSE_USE_VERSION=26
AM_LDFLAGS = $(LIBICONV)

bin_PROGRAMS = curlftpfs

curlftpfs_SOURCES = ftpfs.c
if FUSE_OPT_COMPAT
curlftpfs_LDADD = libcurlftpfs.a compat/libcompat.la
else
curlftpfs_LDADD = libcurlftpfs.a
endif

noinst_LIBRARIES = libcurlftpfs.a

libcurlftpfs_a_SOURCES = cache.c cache.h \
			 ftpfs-ls.c ftpfs-ls.h \
			 charset_utils.c charset_utils.h \
			 path_utils.c path_utils.h ftpfs.h

check: test

test:
	@(cd tests; $(MAKE) test)
