EXTRA_DIST = run_tests.sh

noinst_PROGRAMS = ftpfs-ls_unittest

AM_CPPFLAGS = -DFUSE_USE_VERSION=25

ftpfs_ls_unittest_SOURCES = ftpfs-ls_unittest.c
if FUSE_OPT_COMPAT
ftpfs_ls_unittest_LDADD = ../libcurlftpfs.a ../compat/libcompat.la
else
ftpfs_ls_unittest_LDADD = ../libcurlftpfs.a
endif

test: all
	@./run_tests.sh
