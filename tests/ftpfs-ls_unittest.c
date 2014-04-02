/*
    FTP file system
    Copyright (C) 2006 Robson Braga Araujo <robsonbraga@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#define _XOPEN_SOURCE 600  /* glibc2 needs this */
#include <time.h>                                                        
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "ftpfs.h"
#include "ftpfs-ls.h"

struct ftpfs ftpfs;

#define check(sbuf, dev, ino, mode, nlink, uid, gid, \
              rdev, size, blksize, blocks, date) \
  do { \
  struct tm tm; \
  time_t tt; \
  memset(&tm, 0, sizeof(tm)); \
  strptime(date, "%H:%M:%S %d/%m/%Y", &tm); \
  tt = mktime(&tm); \
  assert(sbuf.st_dev == (dev)); \
  assert(sbuf.st_ino == (ino)); \
  assert(sbuf.st_mode == (mode)); \
  assert(sbuf.st_nlink == (nlink)); \
  assert(sbuf.st_uid == (uid)); \
  assert(sbuf.st_gid == (gid)); \
  assert(sbuf.st_rdev == (rdev)); \
  assert(sbuf.st_size == (size)); \
  assert(sbuf.st_blksize == (blksize)); \
  assert(sbuf.st_blocks == (blocks)); \
  assert(sbuf.st_atime == tt); \
  assert(sbuf.st_ctime == tt); \
  assert(sbuf.st_mtime == tt); \
  } while (0);

int main(int argc, char **argv) {
  const char *list;
  char line[256];
  struct fuse_cache_operations dummy_oper;
  struct stat sbuf;
  int err;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  char linkbuf[1024];
  char date[20];
  time_t tt;
  struct tm tm;
  struct tm test_tm;

  ftpfs.debug = 1;

  tt = time(NULL);
  gmtime_r(&tt, &tm);
  ftpfs.blksize = 4096;

  memset(&dummy_oper, 0, sizeof(dummy_oper));
  err = cache_parse_options(&args);
  cache_init(&dummy_oper);

  list = "05-22-03  12:13PM       <DIR>          chinese_pr\r\n";
  err = parse_dir(list, "/", "chinese_pr", &sbuf, NULL, 0, NULL, NULL);
  assert(err == 0);
  check(sbuf, 0, 0, S_IFDIR, 1, 0, 0, 0, 0, 0, 0, "12:13:00 22/05/2003");

  err = parse_dir(list, "/", "hinese_pr", &sbuf, NULL, 0, NULL, NULL);
  assert(err == 1);

  list = "05-14-03  02:49PM                40448 PR_AU13_CH.doc\r\n";
  err = parse_dir(list, "/", "PR_AU13_CH.doc", &sbuf, NULL, 0, NULL, NULL);
  assert(err == 0);
  check(sbuf, 0, 0, S_IFREG, 1, 0, 0, 0, 40448, 4096, 80, "14:49:00 14/05/2003");

  list = "11-25-04  09:17AM             20075882 242_310_Condor_en_ok.pdf\r\n";
  err = parse_dir(list, "/", "242_310_Condor_en_ok.pdf", &sbuf, NULL, 0, NULL, NULL);
  assert(err == 0);
  check(sbuf, 0, 0, S_IFREG, 1, 0, 0, 0, 20075882, 4096, 39216, "09:17:00 25/11/2004");

  list = "lrwxrwxrwx   1 1             17 Nov 24  2002 lg -> cidirb/documentos\r\n";
  err = parse_dir(list, "/", "lg", &sbuf, linkbuf, 1024, NULL, NULL);
  assert(err == 0);
  assert(!strcmp(linkbuf, "cidirb/documentos"));
  check(sbuf, 0, 0, S_IFLNK|S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH, 1, 0, 0, 0, 17, 4096, 8, "00:00:00 24/11/2002");

  list = "lrwxrwxrwx    1 1137     1100           14 Mar 12  2004 molbio -> Science/molbio\r\n";
  err = parse_dir(list, "/", "molbio", &sbuf, linkbuf, 1024, NULL, NULL);
  assert(err == 0);
  assert(!strcmp(linkbuf, "Science/molbio"));
  check(sbuf, 0, 0, S_IFLNK|S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH, 1, 0, 0, 0, 14, 4096, 8, "00:00:00 12/03/2004");

  // Test a date six months in the past
  test_tm = tm;
  test_tm.tm_mon -= 6;
  if (test_tm.tm_mon < 0) {
    test_tm.tm_mon += 12;
    test_tm.tm_year--;
  }
  strftime(line, 256,
           "drwxr-xr-x  4 robson users   4096 %b %d 00:00 tests\r\n", &test_tm);
  err = parse_dir(line, "/", "tests", &sbuf, NULL, 0, NULL, NULL);
  assert(err == 0);
  strftime(date, 20, "00:00:00 %d/%m/%Y", &test_tm);
  check(sbuf, 0, 0, S_IFDIR|S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH, 4, 0, 0, 0, 4096, 4096, 8, date);

  list = "dr-xr-xr-x   2 root     512 Apr  8  1994 etc\r\n";
  err = parse_dir(list, "/", "etc", &sbuf, NULL, 0, NULL, NULL);
  assert(err == 0);
  check(sbuf, 0, 0, S_IFDIR|S_IRUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH, 2, 0, 0, 0, 512, 4096, 8, "00:00:00 08/04/1994");

  // Test a date a little bit in the past
  test_tm = tm;
  strftime(line, 256,
           "----------  1 robson users   1803128 %b %d 00:00 ls-lR.Z\r\n",
           &test_tm);
  err = parse_dir(line, "/", "ls-lR.Z", &sbuf, NULL, 0, NULL, NULL);
  assert(err == 0);
  strftime(date, 20, "00:00:00 %d/%m/%Y", &test_tm);
  check(sbuf, 0, 0, S_IFREG, 1, 0, 0, 0, 1803128, 4096, 3528, date);

  // Test a file with space
  list = "-rw-r--r--  1 robson users   1803128 Jan 01  2001  test\r\n";
  err = parse_dir(list, "/", " test", &sbuf, NULL, 0, NULL, NULL);
  assert(err == 0);
  check(sbuf, 0, 0, S_IFREG|S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH, 1, 0, 0, 0, 1803128, 4096, 3528, "00:00:00 01/01/2001");

  list = "drwxrwsr-x+ 14 cristol molvis 1024 Feb 17 2000 v2\r\n";
  err = parse_dir(list, "/", "v2", &sbuf, NULL, 0, NULL, NULL);
  assert(err == 0);
  check(sbuf, 0, 0, S_IFDIR|S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IXOTH, 14, 0, 0, 0, 1024, 4096, 8, "00:00:00 17/02/2000");

  list = "drwxrwsr-x+144 cristol molvis 10240 Dec 31 2005 v11\r\n";
  err = parse_dir(list, "/", "v11", &sbuf, NULL, 0, NULL, NULL);
  assert(err == 0);
  check(sbuf, 0, 0, S_IFDIR|S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IXOTH, 144, 0, 0, 0, 10240, 4096, 24, "00:00:00 31/12/2005");

  list = "-rw-------    1 6700     2000     6561177600 Oct 15 2005 home.backup.tar\r\n";
  err = parse_dir(list, "/", "home.backup.tar", &sbuf, NULL, 0, NULL, NULL);
  assert(err == 0);
  check(sbuf, 0, 0, S_IFREG|S_IRUSR|S_IWUSR, 1, 0, 0, 0, 6561177600LL, 4096, 4426192, "00:00:00 15/10/2005");

  return 0;
}
