#ifndef __CURLFTPFS_FTPFS_LS_H__
#define __CURLFTPFS_FTPFS_LS_H__

/*
    FTP file system
    Copyright (C) 2006 Robson Braga Araujo <robsonbraga@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "cache.h"

int parse_dir(const char* list, const char* dir,
              const char* name, struct stat* sbuf,
              char* linkbuf, int linklen,
              fuse_cache_dirh_t h, fuse_cache_dirfil_t filler);

#endif  /* __CURLFTPFS_FTPFS_LS_H__ */
