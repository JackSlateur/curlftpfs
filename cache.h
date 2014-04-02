#ifndef __CURLFTPFS_CACHE_H__
#define __CURLFTPFS_CACHE_H__

/*
    Caching file system proxy
    Copyright (C) 2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <fuse.h>
#include <fuse_opt.h>

#ifndef FUSE_VERSION
#define FUSE_VERSION (FUSE_MAJOR_VERSION * 10 + FUSE_MINOR_VERSION)
#endif

#define DEFAULT_CACHE_TIMEOUT 10
#define MAX_CACHE_SIZE 10000
#define MIN_CACHE_CLEAN_INTERVAL 5
#define CACHE_CLEAN_INTERVAL 60

typedef struct fuse_cache_dirhandle *fuse_cache_dirh_t;
typedef int (*fuse_cache_dirfil_t) (fuse_cache_dirh_t h, const char *name,
                                    const struct stat *stbuf);

struct fuse_cache_operations {
    struct fuse_operations oper;
    int (*cache_getdir) (const char *, fuse_cache_dirh_t, fuse_cache_dirfil_t);
};

struct fuse_operations *cache_init(struct fuse_cache_operations *oper);
int cache_parse_options(struct fuse_args *args);
void cache_add_attr(const char *path, const struct stat *stbuf);
void cache_add_dir(const char *path, char **dir);
void cache_add_link(const char *path, const char *link, size_t size);

#endif   /* __CURLFTPFS_CACHE_H__ */
