#ifndef __CURLFTPFS_FTPFS_H__
#define __CURLFTPFS_FTPFS_H__

/*
    FTP file system
    Copyright (C) 2006 Robson Braga Araujo <robsonbraga@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <curl/curl.h>
#include <curl/easy.h>
#include <pthread.h>
#include <pthread.h>

struct ftpfs {
  char* host;
  char* mountpoint;
  pthread_mutex_t lock;
  CURL* connection;
  CURLM* multi;
  int attached_to_multi;
  struct ftpfs_file* current_fh;
  unsigned blksize;
  int verbose;
  int debug;
  int transform_symlinks;
  int disable_epsv;
  int skip_pasv_ip;
  char* ftp_method;
  char* custom_list;
  int tcp_nodelay;
  char* ftp_port;
  int disable_eprt;
  int connect_timeout;
  int use_ssl;
  int no_verify_hostname;
  int no_verify_peer;
  char* cert;
  char* cert_type;
  char* key;
  char* key_type;
  char* key_password;
  char* engine;
  char* cacert;
  char* capath;
  char* ciphers;
  char* interface;
  char* krb4;
  char* proxy;
  int proxytunnel;
  int proxyanyauth;
  int proxybasic;
  int proxydigest;
  int proxyntlm;
  int proxytype;
  char* user;
  char* proxy_user;
  int ssl_version;
  int ip_version;
  char symlink_prefix[PATH_MAX+1];
  size_t symlink_prefix_len;
  curl_version_info_data* curl_version;
  int safe_nobody;
  int tryutf8;
  char *codepage;
  char *iocharset;
  int multiconn;
};

extern struct ftpfs ftpfs;

#define DEBUG(level, args...) \
        do { if (level <= ftpfs.debug) {\
               int i = 0; \
               while (++i < level) fprintf(stderr, " "); \
               fprintf(stderr, "%ld ", time(NULL));\
               fprintf(stderr, __FILE__ ":%d ", __LINE__);\
               fprintf(stderr, args);\
             }\
           } while(0)

#endif   /* __CURLFTPFS_FTPFS_H__ */
