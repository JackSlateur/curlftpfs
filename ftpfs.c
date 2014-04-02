/*
    FTP file system
    Copyright (C) 2006 Robson Braga Araujo <robsonbraga@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <glib.h>
#include <semaphore.h>
#include <assert.h>

#include "charset_utils.h"
#include "path_utils.h"
#include "ftpfs-ls.h"
#include "cache.h"
#include "ftpfs.h"

#define CURLFTPFS_BAD_NOBODY 0x070f02
#define CURLFTPFS_BAD_SSL 0x070f03

#define CURLFTPFS_BAD_READ ((size_t)-1)

#define MAX_BUFFER_LEN (300*1024)

struct ftpfs ftpfs;
static char error_buf[CURL_ERROR_SIZE];

struct buffer {
  uint8_t* p;
  size_t len;
  size_t size;
  off_t begin_offset;
};

static void usage(const char* progname);

static void buf_init(struct buffer* buf)
{
    buf->p = NULL;
    buf->begin_offset = 0;
    buf->len = 0;
    buf->size = 0;
}

static inline void buf_free(struct buffer* buf)
{
    free(buf->p);
}

static inline void buf_clear(struct buffer *buf)
{
    buf_free(buf);
    buf_init(buf);
}

static int buf_resize(struct buffer *buf, size_t len)
{
    buf->size = (buf->len + len + 63) & ~31;
    buf->p = (uint8_t *) realloc(buf->p, buf->size);
    if (!buf->p) {
        fprintf(stderr, "ftpfs: memory allocation failed\n");
        return -1;
    }
    return 0;
}

static int buf_add_mem(struct buffer *buf, const void *data, size_t len)
{
    if (buf->len + len > buf->size && buf_resize(buf, len) == -1)
        return -1;

    memcpy(buf->p + buf->len, data, len);
    buf->len += len;
    return 0;
}

static void buf_null_terminate(struct buffer *buf)
{
    if (buf_add_mem(buf, "\0", 1) == -1)
        exit(1);
}

struct ftpfs_file {
  struct buffer buf;
  int dirty;
  int copied;
  off_t last_offset;
  int can_shrink;
  pthread_t thread_id;
  mode_t mode;
  char * open_path;
  char * full_path;
  struct buffer stream_buf;
  CURL *write_conn;
  sem_t data_avail;
  sem_t data_need;
  sem_t data_written;
  sem_t ready;
  int isready;
  int eof;
  int written_flag;
  int write_fail_cause;
  int write_may_start;
  char curl_error_buffer[CURL_ERROR_SIZE];
  off_t pos;
};

enum {
  KEY_HELP,
  KEY_VERBOSE,
  KEY_VERSION,
};

#define FTPFS_OPT(t, p, v) { t, offsetof(struct ftpfs, p), v }

static struct fuse_opt ftpfs_opts[] = {
  FTPFS_OPT("ftpfs_debug=%u",     debug, 0),
  FTPFS_OPT("transform_symlinks", transform_symlinks, 1),
  FTPFS_OPT("disable_epsv",       disable_epsv, 1),
  FTPFS_OPT("enable_epsv",        disable_epsv, 0),
  FTPFS_OPT("skip_pasv_ip",       skip_pasv_ip, 1),
  FTPFS_OPT("ftp_port=%s",        ftp_port, 0),
  FTPFS_OPT("disable_eprt",       disable_eprt, 1),
  FTPFS_OPT("ftp_method=%s",      ftp_method, 0),
  FTPFS_OPT("custom_list=%s",     custom_list, 0),
  FTPFS_OPT("tcp_nodelay",        tcp_nodelay, 1),
  FTPFS_OPT("connect_timeout=%u", connect_timeout, 0),
  FTPFS_OPT("ssl",                use_ssl, CURLFTPSSL_ALL),
  FTPFS_OPT("ssl_control",        use_ssl, CURLFTPSSL_CONTROL),
  FTPFS_OPT("ssl_try",            use_ssl, CURLFTPSSL_TRY),
  FTPFS_OPT("no_verify_hostname", no_verify_hostname, 1),
  FTPFS_OPT("no_verify_peer",     no_verify_peer, 1),
  FTPFS_OPT("cert=%s",            cert, 0),
  FTPFS_OPT("cert_type=%s",       cert_type, 0),
  FTPFS_OPT("key=%s",             key, 0),
  FTPFS_OPT("key_type=%s",        key_type, 0),
  FTPFS_OPT("pass=%s",            key_password, 0),
  FTPFS_OPT("engine=%s",          engine, 0),
  FTPFS_OPT("cacert=%s",          cacert, 0),
  FTPFS_OPT("capath=%s",          capath, 0),
  FTPFS_OPT("ciphers=%s",         ciphers, 0),
  FTPFS_OPT("interface=%s",       interface, 0),
  FTPFS_OPT("krb4=%s",            krb4, 0),
  FTPFS_OPT("proxy=%s",           proxy, 0),
  FTPFS_OPT("proxytunnel",        proxytunnel, 1),
  FTPFS_OPT("proxy_anyauth",      proxyanyauth, 1),
  FTPFS_OPT("proxy_basic",        proxybasic, 1),
  FTPFS_OPT("proxy_digest",       proxydigest, 1),
  FTPFS_OPT("proxy_ntlm",         proxyntlm, 1),
  FTPFS_OPT("httpproxy",          proxytype, CURLPROXY_HTTP),
  FTPFS_OPT("socks4",             proxytype, CURLPROXY_SOCKS4),
  FTPFS_OPT("socks5",             proxytype, CURLPROXY_SOCKS5),
  FTPFS_OPT("user=%s",            user, 0),
  FTPFS_OPT("proxy_user=%s",      proxy_user, 0),
  FTPFS_OPT("tlsv1",              ssl_version, CURL_SSLVERSION_TLSv1),
  FTPFS_OPT("sslv3",              ssl_version, CURL_SSLVERSION_SSLv3),
  FTPFS_OPT("ipv4",               ip_version, CURL_IPRESOLVE_V4),
  FTPFS_OPT("ipv6",               ip_version, CURL_IPRESOLVE_V6),
  FTPFS_OPT("utf8",               tryutf8, 1),
  FTPFS_OPT("codepage=%s",        codepage, 0),
  FTPFS_OPT("iocharset=%s",       iocharset, 0),
  FTPFS_OPT("nomulticonn",        multiconn, 0),

  FUSE_OPT_KEY("-h",             KEY_HELP),
  FUSE_OPT_KEY("--help",         KEY_HELP),
  FUSE_OPT_KEY("-v",             KEY_VERBOSE),
  FUSE_OPT_KEY("--verbose",      KEY_VERBOSE),
  FUSE_OPT_KEY("-V",             KEY_VERSION),
  FUSE_OPT_KEY("--version",      KEY_VERSION),
  FUSE_OPT_END
};

static struct ftpfs_file *get_ftpfs_file(struct fuse_file_info *fi)
{
  return (struct ftpfs_file *) (uintptr_t) fi->fh;
}

static void cancel_previous_multi()
{
  //curl_multi_cleanup(ftpfs.multi);
  
  if (!ftpfs.attached_to_multi) return;
  
  DEBUG(1, "cancel previous multi\n");
  
  CURLMcode curlMCode = curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
  if (curlMCode != CURLE_OK)
  {
      fprintf(stderr, "curl_multi_remove_handle problem: %d\n", curlMCode);
      exit(1);
  }
  ftpfs.attached_to_multi = 0;  
}

static int op_return(int err, char * operation)
{
	if(!err)
	{
		DEBUG(2, "%s successful\n", operation);
		return 0;
	}
	fprintf(stderr, "ftpfs: operation %s failed because %s\n", operation, strerror(-err));
	return err;
}


static size_t write_data(void *ptr, size_t size, size_t nmemb, void *data) {
  struct ftpfs_file* fh = (struct ftpfs_file*)data;
  if (fh == NULL) return 0;
  size_t to_copy = size * nmemb;
  if (to_copy > fh->buf.len - fh->copied) {
    to_copy = fh->buf.len - fh->copied;
  }
  DEBUG(2, "write_data: %zu\n", to_copy);
  DEBUG(3, "%*s\n", (int)to_copy, (char*)ptr);
  memcpy(ptr, fh->buf.p + fh->copied, to_copy);
  fh->copied += to_copy;
  return to_copy;
}

static size_t read_data(void *ptr, size_t size, size_t nmemb, void *data) {
  struct buffer* buf = (struct buffer*)data;
  if (buf == NULL) return size * nmemb;
  if (buf_add_mem(buf, ptr, size * nmemb) == -1)
    return 0;

  DEBUG(2, "read_data: %zu\n", size * nmemb);
  DEBUG(3, "%*s\n", (int)(size * nmemb), (char*)ptr);
  return size * nmemb;
}

#define curl_easy_setopt_or_die(handle, option, ...) \
  do {\
    CURLcode res = curl_easy_setopt(handle, option, __VA_ARGS__);\
    if (res != CURLE_OK) {\
      fprintf(stderr, "Error setting curl: %s\n", error_buf);\
      exit(1);\
    }\
  }while(0)

static int ftpfs_getdir(const char* path, fuse_cache_dirh_t h,
                        fuse_cache_dirfil_t filler) {
  int err = 0;
  CURLcode curl_res;
  char* dir_path = get_fulldir_path(path);

  DEBUG(1, "ftpfs_getdir: %s\n", dir_path);
  struct buffer buf;
  buf_init(&buf);

  pthread_mutex_lock(&ftpfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, dir_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_res = curl_easy_perform(ftpfs.connection);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    DEBUG(1, "%s\n", error_buf);
    err = -EIO;
  } else {
    buf_null_terminate(&buf);
    parse_dir((char*)buf.p, dir_path + strlen(ftpfs.host) - 1,
              NULL, NULL, NULL, 0, h, filler); 
  }

  free(dir_path);
  buf_free(&buf);
  return op_return(err, "ftpfs_getdir");
}

static int ftpfs_getattr(const char* path, struct stat* sbuf) {
  int err;
  CURLcode curl_res;
  char* dir_path = get_dir_path(path);

  DEBUG(2, "ftpfs_getattr: %s dir_path=%s\n", path, dir_path);
  struct buffer buf;
  buf_init(&buf);

  pthread_mutex_lock(&ftpfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, dir_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_res = curl_easy_perform(ftpfs.connection);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    DEBUG(1, "%s\n", error_buf);
  }
  buf_null_terminate(&buf);

  char* name = strrchr(path, '/');
  ++name;
  err = parse_dir((char*)buf.p, dir_path + strlen(ftpfs.host) - 1,
                  name, sbuf, NULL, 0, NULL, NULL); 

  free(dir_path);
  buf_free(&buf);
  if (err) return op_return(-ENOENT, "ftpfs_getattr");
  return 0;
}


static int check_running() {
  int running_handles = 0;
  curl_multi_perform(ftpfs.multi, &running_handles);
  return running_handles;
}

static size_t ftpfs_read_chunk(const char* full_path, char* rbuf,
                               size_t size, off_t offset,
                               struct fuse_file_info* fi,
                               int update_offset) {
  int running_handles = 0;
  int err = 0;
  struct ftpfs_file* fh = get_ftpfs_file(fi);

  DEBUG(2, "ftpfs_read_chunk: %s %p %zu %lld %p %p\n",
        full_path, rbuf, size, offset, fi, fh);

  pthread_mutex_lock(&ftpfs.lock);

  DEBUG(2, "buffer size: %zu %lld\n", fh->buf.len, fh->buf.begin_offset);

  if ((fh->buf.len < size + offset - fh->buf.begin_offset) ||
      offset < fh->buf.begin_offset ||
      offset > fh->buf.begin_offset + fh->buf.len) {
    // We can't answer this from cache
    if (ftpfs.current_fh != fh ||
        offset < fh->buf.begin_offset ||
        offset > fh->buf.begin_offset + fh->buf.len ||
        !check_running()) {
      DEBUG(1, "We need to restart the connection %p\n", ftpfs.connection);
      DEBUG(2, "current_fh=%p fh=%p\n", ftpfs.current_fh, fh);
      DEBUG(2, "buf.begin_offset=%lld offset=%lld\n", fh->buf.begin_offset, offset);

      buf_clear(&fh->buf);
      fh->buf.begin_offset = offset;
      ftpfs.current_fh = fh;

      cancel_previous_multi();
      
      curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
      curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &fh->buf);
      if (offset) {
        char range[15];
        snprintf(range, 15, "%lld-", (long long) offset);
        curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_RANGE, range);
      }
      
      CURLMcode curlMCode =  curl_multi_add_handle(ftpfs.multi, ftpfs.connection);
      if (curlMCode != CURLE_OK)
      {
          fprintf(stderr, "curl_multi_add_handle problem: %d\n", curlMCode);
          exit(1);
      }
      ftpfs.attached_to_multi = 1;
    }

    while(CURLM_CALL_MULTI_PERFORM ==
        curl_multi_perform(ftpfs.multi, &running_handles));

    curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_RANGE, NULL);

    while ((fh->buf.len < size + offset - fh->buf.begin_offset) &&
        running_handles) {
      struct timeval timeout;
      int rc; /* select() return code */

      fd_set fdread;
      fd_set fdwrite;
      fd_set fdexcep;
      int maxfd;

      FD_ZERO(&fdread);
      FD_ZERO(&fdwrite);
      FD_ZERO(&fdexcep);

      /* set a suitable timeout to play around with */
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;

      /* get file descriptors from the transfers */
      curl_multi_fdset(ftpfs.multi, &fdread, &fdwrite, &fdexcep, &maxfd);

      rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);
      if (rc == -1) {
          err = 1;
          break;
      }
      while(CURLM_CALL_MULTI_PERFORM ==
            curl_multi_perform(ftpfs.multi, &running_handles));
    }

    if (running_handles == 0) {
      int msgs_left = 1;
      while (msgs_left) {
        CURLMsg* msg = curl_multi_info_read(ftpfs.multi, &msgs_left);
        if (msg == NULL ||
            msg->msg != CURLMSG_DONE ||
            msg->data.result != CURLE_OK) {
          DEBUG(1, "error: curl_multi_info %d\n", msg->msg);
          err = 1;
        }
      }
    }
  }

  size_t to_copy = fh->buf.len + fh->buf.begin_offset - offset;
  size = size > to_copy ? to_copy : size;
  if (rbuf) {
    memcpy(rbuf, fh->buf.p + offset - fh->buf.begin_offset, size);
  }

  if (update_offset) {
    fh->last_offset = offset + size;
  }

  // Check if the buffer is growing and we can delete a part of it
  if (fh->can_shrink && fh->buf.len > MAX_BUFFER_LEN) {
    DEBUG(2, "Shrinking buffer from %zu to %zu bytes\n",
          fh->buf.len, to_copy - size);
    memmove(fh->buf.p,
            fh->buf.p + offset - fh->buf.begin_offset + size,
            to_copy - size);
    fh->buf.len = to_copy - size;
    fh->buf.begin_offset = offset + size;
  }

  pthread_mutex_unlock(&ftpfs.lock);

  if (err) return CURLFTPFS_BAD_READ;
  return size;
}

static void set_common_curl_stuff(CURL* easy);

static size_t write_data_bg(void *ptr, size_t size, size_t nmemb, void *data) {
  struct ftpfs_file *fh = data;
  unsigned to_copy = size * nmemb;

  if (!fh->isready) {
    sem_post(&fh->ready);
    fh->isready = 1;
  }

  if (fh->stream_buf.len == 0 && fh->written_flag) {
    sem_post(&fh->data_written); /* ftpfs_write can return */
  }
  
  sem_wait(&fh->data_avail); 
  
  DEBUG(2, "write_data_bg: data_avail eof=%d\n", fh->eof);
  
  if (fh->eof)
    return 0;

  DEBUG(2, "write_data_bg: %d %zd\n", to_copy, fh->stream_buf.len);
  if (to_copy > fh->stream_buf.len)
    to_copy = fh->stream_buf.len;

  memcpy(ptr, fh->stream_buf.p, to_copy);
  if (fh->stream_buf.len > to_copy) {
    size_t newlen = fh->stream_buf.len - to_copy;
    memmove(fh->stream_buf.p, fh->stream_buf.p + to_copy, newlen);
    fh->stream_buf.len = newlen;
    sem_post(&fh->data_avail);
    DEBUG(2, "write_data_bg: data_avail\n");    
    
  } else {
    fh->stream_buf.len = 0;
    fh->written_flag = 1;
    sem_post(&fh->data_need);
    DEBUG(2, "write_data_bg: data_need\n");
  }

  return to_copy;
}

int write_thread_ctr = 0;

static void *ftpfs_write_thread(void *data) {
  struct ftpfs_file *fh = data;
  char range[15];
  
  DEBUG(2, "enter streaming write thread #%d path=%s pos=%lld\n", ++write_thread_ctr, fh->full_path, fh->pos);
  
  
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_URL, fh->full_path);
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_UPLOAD, 1);
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_INFILESIZE, -1);
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_READFUNCTION, write_data_bg);
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_READDATA, fh);
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_LOW_SPEED_LIMIT, 1);
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_LOW_SPEED_TIME, 60);
  
  fh->curl_error_buffer[0] = '\0';
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_ERRORBUFFER, fh->curl_error_buffer);

  if (fh->pos > 0) {
    /* resuming a streaming write */
    //snprintf(range, 15, "%lld-", (long long) fh->pos);
    //curl_easy_setopt_or_die(fh->write_conn, CURLOPT_RANGE, range);
	  
	curl_easy_setopt_or_die(fh->write_conn, CURLOPT_APPEND, 1);
	  
	//curl_easy_setopt_or_die(fh->write_conn, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)fh->pos);
  }   
  
  CURLcode curl_res = curl_easy_perform(fh->write_conn);
  
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_UPLOAD, 0);

  if (!fh->isready)
    sem_post(&fh->ready);

  if (curl_res != CURLE_OK)
  {  
	  DEBUG(1, "write problem: %d(%s) text=%s\n", curl_res, curl_easy_strerror(curl_res), fh->curl_error_buffer);
	  fh->write_fail_cause = curl_res;
	  /* problem - let ftpfs_write continue to avoid hang */ 
	  sem_post(&fh->data_need);
  }
  
  DEBUG(2, "leaving streaming write thread #%d curl_res=%d\n", write_thread_ctr--, curl_res);
  
  sem_post(&fh->data_written); /* ftpfs_write may return */

  return NULL;
}

/* returns 1 on success, 0 on failure */
static int start_write_thread(struct ftpfs_file *fh)
{
	if (fh->write_conn != NULL)
	{
		fprintf(stderr, "assert fh->write_conn == NULL failed!\n");
		exit(1);
	}
	
	fh->written_flag=0;
	fh->isready=0;
	fh->eof=0;
	sem_init(&fh->data_avail, 0, 0);
	sem_init(&fh->data_need, 0, 0);
	sem_init(&fh->data_written, 0, 0);
	sem_init(&fh->ready, 0, 0);	
	
    fh->write_conn = curl_easy_init();
    if (fh->write_conn == NULL) {
      fprintf(stderr, "Error initializing libcurl\n");
      return 0;
    } else {
      int err;
      set_common_curl_stuff(fh->write_conn);
      err = pthread_create(&fh->thread_id, NULL, ftpfs_write_thread, fh);
      if (err) {
        fprintf(stderr, "failed to create thread: %s\n", strerror(err));
        /* FIXME: destroy curl_easy */
        return 0;	
      }
    }
	return 1;
}

static int finish_write_thread(struct ftpfs_file *fh)
{
    if (fh->write_fail_cause == CURLE_OK)
    {
      sem_wait(&fh->data_need);  /* only wait when there has been no error */
    }
    sem_post(&fh->data_avail);
    fh->eof = 1;
    
    pthread_join(fh->thread_id, NULL);
    DEBUG(2, "finish_write_thread after pthread_join. write_fail_cause=%d\n", fh->write_fail_cause);

    curl_easy_cleanup(fh->write_conn);    
    fh->write_conn = NULL;
    
    sem_destroy(&fh->data_avail);
    sem_destroy(&fh->data_need);
    sem_destroy(&fh->data_written);
    sem_destroy(&fh->ready);    
    
    if (fh->write_fail_cause != CURLE_OK)
    {
      return -EIO;
    }	
    return 0;
}


static void free_ftpfs_file(struct ftpfs_file *fh) {
  if (fh->write_conn)
    curl_easy_cleanup(fh->write_conn);
  g_free(fh->full_path);
  g_free(fh->open_path);
  sem_destroy(&fh->data_avail);
  sem_destroy(&fh->data_need);
  sem_destroy(&fh->data_written);
  sem_destroy(&fh->ready);
  free(fh);
}

static int buffer_file(struct ftpfs_file *fh) {
  // If we want to write to the file, we have to load it all at once,
  // modify it in memory and then upload it as a whole as most FTP servers
  // don't support resume for uploads.
  pthread_mutex_lock(&ftpfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, fh->full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &fh->buf);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    return -EACCES;
  }

  return 0;
}

static int create_empty_file(const char * path)
{
  int err = 0;

  char *full_path = get_full_path(path);

  pthread_mutex_lock(&ftpfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_INFILESIZE, 0);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_UPLOAD, 1);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_READDATA, NULL);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_UPLOAD, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }	
  free(full_path);
  return err;
}

static int ftpfs_mknod(const char* path, mode_t mode, dev_t rdev);
static int ftpfs_chmod(const char* path, mode_t mode);

static char * flags_to_string(int flags)
{
	char * access_mode_str = NULL;
	if ((flags & O_ACCMODE) == O_WRONLY)
		access_mode_str = "O_WRONLY";
	else if ((flags & O_ACCMODE) == O_RDWR) 
		access_mode_str = "O_RDWR";
	else if ((flags & O_ACCMODE) == O_RDONLY)
		access_mode_str = "O_RDONLY";
	
	return g_strdup_printf("access_mode=%s, flags=%s%s%s%s",
			access_mode_str,
			(flags & O_CREAT) ? "O_CREAT " : "",
			(flags & O_TRUNC) ? "O_TRUNC " : "",
			(flags & O_EXCL) ? "O_EXCL " : "",
			(flags & O_APPEND) ? "O_APPEND " : "");
	
}

static int test_exists(const char* path)
{
	struct stat sbuf;
	return ftpfs_getattr(path, &sbuf);
}

static __off_t test_size(const char* path)
{
	struct stat sbuf;
	int err = ftpfs_getattr(path, &sbuf);
	if (err)
		return err;
	return sbuf.st_size;
}

static int ftpfs_open_common(const char* path, mode_t mode,
                             struct fuse_file_info* fi) {
	
  char * flagsAsStr = flags_to_string(fi->flags);
  DEBUG(2, "ftpfs_open_common: %s\n", flagsAsStr);
  int err = 0;

  struct ftpfs_file* fh =
    (struct ftpfs_file*) malloc(sizeof(struct ftpfs_file));

  memset(fh, 0, sizeof(*fh));
  buf_init(&fh->buf);
  fh->mode = mode;
  fh->dirty = 0;
  fh->copied = 0;
  fh->last_offset = 0;
  fh->can_shrink = 0;
  buf_init(&fh->stream_buf);
  /* sem_init(&fh->data_avail, 0, 0);
  sem_init(&fh->data_need, 0, 0);
  sem_init(&fh->data_written, 0, 0);
  sem_init(&fh->ready, 0, 0); */
  fh->open_path = strdup(path);
  fh->full_path = get_full_path(path);
  fh->written_flag = 0;
  fh->write_fail_cause = CURLE_OK;
  fh->curl_error_buffer[0] = '\0';
  fh->write_may_start = 0;
  fi->fh = (unsigned long) fh;

  if ((fi->flags & O_ACCMODE) == O_RDONLY) {
    if (fi->flags & O_CREAT) {
      err = ftpfs_mknod(path, (mode & 07777) | S_IFREG, 0);
    } else {
      // If it's read-only, we can load the file a bit at a time, as necessary.
      DEBUG(1, "opening %s O_RDONLY\n", path);
      fh->can_shrink = 1;
      size_t size = ftpfs_read_chunk(fh->full_path, NULL, 1, 0, fi, 0);

      if (size == CURLFTPFS_BAD_READ) {
        DEBUG(1, "initial read failed size=%d\n", size);
        err = -EACCES;
      }
    }
  }

  else if ((fi->flags & O_ACCMODE) == O_RDWR || (fi->flags & O_ACCMODE) == O_WRONLY)
  {
#ifndef CURLFTPFS_O_RW_WORKAROUND
	  if ((fi->flags & O_ACCMODE) == O_RDWR)
	  {
		  err = -ENOTSUP;
		  goto fin;
	  }
#endif
	  
	  
	  if ((fi->flags & O_APPEND))
	  {
		DEBUG(1, "opening %s with O_APPEND - not supported!\n", path);
		err = -ENOTSUP;
	  }
	  
	  if ((fi->flags & O_EXCL))
	  {
		DEBUG(1, "opening %s with O_EXCL - testing existence\n", path);
		int exists_r = test_exists(path);
		if (exists_r != -ENOENT)
			err = -EACCES;
	  }
	  
	  if (!err)
	  {
		  if ((fi->flags & O_CREAT) || (fi->flags & O_TRUNC))
	      {
	        DEBUG(1, "opening %s for writing with O_CREAT or O_TRUNC. write thread will start now\n", path);
	    	  
	    	  
	    	fh->write_may_start=1;
	    	  
	        if (start_write_thread(fh))
	        {
	          sem_wait(&fh->ready);
	          /* chmod makes only sense on O_CREAT */ 
	          if (fi->flags & O_CREAT) ftpfs_chmod(path, mode);  
	          sem_post(&fh->data_need);
	        }
	        else
	        {
	          err = -EIO;
	        }
	      }
	      else
	      {
	    	/* in this case we have to start writing later */
	        DEBUG(1, "opening %s for writing without O_CREAT or O_TRUNC. write thread will start after ftruncate\n", path);
	        /* expecting ftruncate */
	        fh->write_may_start=0;
	      }
	  }
      
  } else {
      err = -EIO;
  }

  fin:
  if (err)
    free_ftpfs_file(fh);

  g_free(flagsAsStr);
  return op_return(err, "ftpfs_open");
}

static int ftpfs_open(const char* path, struct fuse_file_info* fi) {
  return ftpfs_open_common(path, 0, fi);
}

#if FUSE_VERSION >= 25
static int ftpfs_create(const char* path, mode_t mode,
                        struct fuse_file_info* fi) {
  return ftpfs_open_common(path, mode, fi);
}
#endif

static int ftpfs_read(const char* path, char* rbuf, size_t size, off_t offset,
                      struct fuse_file_info* fi) {
  int ret;
  struct ftpfs_file *fh = get_ftpfs_file(fi);
  
  DEBUG(1, "ftpfs_read: %s size=%zu offset=%lld has_write_conn=%d pos=%lld\n", path, size, (long long) offset, fh->write_conn!=0, fh->pos);
  
  if (fh->pos>0 || fh->write_conn!=NULL)
  {
	  fprintf(stderr, "in read/write mode we cannot read from a file that has already been written to\n");
	  return op_return(-EIO, "ftpfs_read");
  }
  
  char *full_path = get_full_path(path);
  size_t size_read = ftpfs_read_chunk(full_path, rbuf, size, offset, fi, 1);
  free(full_path);
  if (size_read == CURLFTPFS_BAD_READ) {
    ret = -EIO;
  } else {
    ret = size_read;
  }
  
  if (ret<0) op_return(ret, "ftpfs_read");
  return ret;
}

static int ftpfs_mknod(const char* path, mode_t mode, dev_t rdev) {
  (void) rdev;

  int err = 0;

  DEBUG(1, "ftpfs_mknode: mode=%d\n", (int)mode);
  
  if ((mode & S_IFMT) != S_IFREG)
    return -EPERM;

  err = create_empty_file(path);
 
  if (!err)
      ftpfs_chmod(path, mode);

  return op_return(err, "ftpfs_mknod");
}

static int ftpfs_chmod(const char* path, mode_t mode) {
  int err = 0;

  // We can only process a subset of the mode - so strip
  // to supported subset
  int mode_c = mode - (mode / 0x1000 * 0x1000);
  
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("SITE CHMOD %.3o %s", mode_c, filename);
  struct buffer buf;
  buf_init(&buf);

  header = curl_slist_append(header, cmd);

  pthread_mutex_lock(&ftpfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, ftpfs.safe_nobody);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd); 
  return op_return(err, "ftpfs_chmod");
}

static int ftpfs_chown(const char* path, uid_t uid, gid_t gid) {
  int err = 0;
  
  DEBUG(1, "ftpfs_chown: %d %d\n", (int)uid, (int)gid);
  
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("SITE CHUID %i %s", uid, filename);
  char* cmd2 = g_strdup_printf("SITE CHGID %i %s", gid, filename);
  struct buffer buf;
  buf_init(&buf);

  header = curl_slist_append(header, cmd);
  header = curl_slist_append(header, cmd2);

  pthread_mutex_lock(&ftpfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, ftpfs.safe_nobody);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd); 
  free(cmd2); 
  return op_return(err, "ftpfs_chown");
}

static int ftpfs_truncate(const char* path, off_t offset) {
  DEBUG(1, "ftpfs_truncate: %s len=%lld\n", path, offset);
  /* we can't use ftpfs_mknod here, because we don't know the right permissions */
  if (offset == 0) return op_return(create_empty_file(path), "ftpfs_truncate");

  /* fix openoffice problem, truncating exactly to file length */
  
  __off_t size = (long long int)test_size(path); 
  DEBUG(1, "ftpfs_truncate: %s check filesize=%lld\n", path, (long long int)size);
  
  if (offset == size)  
	  return op_return(0, "ftpfs_ftruncate");
  
  DEBUG(1, "ftpfs_truncate problem: %s offset != 0 or filesize=%lld != offset\n", path, (long long int)size);
  
  
  return op_return(-EPERM, "ftpfs_truncate");
}

static int ftpfs_ftruncate(const char * path , off_t offset, struct fuse_file_info * fi)
{
  DEBUG(1, "ftpfs_ftruncate: %s len=%lld\n", path, offset);
  struct ftpfs_file *fh = get_ftpfs_file(fi);

  if (offset == 0) 
  {
	 if (fh->pos == 0)
	 {
		 fh->write_may_start=1;
		 return op_return(create_empty_file(fh->open_path), "ftpfs_ftruncate");
	 }
	 return op_return(-EPERM, "ftpfs_ftruncate");
  }
  /* fix openoffice problem, truncating exactly to file length */
  
  __off_t size = test_size(path); 
  DEBUG(1, "ftpfs_ftruncate: %s check filesize=%lld\n", path, (long long int)size);
  
  if (offset == size)  
	  return op_return(0, "ftpfs_ftruncate");
  
  DEBUG(1, "ftpfs_ftruncate problem: %s offset != 0 or filesize(=%lld) != offset(=%lld)\n", path, (long long int)size, (long long int) offset);
  
  return op_return(-EPERM, "ftpfs_ftruncate");
}

static int ftpfs_utime(const char* path, struct utimbuf* time) {
  (void) path;
  (void) time;
  return op_return(0, "ftpfs_utime");
}

static int ftpfs_rmdir(const char* path) {
  int err = 0;
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("RMD %s", filename);
  struct buffer buf;
  buf_init(&buf);

  DEBUG(2, "%s\n", full_path);
  DEBUG(2, "%s\n", cmd);

  header = curl_slist_append(header, cmd);

  pthread_mutex_lock(&ftpfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, ftpfs.safe_nobody);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd);
  return op_return(err, "ftpfs_rmdir");
}

static int ftpfs_mkdir(const char* path, mode_t mode) {
  int err = 0;
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("MKD %s", filename);
  struct buffer buf;
  buf_init(&buf);

  header = curl_slist_append(header, cmd);

  pthread_mutex_lock(&ftpfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, ftpfs.safe_nobody);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd);

  if (!err)
    ftpfs_chmod(path, mode);

  return op_return(err, "ftpfs_mkdir");
}

static int ftpfs_unlink(const char* path) {
  int err = 0;
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("DELE %s", filename);
  struct buffer buf;
  buf_init(&buf);

  header = curl_slist_append(header, cmd);

  pthread_mutex_lock(&ftpfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, ftpfs.safe_nobody);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd);
  return op_return(err, "ftpfs_unlink");
}

static int ftpfs_write(const char *path, const char *wbuf, size_t size,
                       off_t offset, struct fuse_file_info *fi) {
  (void) path;
  struct ftpfs_file *fh = get_ftpfs_file(fi);

  DEBUG(1, "ftpfs_write: %s size=%zu offset=%lld has_write_conn=%d pos=%lld\n", path, size, (long long) offset, fh->write_conn!=0, fh->pos);

  if (fh->write_fail_cause != CURLE_OK)
  {
    DEBUG(1, "previous write failed. cause=%d\n", fh->write_fail_cause);
    return -EIO;
  }    
  
  if (!fh->write_conn && fh->pos == 0 && offset == 0)
  {
    DEBUG(1, "ftpfs_write: starting a streaming write at pos=%lld\n", fh->pos);
    
    /* check if the file has been truncated to zero or has been newly created */
    if (!fh->write_may_start)
    {
    	long long size = (long long int)test_size(path); 
    	if (size != 0)
    	{
    		fprintf(stderr, "ftpfs_write: start writing with no previous truncate not allowed! size check rval=%lld\n", size);
    		return op_return(-EIO, "ftpfs_write");
    	}
    }
    
	int success = start_write_thread(fh);
    if (!success)
    {
      return op_return(-EIO, "ftpfs_write");
    }
    sem_wait(&fh->ready);
	sem_post(&fh->data_need);    
  }
  
  if (!fh->write_conn && fh->pos >0 && offset == fh->pos)
  {
    /* resume a streaming write */
    DEBUG(1, "ftpfs_write: resuming a streaming write at pos=%lld\n", fh->pos);
	  
    int success = start_write_thread(fh);
    if (!success)
    {
      return op_return(-EIO, "ftpfs_write");
    }
    sem_wait(&fh->ready);
    sem_post(&fh->data_need);    
  }
  
  if (fh->write_conn) {
    sem_wait(&fh->data_need);
    
    if (offset != fh->pos) {
      DEBUG(1, "non-sequential write detected -> fail\n");

      sem_post(&fh->data_avail);      
      finish_write_thread(fh);      
      return op_return(-EIO, "ftpfs_write");
      
      
    } else {
      if (buf_add_mem(&fh->stream_buf, wbuf, size) == -1) {
        sem_post(&fh->data_need);
        return op_return(-ENOMEM, "ftpfs_write");
      }
      fh->pos += size;
      /* wake up write_data_bg */
      sem_post(&fh->data_avail);
      /* wait until libcurl has completely written the current chunk or finished/failed */
      sem_wait(&fh->data_written);  
      fh->written_flag = 0;
      
      if (fh->write_fail_cause != CURLE_OK)
      {
    	/* TODO: on error we should problably unlink the target file  */ 
        DEBUG(1, "writing failed. cause=%d\n", fh->write_fail_cause);
        return op_return(-EIO, "ftpfs_write");
      }    
    }
    
  }

  return size;

}

static int ftpfs_flush(const char *path, struct fuse_file_info *fi) {
  int err = 0;
  struct ftpfs_file* fh = get_ftpfs_file(fi);

  DEBUG(1, "ftpfs_flush: buf.len=%zu buf.pos=%lld write_conn=%d\n", fh->buf.len, fh->pos, fh->write_conn!=0);
  
  if (fh->write_conn) {
    err = finish_write_thread(fh);
    if (err) return op_return(err, "ftpfs_flush");
    
    struct stat sbuf;
    
    /* check if the resulting file has the correct size
     this is important, because we use APPE for continuing
     writing after a premature flush */
    err = ftpfs_getattr(path, &sbuf);   
    if (err) return op_return(err, "ftpfs_flush");
    
    if (sbuf.st_size != fh->pos)
    {
    	fh->write_fail_cause = -999;
    	fprintf(stderr, "ftpfs_flush: check filesize problem: size=%lld expected=%lld\n", sbuf.st_size, fh->pos);
    	return op_return(-EIO, "ftpfs_flush");
    }
    
    return 0;
  }
  
 
  if (!fh->dirty) return 0;

  return op_return(-EIO, "ftpfs_flush");
  
}

static int ftpfs_fsync(const char *path, int isdatasync,
                      struct fuse_file_info *fi) {
	DEBUG(1, "ftpfs_fsync %s\n", path);
  (void) isdatasync;
  return ftpfs_flush(path, fi);
}

static int ftpfs_release(const char* path, struct fuse_file_info* fi) {

  DEBUG(1, "ftpfs_release %s\n", path);
  struct ftpfs_file* fh = get_ftpfs_file(fi);
  ftpfs_flush(path, fi);
  pthread_mutex_lock(&ftpfs.lock);
  if (ftpfs.current_fh == fh) {
    ftpfs.current_fh = NULL;
  }
  pthread_mutex_unlock(&ftpfs.lock);

  /*
  if (fh->write_conn) {
	  finish_write_thread(fh);
  }
  */
  free_ftpfs_file(fh);
  return op_return(0, "ftpfs_release"); 
}


static int ftpfs_rename(const char* from, const char* to) {
  DEBUG(1, "ftpfs_rename from %s to %s\n", from, to);
  int err = 0;
  char* rnfr = g_strdup_printf("RNFR %s", from + 1);
  char* rnto = g_strdup_printf("RNTO %s", to + 1);
  struct buffer buf;
  buf_init(&buf);
  struct curl_slist* header = NULL;

  if (ftpfs.codepage) {
    convert_charsets(ftpfs.iocharset, ftpfs.codepage, &rnfr);
    convert_charsets(ftpfs.iocharset, ftpfs.codepage, &rnto);
  }

  header = curl_slist_append(header, rnfr);
  header = curl_slist_append(header, rnto);

  pthread_mutex_lock(&ftpfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, ftpfs.host);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, ftpfs.safe_nobody);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(rnfr);
  free(rnto);

  return op_return(err, "ftpfs_rename");
}

static int ftpfs_readlink(const char *path, char *linkbuf, size_t size) {
  int err;
  CURLcode curl_res;
  char* dir_path = get_dir_path(path);

  DEBUG(2, "dir_path: %s %s\n", path, dir_path);
  struct buffer buf;
  buf_init(&buf);

  pthread_mutex_lock(&ftpfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, dir_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_res = curl_easy_perform(ftpfs.connection);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    DEBUG(1, "%s\n", error_buf);
  }
  buf_null_terminate(&buf);

  char* name = strrchr(path, '/');
  ++name;
  err = parse_dir((char*)buf.p, dir_path + strlen(ftpfs.host) - 1,
                  name, NULL, linkbuf, size, NULL, NULL); 

  free(dir_path);
  buf_free(&buf);
  if (err) return op_return(-ENOENT, "ftpfs_readlink");
  return op_return(0, "ftpfs_readlink");
}

#if FUSE_VERSION >= 25
static int ftpfs_statfs(const char *path, struct statvfs *buf)
{
    (void) path;

    buf->f_namemax = 255;
    buf->f_bsize = ftpfs.blksize;
    buf->f_frsize = 512;
    buf->f_blocks = 999999999 * 2;
    buf->f_bfree =  999999999 * 2;
    buf->f_bavail = 999999999 * 2;
    buf->f_files =  999999999;
    buf->f_ffree =  999999999;
    return op_return(0, "ftpfs_statfs");
}
#else
static int ftpfs_statfs(const char *path, struct statfs *buf)
{
    (void) path;

    buf->f_namelen = 255;
    buf->f_bsize = ftpfs.blksize;
    buf->f_blocks = 999999999 * 2;
    buf->f_bfree =  999999999 * 2;
    buf->f_bavail = 999999999 * 2;
    buf->f_files =  999999999;
    buf->f_ffree =  999999999;
    return op_return(0, "ftpfs_statfs");
}
#endif

static struct fuse_cache_operations ftpfs_oper = {
  .oper = {
//    .init       = ftpfs_init,
    .getattr    = ftpfs_getattr,
    .readlink   = ftpfs_readlink,
    .mknod      = ftpfs_mknod,
    .mkdir      = ftpfs_mkdir,
//    .symlink    = ftpfs_symlink,
    .unlink     = ftpfs_unlink,
    .rmdir      = ftpfs_rmdir,
    .rename     = ftpfs_rename,
    .chmod      = ftpfs_chmod,
    .chown      = ftpfs_chown,
    .truncate   = ftpfs_truncate,
    .utime      = ftpfs_utime,
    .open       = ftpfs_open,
    .flush      = ftpfs_flush,
    .fsync      = ftpfs_fsync,
    .release    = ftpfs_release,
    .read       = ftpfs_read,
    .write      = ftpfs_write,
    .statfs     = ftpfs_statfs,
#if FUSE_VERSION >= 25
    .create     = ftpfs_create,
    .ftruncate  = ftpfs_ftruncate,
//    .fgetattr   = ftpfs_fgetattr,
#endif
  },
  .cache_getdir = ftpfs_getdir,
};

static int curlftpfs_fuse_main(struct fuse_args *args)
{
#if FUSE_VERSION >= 26
    return fuse_main(args->argc, args->argv, cache_init(&ftpfs_oper), NULL);
#else
    return fuse_main(args->argc, args->argv, cache_init(&ftpfs_oper));
#endif
}

static int ftpfs_opt_proc(void* data, const char* arg, int key,
                          struct fuse_args* outargs) {
  (void) data;
  (void) outargs;

  switch (key) {
    case FUSE_OPT_KEY_OPT:
      return 1;
    case FUSE_OPT_KEY_NONOPT:
      if (!ftpfs.host) {
        const char* prefix = "";
        if (strncmp(arg, "ftp://", 6) && strncmp(arg, "ftps://", 7)) {
          prefix = "ftp://";
        }
        ftpfs.host = g_strdup_printf("%s%s%s", prefix, arg, 
			arg[strlen(arg)-1] == '/' ? "" : "/");
        return 0;
      } else if (!ftpfs.mountpoint)
        ftpfs.mountpoint = strdup(arg);
      return 1;
    case KEY_HELP:
      usage(outargs->argv[0]);
      fuse_opt_add_arg(outargs, "-ho");
      curlftpfs_fuse_main(outargs);
      exit(1);
    case KEY_VERBOSE:
      ftpfs.verbose = 1;
      return 0;
    case KEY_VERSION:
      fprintf(stderr, "curlftpfs %s libcurl/%s fuse/%u.%u\n",
              VERSION,
              ftpfs.curl_version->version,
              FUSE_MAJOR_VERSION,
              FUSE_MINOR_VERSION);
      exit(1);
    default:
      exit(1);
  }
}

static void usage(const char* progname) {
  fprintf(stderr,
"usage: %s <ftphost> <mountpoint>\n"
"\n"
"CurlFtpFS options:\n"
"    -o opt,[opt...]        ftp options\n"
"    -v   --verbose         make libcurl print verbose debug\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"\n"
"FTP options:\n"
"    ftpfs_debug         print some debugging information\n"
"    transform_symlinks  prepend mountpoint to absolute symlink targets\n"
"    disable_epsv        use PASV, without trying EPSV first (default)\n"
"    enable_epsv         try EPSV before reverting to PASV\n"
"    skip_pasv_ip        skip the IP address for PASV\n"
"    ftp_port=STR        use PORT with address instead of PASV\n"
"    disable_eprt        use PORT, without trying EPRT first\n"
"    ftp_method          [multicwd/singlecwd] Control CWD usage\n"
"    custom_list=STR     Command used to list files. Defaults to \"LIST -a\"\n"
"    tcp_nodelay         use the TCP_NODELAY option\n"
"    connect_timeout=N   maximum time allowed for connection in seconds\n"
"    ssl                 enable SSL/TLS for both control and data connections\n"
"    ssl_control         enable SSL/TLS only for control connection\n"
"    ssl_try             try SSL/TLS first but connect anyway\n"
"    no_verify_hostname  does not verify the hostname (SSL)\n"
"    no_verify_peer      does not verify the peer (SSL)\n"
"    cert=STR            client certificate file (SSL)\n"
"    cert_type=STR       certificate file type (DER/PEM/ENG) (SSL)\n"
"    key=STR             private key file name (SSL)\n"
"    key_type=STR        private key file type (DER/PEM/ENG) (SSL)\n"
"    pass=STR            pass phrase for the private key (SSL)\n"
"    engine=STR          crypto engine to use (SSL)\n"
"    cacert=STR          file with CA certificates to verify the peer (SSL)\n"
"    capath=STR          CA directory to verify peer against (SSL)\n"
"    ciphers=STR         SSL ciphers to use (SSL)\n"
"    interface=STR       specify network interface/address to use\n"
"    krb4=STR            enable krb4 with specified security level\n"
"    proxy=STR           use host:port HTTP proxy\n"
"    proxytunnel         operate through a HTTP proxy tunnel (using CONNECT)\n"
"    proxy_anyauth       pick \"any\" proxy authentication method\n"
"    proxy_basic         use Basic authentication on the proxy\n"
"    proxy_digest        use Digest authentication on the proxy\n"
"    proxy_ntlm          use NTLM authentication on the proxy\n"
"    httpproxy           use a HTTP proxy (default)\n"
"    socks4              use a SOCKS4 proxy\n"
"    socks5              use a SOCKS5 proxy\n"
"    user=STR            set server user and password\n"
"    proxy_user=STR      set proxy user and password\n"
"    tlsv1               use TLSv1 (SSL)\n"
"    sslv3               use SSLv3 (SSL)\n"
"    ipv4                resolve name to IPv4 address\n"
"    ipv6                resolve name to IPv6 address\n"
"    utf8                try to transfer file list with utf-8 encoding\n"
"    codepage=STR        set the codepage the server uses\n"
"    iocharset=STR       set the charset used by the client\n"
"\n"
"CurlFtpFS cache options:  \n"
"    cache=yes|no              enable/disable cache (default: yes)\n"
"    cache_timeout=SECS        set timeout for stat, dir, link at once\n"
"                              default is %d seconds\n"
"    cache_stat_timeout=SECS   set stat timeout\n"
"    cache_dir_timeout=SECS    set dir timeout\n"
"    cache_link_timeout=SECS   set link timeout\n"          
"\n", progname, DEFAULT_CACHE_TIMEOUT);
}

static int ftpfilemethod(const char *str)
{
  if(!strcmp("singlecwd", str))
    return CURLFTPMETHOD_SINGLECWD;
  if(!strcmp("multicwd", str))
    return CURLFTPMETHOD_MULTICWD;
  DEBUG(1, "unrecognized ftp file method '%s', using default\n", str);
  return CURLFTPMETHOD_MULTICWD;
}

static void set_common_curl_stuff(CURL* easy) {
  curl_easy_setopt_or_die(easy, CURLOPT_WRITEFUNCTION, read_data);
  curl_easy_setopt_or_die(easy, CURLOPT_READFUNCTION, write_data);
  curl_easy_setopt_or_die(easy, CURLOPT_ERRORBUFFER, error_buf);
  curl_easy_setopt_or_die(easy, CURLOPT_URL, ftpfs.host);
  curl_easy_setopt_or_die(easy, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
  curl_easy_setopt_or_die(easy, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt_or_die(easy, CURLOPT_CUSTOMREQUEST, "LIST -a");

  if (ftpfs.custom_list) {
    curl_easy_setopt_or_die(easy, CURLOPT_CUSTOMREQUEST, ftpfs.custom_list);
  }

  if (ftpfs.tryutf8) {
    // We'll let the slist leak, as it will still be accessible within
    // libcurl. If we ever want to add more commands to CURLOPT_QUOTE, we'll
    // have to think of a better strategy.
    struct curl_slist *slist = NULL;

    // Adding the QUOTE here will make this command be sent with every request.
    // This is necessary to ensure that the server is still in UTF8 mode after
    // we get disconnected and automatically reconnect.
    slist = curl_slist_append(slist, "OPTS UTF8 ON");
    curl_easy_setopt_or_die(easy, CURLOPT_QUOTE, slist);
  }

  if (ftpfs.verbose) {
    curl_easy_setopt_or_die(easy, CURLOPT_VERBOSE, TRUE);
  }

  if (ftpfs.disable_epsv) {
    curl_easy_setopt_or_die(easy, CURLOPT_FTP_USE_EPSV, FALSE);
  }

  if (ftpfs.skip_pasv_ip) {
    curl_easy_setopt_or_die(easy, CURLOPT_FTP_SKIP_PASV_IP, TRUE);
  }

  if (ftpfs.ftp_port) {
    curl_easy_setopt_or_die(easy, CURLOPT_FTPPORT, ftpfs.ftp_port);
  }

  if (ftpfs.disable_eprt) {
    curl_easy_setopt_or_die(easy, CURLOPT_FTP_USE_EPRT, FALSE);
  }

  if (ftpfs.ftp_method) {
    curl_easy_setopt_or_die(easy, CURLOPT_FTP_FILEMETHOD,
                            ftpfilemethod(ftpfs.ftp_method));
  }

  if (ftpfs.tcp_nodelay) {
    /* CURLOPT_TCP_NODELAY is not defined in older versions */
    curl_easy_setopt_or_die(easy, CURLOPT_TCP_NODELAY, 1);
  }

  curl_easy_setopt_or_die(easy, CURLOPT_CONNECTTIMEOUT, ftpfs.connect_timeout);

  /* CURLFTPSSL_CONTROL and CURLFTPSSL_ALL should make the connection fail if
   * the server doesn't support SSL but libcurl only honors this beginning
   * with version 7.15.4 */
  if (ftpfs.use_ssl > CURLFTPSSL_TRY &&
      ftpfs.curl_version->version_num <= CURLFTPFS_BAD_SSL) {
    fprintf(stderr,
"WARNING: you are using libcurl %s.\n"
"This version of libcurl does not respect the mandatory SSL flag.\n" 
"It will try to send the user and password even if the server doesn't support\n"
"SSL. Please upgrade to libcurl version 7.15.4 or higher.\n"
"You can abort the connection now by pressing ctrl+c.\n",
            ftpfs.curl_version->version);
    int i;
    const int time_to_wait = 10;
    for (i = 0; i < time_to_wait; i++) {
      fprintf(stderr, "%d.. ", time_to_wait - i);
      sleep(1);
    }
    fprintf(stderr, "\n");
  }
  curl_easy_setopt_or_die(easy, CURLOPT_FTP_SSL, ftpfs.use_ssl);

  curl_easy_setopt_or_die(easy, CURLOPT_SSLCERT, ftpfs.cert);
  curl_easy_setopt_or_die(easy, CURLOPT_SSLCERTTYPE, ftpfs.cert_type);
  curl_easy_setopt_or_die(easy, CURLOPT_SSLKEY, ftpfs.key);
  curl_easy_setopt_or_die(easy, CURLOPT_SSLKEYTYPE, ftpfs.key_type);
  curl_easy_setopt_or_die(easy, CURLOPT_SSLKEYPASSWD, ftpfs.key_password);

  if (ftpfs.engine) {
    curl_easy_setopt_or_die(easy, CURLOPT_SSLENGINE, ftpfs.engine);
    curl_easy_setopt_or_die(easy, CURLOPT_SSLENGINE_DEFAULT, 1);
  }

  curl_easy_setopt_or_die(easy, CURLOPT_SSL_VERIFYPEER, TRUE);
  if (ftpfs.no_verify_peer) {
    curl_easy_setopt_or_die(easy, CURLOPT_SSL_VERIFYPEER, FALSE);
  }

  if (ftpfs.cacert || ftpfs.capath) {
    if (ftpfs.cacert) {
      curl_easy_setopt_or_die(easy, CURLOPT_CAINFO, ftpfs.cacert);
    }
    if (ftpfs.capath) {
      curl_easy_setopt_or_die(easy, CURLOPT_CAPATH, ftpfs.capath);
    }
  }

  if (ftpfs.ciphers) {
    curl_easy_setopt_or_die(easy, CURLOPT_SSL_CIPHER_LIST, ftpfs.ciphers);
  }

  if (ftpfs.no_verify_hostname) {
    /* The default is 2 which verifies even the host string. This sets to 1
     * which means verify the host but not the string. */
    curl_easy_setopt_or_die(easy, CURLOPT_SSL_VERIFYHOST, 1);
  }

  curl_easy_setopt_or_die(easy, CURLOPT_INTERFACE, ftpfs.interface);
  curl_easy_setopt_or_die(easy, CURLOPT_KRB4LEVEL, ftpfs.krb4);
  
  if (ftpfs.proxy) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXY, ftpfs.proxy);
  }

  /* The default proxy type is HTTP */
  if (!ftpfs.proxytype) {
    ftpfs.proxytype = CURLPROXY_HTTP;
  }
  curl_easy_setopt_or_die(easy, CURLOPT_PROXYTYPE, ftpfs.proxytype);
  
  /* Connection to FTP servers only make sense with a HTTP tunnel proxy */
  if (ftpfs.proxytype == CURLPROXY_HTTP || ftpfs.proxytunnel) {
    curl_easy_setopt_or_die(easy, CURLOPT_HTTPPROXYTUNNEL, TRUE);
  }

  if (ftpfs.proxyanyauth) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
  } else if (ftpfs.proxyntlm) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_NTLM);
  } else if (ftpfs.proxydigest) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
  } else if (ftpfs.proxybasic) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);
  }

  curl_easy_setopt_or_die(easy, CURLOPT_USERPWD, ftpfs.user);
  curl_easy_setopt_or_die(easy, CURLOPT_PROXYUSERPWD, ftpfs.proxy_user);
  curl_easy_setopt_or_die(easy, CURLOPT_SSLVERSION, ftpfs.ssl_version);
  curl_easy_setopt_or_die(easy, CURLOPT_IPRESOLVE, ftpfs.ip_version);
}

static void checkpasswd(const char *kind, /* for what purpose */
                        char **userpwd) /* pointer to allocated string */
{
  char *ptr;
  if(!*userpwd)
    return;

  ptr = strchr(*userpwd, ':');
  if(!ptr) {
    /* no password present, prompt for one */
    char *passwd;
    char prompt[256];
    size_t passwdlen;
    size_t userlen = strlen(*userpwd);
    char *passptr;

    /* build a nice-looking prompt */
    snprintf(prompt, sizeof(prompt),
        "Enter %s password for user '%s':",
        kind, *userpwd);

    /* get password */
    passwd = getpass(prompt);
    passwdlen = strlen(passwd);

    /* extend the allocated memory area to fit the password too */
    passptr = realloc(*userpwd,
        passwdlen + 1 + /* an extra for the colon */
        userlen + 1);   /* an extra for the zero */

    if(passptr) {
      /* append the password separated with a colon */
      passptr[userlen]=':';
      memcpy(&passptr[userlen+1], passwd, passwdlen+1);
      *userpwd = passptr;
    }
  }
}

#if FUSE_VERSION == 25
static int fuse_opt_insert_arg(struct fuse_args *args, int pos,
                               const char *arg)
{
    assert(pos <= args->argc);
    if (fuse_opt_add_arg(args, arg) == -1)
        return -1;

    if (pos != args->argc - 1) {
        char *newarg = args->argv[args->argc - 1];
        memmove(&args->argv[pos + 1], &args->argv[pos],
                sizeof(char *) * (args->argc - pos - 1));
        args->argv[pos] = newarg;
    }
    return 0;
}
#endif

int main(int argc, char** argv) {
  int res;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  CURLcode curl_res;
  CURL* easy;
  char *tmp;

  // Initialize curl library before we are a multithreaded program
  curl_global_init(CURL_GLOBAL_ALL);
  
  memset(&ftpfs, 0, sizeof(ftpfs));

  // Set some default values
  ftpfs.curl_version = curl_version_info(CURLVERSION_NOW);
  ftpfs.safe_nobody = ftpfs.curl_version->version_num > CURLFTPFS_BAD_NOBODY;
  ftpfs.blksize = 4096;
  ftpfs.disable_epsv = 1;
  ftpfs.multiconn = 1;
  ftpfs.attached_to_multi = 0;
  
  if (fuse_opt_parse(&args, &ftpfs, ftpfs_opts, ftpfs_opt_proc) == -1)
    exit(1);

  if (!ftpfs.host) {
    fprintf(stderr, "missing host\n");
    fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
    exit(1);
  }

  if (!ftpfs.iocharset) {
    ftpfs.iocharset = "UTF8";
  }

  if (ftpfs.codepage) {
    convert_charsets(ftpfs.iocharset, ftpfs.codepage, &ftpfs.host);
  }

  easy = curl_easy_init();
  if (easy == NULL) {
    fprintf(stderr, "Error initializing libcurl\n");
    exit(1);
  }

  res = cache_parse_options(&args);
  if (res == -1)
    exit(1);

  checkpasswd("host", &ftpfs.user);
  checkpasswd("proxy", &ftpfs.proxy_user);

  if (ftpfs.transform_symlinks && !ftpfs.mountpoint) {
    fprintf(stderr, "cannot transform symlinks: no mountpoint given\n");
    exit(1);
  }
  if (!ftpfs.transform_symlinks)
    ftpfs.symlink_prefix_len = 0;
  else if (realpath(ftpfs.mountpoint, ftpfs.symlink_prefix) != NULL)
    ftpfs.symlink_prefix_len = strlen(ftpfs.symlink_prefix);
  else {
    perror("unable to normalize mount path");
    exit(1);
  }

  set_common_curl_stuff(easy);
  curl_easy_setopt_or_die(easy, CURLOPT_WRITEDATA, NULL);
  curl_easy_setopt_or_die(easy, CURLOPT_NOBODY, ftpfs.safe_nobody);
  curl_res = curl_easy_perform(easy);
  if (curl_res != 0) {
    fprintf(stderr, "Error connecting to ftp: %s\n", error_buf);
    exit(1);
  }
  curl_easy_setopt_or_die(easy, CURLOPT_NOBODY, 0);

  ftpfs.multi = curl_multi_init();
  if (ftpfs.multi == NULL) {
    fprintf(stderr, "Error initializing libcurl multi\n");
    exit(1);
  }

  ftpfs.connection = easy;
  pthread_mutex_init(&ftpfs.lock, NULL);

  // Set the filesystem name to show the current server
  tmp = g_strdup_printf("-ofsname=curlftpfs#%s", ftpfs.host);
  fuse_opt_insert_arg(&args, 1, tmp);
  g_free(tmp);

  res = curlftpfs_fuse_main(&args);

  cancel_previous_multi();
  curl_multi_cleanup(ftpfs.multi);
  curl_easy_cleanup(easy);
  curl_global_cleanup();
  fuse_opt_free_args(&args);

  return res;
}
