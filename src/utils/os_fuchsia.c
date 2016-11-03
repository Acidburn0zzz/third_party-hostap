/*
 * OS specific functions for Fuchsia OS.
 *
 * Copyright (c) 2005-2009, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2016 The Fuchsia Authors
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * OS specific functions for Fuchsia. Based off os_unix.c.
 */

#include "includes.h"

#include <magenta/syscalls.h>
#include <sys/wait.h>
#include <time.h>

#include "common.h"
#include "os.h"

#ifdef WPA_TRACE

#include "list.h"
#include "trace.h"
#include "wpa_debug.h"

static struct dl_list alloc_list = DL_LIST_HEAD_INIT(alloc_list);

#define ALLOC_MAGIC 0xa84ef1b2
#define FREED_MAGIC 0x67fd487a

struct os_alloc_trace {
  unsigned int magic;
  struct dl_list list;
  size_t len;
  WPA_TRACE_INFO
} __attribute__((aligned(16)));

#endif /* WPA_TRACE */

void os_sleep(os_time_t sec, os_time_t usec) {
  if (sec) sleep(sec);
  if (usec) usleep(usec);
}

int os_get_time(struct os_time *t) {
  int res;
  struct timeval tv;
  res = gettimeofday(&tv, NULL);
  t->sec = tv.tv_sec;
  t->usec = tv.tv_usec;
  return res;
}

int os_get_reltime(struct os_reltime *t) {
#if defined(CLOCK_BOOTTIME)
  static clockid_t clock_id = CLOCK_BOOTTIME;
#elif defined(CLOCK_MONOTONIC)
  static clockid_t clock_id = CLOCK_MONOTONIC;
#else
  static clockid_t clock_id = CLOCK_REALTIME;
#endif
  struct timespec ts;
  int res;

  while (1) {
    res = clock_gettime(clock_id, &ts);
    if (res == 0) {
      t->sec = ts.tv_sec;
      t->usec = ts.tv_nsec / 1000;
      return 0;
    }
    switch (clock_id) {
#ifdef CLOCK_BOOTTIME
      case CLOCK_BOOTTIME:
        clock_id = CLOCK_MONOTONIC;
        break;
#endif
#ifdef CLOCK_MONOTONIC
      case CLOCK_MONOTONIC:
        clock_id = CLOCK_REALTIME;
        break;
#endif
      case CLOCK_REALTIME:
        return -1;
    }
  }
}

int os_mktime(int year, int month, int day, int hour, int min, int sec,
              os_time_t *t) {
  struct tm tm, *tm1;
  time_t t_local, t1, t2;
  os_time_t tz_offset;

  if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 ||
      hour < 0 || hour > 23 || min < 0 || min > 59 || sec < 0 || sec > 60)
    return -1;

  memset(&tm, 0, sizeof(tm));
  tm.tm_year = year - 1900;
  tm.tm_mon = month - 1;
  tm.tm_mday = day;
  tm.tm_hour = hour;
  tm.tm_min = min;
  tm.tm_sec = sec;

  t_local = mktime(&tm);

  /* figure out offset to UTC */
  tm1 = localtime(&t_local);
  if (tm1) {
    t1 = mktime(tm1);
    tm1 = gmtime(&t_local);
    if (tm1) {
      t2 = mktime(tm1);
      tz_offset = t2 - t1;
    } else
      tz_offset = 0;
  } else
    tz_offset = 0;

  *t = (os_time_t)t_local - tz_offset;
  return 0;
}

int os_gmtime(os_time_t t, struct os_tm *tm) {
  struct tm *tm2;
  time_t t2 = t;

  tm2 = gmtime(&t2);
  if (tm2 == NULL) return -1;
  tm->sec = tm2->tm_sec;
  tm->min = tm2->tm_min;
  tm->hour = tm2->tm_hour;
  tm->day = tm2->tm_mday;
  tm->month = tm2->tm_mon + 1;
  tm->year = tm2->tm_year + 1900;
  return 0;
}

#define os_daemon daemon

int os_daemonize(const char *pid_file) {
  /* Not supported */
  return -1;
}

void os_daemonize_terminate(const char *pid_file) { /* Not supported */ }

int os_get_random(unsigned char *buf, size_t len) {
  if (TEST_FAIL()) return -1;

  while (len > 0) {
    mx_size_t output_bytes_this_pass = MX_CPRNG_DRAW_MAX_LEN;
    if (len < (size_t)output_bytes_this_pass) {
      output_bytes_this_pass = len;
    }
    mx_size_t bytes_drawn;
    mx_status_t status = mx_cprng_draw(buf, output_bytes_this_pass, &bytes_drawn);
    if (status != NO_ERROR) {
      abort();
    }
    len -= bytes_drawn;
    buf += bytes_drawn;
  }
  return 0;
}

unsigned long os_random(void) { return random(); }

char *os_rel2abs_path(const char *rel_path) {
  char *buf = NULL, *cwd, *ret;
  size_t len = 128, cwd_len, rel_len, ret_len;
  int last_errno;

  if (!rel_path) return NULL;

  if (rel_path[0] == '/') return os_strdup(rel_path);

  for (;;) {
    buf = os_malloc(len);
    if (buf == NULL) return NULL;
    cwd = getcwd(buf, len);
    if (cwd == NULL) {
      last_errno = errno;
      os_free(buf);
      if (last_errno != ERANGE) return NULL;
      len *= 2;
      if (len > 2000) return NULL;
    } else {
      buf[len - 1] = '\0';
      break;
    }
  }

  cwd_len = os_strlen(cwd);
  rel_len = os_strlen(rel_path);
  ret_len = cwd_len + 1 + rel_len + 1;
  ret = os_malloc(ret_len);
  if (ret) {
    os_memcpy(ret, cwd, cwd_len);
    ret[cwd_len] = '/';
    os_memcpy(ret + cwd_len + 1, rel_path, rel_len);
    ret[ret_len - 1] = '\0';
  }
  os_free(buf);
  return ret;
}

int os_program_init(void) { return 0; }

void os_program_deinit(void) {
#ifdef WPA_TRACE
  struct os_alloc_trace *a;
  unsigned long total = 0;
  dl_list_for_each(a, &alloc_list, struct os_alloc_trace, list) {
    total += a->len;
    if (a->magic != ALLOC_MAGIC) {
      wpa_printf(MSG_INFO,
                 "MEMLEAK[%p]: invalid magic 0x%x "
                 "len %lu",
                 a, a->magic, (unsigned long)a->len);
      continue;
    }
    wpa_printf(MSG_INFO, "MEMLEAK[%p]: len %lu", a, (unsigned long)a->len);
    wpa_trace_dump("memleak", a);
  }
  if (total)
    wpa_printf(MSG_INFO, "MEMLEAK: total %lu bytes", (unsigned long)total);
#endif /* WPA_TRACE */
}

int os_setenv(const char *name, const char *value, int overwrite) {
  return setenv(name, value, overwrite);
}

int os_unsetenv(const char *name) { return unsetenv(name); }

char *os_readfile(const char *name, size_t *len) {
  FILE *f;
  char *buf;
  long pos;

  f = fopen(name, "rb");
  if (f == NULL) return NULL;

  if (fseek(f, 0, SEEK_END) < 0 || (pos = ftell(f)) < 0) {
    fclose(f);
    return NULL;
  }
  *len = pos;
  if (fseek(f, 0, SEEK_SET) < 0) {
    fclose(f);
    return NULL;
  }

  buf = os_malloc(*len);
  if (buf == NULL) {
    fclose(f);
    return NULL;
  }

  if (fread(buf, 1, *len, f) != *len) {
    fclose(f);
    os_free(buf);
    return NULL;
  }

  fclose(f);

  return buf;
}

int os_file_exists(const char *fname) {
  FILE *f = fopen(fname, "rb");
  if (f == NULL) return 0;
  fclose(f);
  return 1;
}

int os_fdatasync(FILE *stream) {
  if (!fflush(stream)) {
    return fdatasync(fileno(stream));
  }

  return -1;
}

#ifndef WPA_TRACE
void *os_zalloc(size_t size) { return calloc(1, size); }
#endif /* WPA_TRACE */

size_t os_strlcpy(char *dest, const char *src, size_t siz) {
  return strlcpy(dest, src, siz);
}

int os_memcmp_const(const void *a, const void *b, size_t len) {
  const u8 *aa = a;
  const u8 *bb = b;
  size_t i;
  u8 res;

  for (res = 0, i = 0; i < len; i++) res |= aa[i] ^ bb[i];

  return res;
}

#ifdef WPA_TRACE

#if defined(WPA_TRACE_BFD) && defined(CONFIG_TESTING_OPTIONS)
char wpa_trace_fail_func[256] = {0};
unsigned int wpa_trace_fail_after;

static int testing_fail_alloc(void) {
  const char *func[WPA_TRACE_LEN];
  size_t i, res, len;
  char *pos, *next;
  int match;

  if (!wpa_trace_fail_after) return 0;

  res = wpa_trace_calling_func(func, WPA_TRACE_LEN);
  i = 0;
  if (i < res && os_strcmp(func[i], __func__) == 0) i++;
  if (i < res && os_strcmp(func[i], "os_malloc") == 0) i++;
  if (i < res && os_strcmp(func[i], "os_zalloc") == 0) i++;
  if (i < res && os_strcmp(func[i], "os_calloc") == 0) i++;
  if (i < res && os_strcmp(func[i], "os_realloc") == 0) i++;
  if (i < res && os_strcmp(func[i], "os_realloc_array") == 0) i++;
  if (i < res && os_strcmp(func[i], "os_strdup") == 0) i++;

  pos = wpa_trace_fail_func;

  match = 0;
  while (i < res) {
    int allow_skip = 1;
    int maybe = 0;

    if (*pos == '=') {
      allow_skip = 0;
      pos++;
    } else if (*pos == '?') {
      maybe = 1;
      pos++;
    }
    next = os_strchr(pos, ';');
    if (next)
      len = next - pos;
    else
      len = os_strlen(pos);
    if (os_memcmp(pos, func[i], len) != 0) {
      if (maybe && next) {
        pos = next + 1;
        continue;
      }
      if (allow_skip) {
        i++;
        continue;
      }
      return 0;
    }
    if (!next) {
      match = 1;
      break;
    }
    pos = next + 1;
    i++;
  }
  if (!match) return 0;

  wpa_trace_fail_after--;
  if (wpa_trace_fail_after == 0) {
    wpa_printf(MSG_INFO, "TESTING: fail allocation at %s", wpa_trace_fail_func);
    for (i = 0; i < res; i++)
      wpa_printf(MSG_INFO, "backtrace[%d] = %s", (int)i, func[i]);
    return 1;
  }

  return 0;
}

char wpa_trace_test_fail_func[256] = {0};
unsigned int wpa_trace_test_fail_after;

int testing_test_fail(void) {
  const char *func[WPA_TRACE_LEN];
  size_t i, res, len;
  char *pos, *next;
  int match;

  if (!wpa_trace_test_fail_after) return 0;

  res = wpa_trace_calling_func(func, WPA_TRACE_LEN);
  i = 0;
  if (i < res && os_strcmp(func[i], __func__) == 0) i++;

  pos = wpa_trace_test_fail_func;

  match = 0;
  while (i < res) {
    int allow_skip = 1;
    int maybe = 0;

    if (*pos == '=') {
      allow_skip = 0;
      pos++;
    } else if (*pos == '?') {
      maybe = 1;
      pos++;
    }
    next = os_strchr(pos, ';');
    if (next)
      len = next - pos;
    else
      len = os_strlen(pos);
    if (os_memcmp(pos, func[i], len) != 0) {
      if (maybe && next) {
        pos = next + 1;
        continue;
      }
      if (allow_skip) {
        i++;
        continue;
      }
      return 0;
    }
    if (!next) {
      match = 1;
      break;
    }
    pos = next + 1;
    i++;
  }
  if (!match) return 0;

  wpa_trace_test_fail_after--;
  if (wpa_trace_test_fail_after == 0) {
    wpa_printf(MSG_INFO, "TESTING: fail at %s", wpa_trace_test_fail_func);
    for (i = 0; i < res; i++)
      wpa_printf(MSG_INFO, "backtrace[%d] = %s", (int)i, func[i]);
    return 1;
  }

  return 0;
}

#else

static inline int testing_fail_alloc(void) { return 0; }
#endif

void *os_malloc(size_t size) {
  struct os_alloc_trace *a;

  if (testing_fail_alloc()) return NULL;

  a = malloc(sizeof(*a) + size);
  if (a == NULL) return NULL;
  a->magic = ALLOC_MAGIC;
  dl_list_add(&alloc_list, &a->list);
  a->len = size;
  wpa_trace_record(a);
  return a + 1;
}

void *os_realloc(void *ptr, size_t size) {
  struct os_alloc_trace *a;
  size_t copy_len;
  void *n;

  if (ptr == NULL) return os_malloc(size);

  a = (struct os_alloc_trace *)ptr - 1;
  if (a->magic != ALLOC_MAGIC) {
    wpa_printf(MSG_INFO, "REALLOC[%p]: invalid magic 0x%x%s", a, a->magic,
               a->magic == FREED_MAGIC ? " (already freed)" : "");
    wpa_trace_show("Invalid os_realloc() call");
    abort();
  }
  n = os_malloc(size);
  if (n == NULL) return NULL;
  copy_len = a->len;
  if (copy_len > size) copy_len = size;
  os_memcpy(n, a + 1, copy_len);
  os_free(ptr);
  return n;
}

void os_free(void *ptr) {
  struct os_alloc_trace *a;

  if (ptr == NULL) return;
  a = (struct os_alloc_trace *)ptr - 1;
  if (a->magic != ALLOC_MAGIC) {
    wpa_printf(MSG_INFO, "FREE[%p]: invalid magic 0x%x%s", a, a->magic,
               a->magic == FREED_MAGIC ? " (already freed)" : "");
    wpa_trace_show("Invalid os_free() call");
    abort();
  }
  dl_list_del(&a->list);
  a->magic = FREED_MAGIC;

  wpa_trace_check_ref(ptr);
  free(a);
}

void *os_zalloc(size_t size) {
  void *ptr = os_malloc(size);
  if (ptr) os_memset(ptr, 0, size);
  return ptr;
}

char *os_strdup(const char *s) {
  size_t len;
  char *d;
  len = os_strlen(s);
  d = os_malloc(len + 1);
  if (d == NULL) return NULL;
  os_memcpy(d, s, len);
  d[len] = '\0';
  return d;
}

#endif /* WPA_TRACE */

int os_exec(const char *program, const char *arg, int wait_completion) {
  // Not implemented.
  return -1;
}
