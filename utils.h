#ifndef UTIL_H
#define UTIL_H

#define _GNU_SOURCE

#include <sys/types.h>
#include <stdlib.h>

// #define DEBUG 0

#ifdef DEBUG
#define DEBUG_TEST 1
#else
#define DEBUG_TEST 0
#endif


#define         STRCMP(a, R, b)         (strcmp(a, b) R 0)

#define debug_print(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
			__LINE__, __func__, ##__VA_ARGS__); } while (0)


#define debug_kprint(...) \ do { if (DEBUG) \ printk("DRIVER_NAME:"); \ printk(__VA_ARGS__); \ 			printk("\n"); \ } while (0)

int IsPathExist(const char *path_name);
int SafeWrite2File(const char *fn, const char *buf, size_t buflen);
char *Trim(char *str);
int is_valid_ip_address(const char *ip_address);
int is_valid_mac_address(const char* mac);
int is_digits(const char *str);
void s_sleep(unsigned int s, unsigned int u);
void get_timestamp_millisecond(long int *sec, long int *usec);
int substring(char *dest, int dest_len, const char *src, int start, int end);
int IsALNUMornot(const char *string);
int http_url_format(const char *orig_url, char *url_result_buf, int buf_len);
int get_child_pids(int parent_pid, char *exec_cmd, int *child_pids, int len, char stat);
int get_ancestor_pid(char *exec_cmd, int target_pid);
int get_pure_md5sum(const char *md5_sum, char *pure_md5_buf, int buf_len);
#endif // UTIL_H