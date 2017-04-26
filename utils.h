#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

// #define DEBUG 0

#ifdef DEBUG
#define DEBUG_TEST 1
#else
#define DEBUG_TEST 0
#endif

#ifndef os_malloc
#define os_malloc(s) malloc((s))
#endif
#ifndef os_memset
#define os_memset(s, c, n) memset(s, c, n)
#endif
#ifndef os_free
#define os_free(p) free((p))
#endif

#define         STRCMP(a, R, b)         (strcmp(a, b) R 0)

/* curl define */
// curl methods 
#define GET 0
#define POST 1

#define CURL_DEBUG 0

#define CURL_OK 0x900
#define CURL_TIMEOUT_SET_ERR 0x901
#define CURL_FILE_DEL_ERR 0x902
#define CURL_FILE_OPEN_ERR 0x903
#define CURL_PERFORM_UNHANDLED_ERR 0x904
#define CURL_HTTP_200 0x905
#define CURL_HTTP_404 0x906
#define CURL_HTTP_OTHER 0x999

#define debug_print(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
			__LINE__, __func__, ##__VA_ARGS__); } while (0)


#define debug_kprint(...) \ do { if (DEBUG) \ printk("DRIVER_NAME:"); \ printk(__VA_ARGS__); \ 			printk("\n"); \ } while (0)


/* structs define */
struct mycurl_string {
	char *ptr;
	size_t len;
};

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

void curl_init();
void mycurl_string_free(struct mycurl_string *stream);
struct mycurl_string *mycurl_string_init(struct mycurl_string *stream);
int download(char *url, 
			char *target_filename, 
			int resume_enable,
			long timeout, 
			int *state_code,
			double *download_size);

int net_visit(const char *url, 
			struct mycurl_string *s,
			int method,
			char *post_buf,
			long timeout, 
			int *state_code,
			double *down_size);

#endif // UTIL_H