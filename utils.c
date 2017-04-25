/* created by gukq.20160420 gukaiqiang@kunteng.org
 *
 */

#include <stdlib.h>
#include <sys/file.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <curl/curl.h>
#include <curl/easy.h>

#include "utils.h"

#define PROC_PATH "/proc"
#define PATH_NAME_LEN 512
#define PID_STAT_BUF_LEN 1024

// exist 1, not exist return 0
int 
IsPathExist(const char *path_name) {
	if (access(path_name, F_OK) != -1) {
		return 1;
	}else{
		return 0;
	}
}

// if cannot open file fn, return -1, or return written size when sccessed
int 
SafeWrite2File(const char *fn, const char *buf, size_t buflen) {
	int fd;
	int written_size = 0;

	fd = open(fn, O_WRONLY|O_CREAT);
	if ( fd == -1 ) {
		return -1;
	}

	flock(fd, LOCK_EX);
	written_size = write(fd, buf, buflen);
	close(fd);
	flock(fd, LOCK_UN);
	return (int) written_size;
}

// Trim: This function returns a pointer to a substring of the original string.
// If the given string was allocated dynamically, the caller must not overwrite
// that pointer with the returned value, since the original pointer must be
// deallocated using the same allocator with which it was allocated.  The return
// value must NOT be deallocated using free() etc.
char 
*Trim(char *str) {
	char *end;

	// Trim leading space
	while(isspace(*str)) str++;

	if(*str == 0){ // All spaces?
		return str;
	}  

	// Trim trailing space
	end = str + strlen(str) - 1;
	while(end > str && isspace(*end)) end--;

	// Write new null terminator
	*(end + 1) = 0;

	return str;
}

// is_valid_ip_address:
// return 0:ipaddress unlegal
int 
is_valid_ip_address(const char *ip_address) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_address, &(sa.sin_addr));
	return result;
}

// is_valid_mac_address:
// mac must be end by '/0'
// return 0:mac unlegal; 1: mac address is valid
int is_valid_mac_address(const char* mac) {
	if (mac == NULL) {
		return 0;
	}
    int i = 0;
    int s = 0;

    while (*mac) {
       if (isxdigit(*mac)) {
          i++;
       }
       else if (*mac == ':') {
          if (i == 0 || (i / 2 - 1 != s)){
            break;
		  }
          ++s;
       }
       else {
           s = -1;
       }

       ++mac;
    }

    return (i == 12 && (s == 5 || s == 0));
}


// is_digits: check all charactor in str is digit
// return 0:error, other: all digit
int
is_digits(const char *str) {
	int ret = 1;
	if (str == NULL) {
		return 0;
	}

	unsigned int i = 0;
	for(; i<strlen(str); i++) {
		ret = isdigit(str[i]);
		if(ret){
			continue;
		}else{
			break;
		}
	}

	return ret;
}

// s_sleep using select instead of sleep
// s: second, u: usec 10^6usec = 1s
void 
s_sleep(unsigned int s, unsigned int u){
	struct timeval timeout;

	timeout.tv_sec = s;
	timeout.tv_usec = u;
	select(0, NULL, NULL, NULL, &timeout);
}

// get_timestamp_millisecond get timestamp from time-now
// it writes resut of unix-time to "sec" and "usec"
void 
get_timestamp_millisecond(long int *sec, long int *usec) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	*sec = tv.tv_sec;
	*usec = tv.tv_usec;
}



/*
 * Input:	dest-	target buffer
 * 			src-		source buffer
 *			start-	begin with 0, start mark
 *			end- 	end mark
 * return:
*/
int 
substring(char *dest, int dest_len, const char *src, int start, int end) {
	if (src == NULL || dest == NULL) {
		return 1;
	}
	
	if (start < 0 || end < 0 || end - start < 0) {
		return 1;
	}

	if (dest_len < (end - start + 1)) {
		return 1;
	}

	int i = start;

	if( (unsigned int )start > strlen(src) ) {
		return 1;
	}

	if( (unsigned int )end > strlen(src) ) {
		end = strlen(src);
	}
		
	while( i < end ) {
		dest[i-start] = src[i];
		i++;
	}
	dest[i-start] = '\0';
	return 0;
}

/*
 * return:	0-string is made of alphanumeric.
 *			1-string is mixed with no-alphanumeric, field.
*/
int 
IsALNUMornot(const char *string) {
	if (string == NULL) {
		return 1;
	}
	
	int ret = 0;
	unsigned int i = 0;
	for( i=0;i<strlen(string);i++ )
		if( !isalnum(string[i]) ){
			ret = 1;
			break;
		}

	return ret;
}

// e.g.:http:\/\/114.112.99.152:31100\/firmware\/R7800_74MB\/test.bin to
// 	http://114.112.99.152:31100/firmware/R7800_74MB/test.bin
int 
http_url_format(const char *orig_url, char *url_result_buf, int buf_len) {
	int orig_url_len = strlen(orig_url);
	if (buf_len <= orig_url_len) {
		return -1;
	}

	int i = 0, j = 0;
	for(;i < orig_url_len; i++) {
		if (orig_url[i] != '\\') {
			url_result_buf[j] = orig_url[i];
			j++;
		}
	}

	return i-j;
}


// get_child_pids get all child pids from gaven parent pid
// argument child_pids is a buffer which will be inset result pid
// return: -1: error, >=0 child pids count
int
get_child_pids(int parent_pid, char *exec_cmd, int *child_pids, int len, char stat) {
	if (stat != 'Z' && stat != 'S' && stat != 'R' && stat != 0 ) {
		return -1;
	}

	if (parent_pid <= 0) {
		return -1;
	}

	if (child_pids == NULL) {
		return -1;
	}

	char target_exec_cmd[64] = {0};
	if (NULL != exec_cmd) {
		snprintf(target_exec_cmd, sizeof(target_exec_cmd), "(%s)", exec_cmd);
	}

	char parent_pid_str[8] = {0};
	snprintf(parent_pid_str, sizeof(parent_pid_str), "%d", parent_pid);

	struct dirent *ptr = NULL;
	DIR *dir = opendir(PROC_PATH);
	if (dir == NULL) {
		perror("Open dir error...");
        return -1;
	}

	int count = 0;
	char proc_path[PATH_NAME_LEN] = {0};

	/* because of PID_STAT_BUF_LEN, 'others' is safe when using sscanf */
	char proc_stat_buf[PID_STAT_BUF_LEN] = {0};
	char others[PID_STAT_BUF_LEN] = {0};

	char pid_str[8]={0}, cmd_buf[64]={0}, pstat[4]={0}, ppid_str[8]={0}, init_pid[8] = {0};
	char *endptr;
	char stat_str[2] = {0};
	int pid = 0;

	snprintf(stat_str, sizeof(stat_str), "%c", stat);
	while( (ptr=readdir(dir)) != NULL && count < len ) {
		if( STRCMP(ptr->d_name, ==, ".") || STRCMP(ptr->d_name, ==, "..") ){
			//current dir OR parrent dir
            continue;
        } else if( ptr->d_type == 4 ) { //dir
            if (is_digits(ptr->d_name)) {
				snprintf(proc_path, 
						sizeof(proc_path), 
						"%s/%s/stat", 
						PROC_PATH, 
						ptr->d_name);

				FILE *fp = fopen(proc_path, "r");
				if (fp == NULL) {
					char err_buf[PATH_NAME_LEN + 64] = {0};
					snprintf(err_buf, sizeof(err_buf), "get_child_pids %s", proc_path);
					perror(err_buf);
					continue;
				}

				fread(proc_stat_buf, sizeof(proc_stat_buf), 1, fp);
				Trim(proc_stat_buf);
				sscanf(proc_stat_buf, 
					"%s %s %s %s %s %s", 
					pid_str, 
					cmd_buf, 
					pstat, 
					ppid_str, 
					init_pid,
					others);
				fclose(fp);

				if ( (STRCMP(parent_pid_str, ==, init_pid)) && 
					(exec_cmd == NULL || (STRCMP(cmd_buf, ==, target_exec_cmd))) && 
					(stat == 0 || STRCMP(stat_str, ==, pstat)) ) {

					pid = strtoimax(pid_str, &endptr, 10);
					if (endptr != NULL) {
						child_pids[count] = pid;
						count++;
						memset(pid_str, 0, sizeof(pid_str));
						memset(pstat, 0, sizeof(pstat));
						memset(ppid_str, 0, sizeof(ppid_str));
						memset(init_pid, 0, sizeof(init_pid));
					}
				}
			}
        }
	}

	closedir(dir);
	return count;
}

// get_ancestor_pid:
// arguments:
//		exec_cmd: exec_cmd name, if exec_cmd is NULL, only check with target_pid.
//		target_pid: the target pid of the exec_cmd which be checked, if check all (but will //			return the first one), it should be set 0
//
//		WARNING: exec_cmd and target_pid mustn't equal with NULL/0 at the same time
// return: -1 failed; other(>0):ancestor pid, success
int
get_ancestor_pid(char *exec_cmd, int target_pid) {
	if (target_pid < 0 || (exec_cmd == NULL && target_pid == 0)) {
		return -1;
	}

	struct dirent *ptr = NULL;
	DIR *dir = opendir(PROC_PATH);
	if (dir == NULL) {
		perror("Open dir error...");
        return -1;
	}

	char proc_path[PATH_NAME_LEN] = {0};

	char target_exec_cmd[64] = {0};
	if (exec_cmd) {
		snprintf(target_exec_cmd, sizeof(target_exec_cmd), "(%s)", exec_cmd);
	}

	/* because of PID_STAT_BUF_LEN, 'others' is safe when using sscanf */
	char proc_stat_buf[PID_STAT_BUF_LEN] = {0};
	char others[PID_STAT_BUF_LEN] = {0};
	char pid_str[8]={0}, cmd_buf[64]={0}, pstat[4]={0}, ppid_str[8]={0}, init_pid[8] = {0};
	char *pid_str_p = NULL;
	int ancestor_pid = -1;
	int proc_pid = 0;
	while( (ptr=readdir(dir)) != NULL ) {
		if( STRCMP(ptr->d_name, ==, ".") || STRCMP(ptr->d_name, ==, "..") ){
			//current dir OR parrent dir
            continue;
        } else if( ptr->d_type == 4 ) { //dir
            if (is_digits(ptr->d_name)) {
				snprintf(proc_path, 
						sizeof(proc_path), 
						"%s/%s/stat", 
						PROC_PATH, 
						ptr->d_name);

				FILE *fp = fopen(proc_path, "r");
				if (fp == NULL) {
					char err_buf[PATH_NAME_LEN + 64] = {0};
					snprintf(err_buf, sizeof(err_buf), "get_child_pids %s", proc_path);
					perror(err_buf);
					continue;
				}

				fread(proc_stat_buf, sizeof(proc_stat_buf), 1, fp);
				fclose(fp);

				Trim(proc_stat_buf);
				sscanf(proc_stat_buf, 
					"%s %s %s %s %s %s", 
					pid_str, 
					cmd_buf, 
					pstat, 
					ppid_str, 
					init_pid,
					others);

				errno = 0;
				if (target_pid){
					proc_pid = strtoimax(pid_str, &pid_str_p, 10);
					if (errno) {
						perror("get_ancestor_pid pid");
						ancestor_pid = -1;
						break;
					}
				}
				
				if ((exec_cmd && STRCMP(cmd_buf, ==, target_exec_cmd)) &&
					(target_pid == proc_pid)) {
						
					ancestor_pid = strtoimax(init_pid, &pid_str_p, 10);
					if (errno) {
						perror("get_ancestor_pid init_pid");
						ancestor_pid = 0;
						break;
					}

					if (!ancestor_pid){
						ancestor_pid = -1;
					}
					break;
				}
			}
        }
	}

	closedir(dir);
	return ancestor_pid;
}

// get_pure_md5sum eg:
// 20834e37730ba6d7f881b7a89f7e55b3  mdresult.exp get 20834e37730ba6d7f881b7a89f7e55b3
// return: 0: succeed, 1: failed
int 
get_pure_md5sum(const char *md5_sum, char *pure_md5_buf, int buf_len) {
	if (md5_sum == NULL || strlen(md5_sum) < 32 || buf_len <= 32) {
		return 1;
	}

	snprintf(pure_md5_buf, 32+1, "%s", md5_sum);
	if (IsALNUMornot(pure_md5_buf)) {
		return 1;
	}

	return 0;
}

/* my curl functions define */

/*
 * NAME curl_init()
 *
 * DESCRIPTION
 *
 * curl_init() will call libcurl func curl_global_init(), which should be invoked 
 * exactly once for each application that uses libcurl and before any call of 
 * other libcurl functions.
 *
 * This function is not thread-safe! So I allways dont't use it ---- By KerwinKoo
 */
void curl_init() {
	curl_global_init(CURL_GLOBAL_DEFAULT);
}

static int dl_progress(void *clientp,double dltotal,double dlnow,double ultotal,double ulnow) {
    // if (dlnow && dltotal)
    //     printf("dl:%3.0f%%\r",100*dlnow/dltotal); //shenzi prog-mon 
	// //	printf("dl:%3.0f\r",100*dlnow/dltotal); //shenzi prog-mon 
    // fflush(stdout);
    return 0;
}

// dl_write callback func, write bytes into File 
static size_t dl_write(void *buffer, const size_t size, const size_t nmemb, void *stream) {    
	return fwrite(buffer, size, nmemb, (FILE*)stream); 
}

static size_t write_to_mycurl_string(void *buffer, 
									const size_t size, 
									const size_t nmemb, 
									struct mycurl_string *s) {
	size_t new_len = s->len + size*nmemb;
	// s->ptr = realloc(s->ptr, new_len + 1); // realloc is NOT recommended
	size_t malloc_len = new_len + 1;
	char *tmp_p = os_malloc(malloc_len);
	if (tmp_p == NULL) {
		return 0;
	}

	memset(tmp_p, 0, malloc_len);
	memcpy(tmp_p, s->ptr, s->len);
	free(s->ptr);
	s->ptr = tmp_p;
	memcpy(s->ptr + s->len, buffer, size*nmemb);

	return size*nmemb;
}

struct mycurl_string *mycurl_string_init(struct mycurl_string *stream) {
	stream->len = 0;
	stream->ptr = os_malloc(stream->len+1);

	if (stream->ptr == NULL) {
		return NULL;
	}

	stream->ptr[0] = '\0';
	return stream;
}

void mycurl_string_free(struct mycurl_string *stream) {
	if (stream != NULL && stream->ptr != NULL) {
		free(stream->ptr);
	}
}

// curl_download main curl download func
// return : 0=succeed
// 			1-failed/err with some reason that could not download, reason code 
//				saved in state_code argument.
int download(char *url, 
			char *target_filename, 
			int resume_enable,
			long timeout, 
			int *state_code,
			double *download_size) {
				
	if (target_filename == NULL) {
		return 1;
	}

	CURL *curl;
    FILE *fp;
	CURLcode curl_retval;
	long http_response;
	double dl_size;
	int could_be_resume = 0;
	struct stat st={0};
	int file_stat = 0;
	int ret = 1;

	/* dl_lowspeed_time seconds while below low spped limit before aborting 
	 * dl_lowspeed_bytes is the limitation. 
	 */
    long dl_lowspeed_bytes = 1000; //1K
	*state_code = CURL_OK;
    long dl_lowspeed_time = 60; //sec
	if (timeout <= 0) {
		*state_code = CURL_TIMEOUT_SET_ERR;
		return ret;
	}
	file_stat = stat(target_filename, &st);
    if (file_stat) {
		// file is not existed, so create new one
		;
    }else{
		//file is existed, so it could be using resume func
		if (resume_enable) {
			could_be_resume = 1;
		}else{
			if( remove(target_filename) ) { // remove return 0 if succeed
				*state_code = CURL_FILE_DEL_ERR;
				return ret;
			}
		}
	}

	if(!(fp=fopen(target_filename, "ab")/*append binary*/)) {
		*state_code = CURL_FILE_OPEN_ERR;
		return ret; 
	}
	curl = curl_easy_init();

	if (curl) {
        //http://linux.die.net/man/3/curl_easy_setopt
        curl_easy_setopt(curl, CURLOPT_URL, url);
        /*callbacks*/
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dl_write);
        curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, dl_progress);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);

        /*curl will keep running -so you have the freedom to recover 
        from network disconnects etc in your own way without
        distrubing the curl task in hand. ** this is by design :p ** */ 
		// everything need be downloaded in CURLOPT_TIMEOUT limit
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30);
        /*set up min download speed threshold & time endured before aborting*/
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, dl_lowspeed_bytes); //bytes/sec

		/* seconds while below low spped limit before aborting */
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, dl_lowspeed_time); 
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

		if (resume_enable && could_be_resume) {
			curl_easy_setopt(curl, CURLOPT_RESUME_FROM,st.st_size);
		}

        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1); // handle 302 and 301
        /*digitals to descrip info,
		 *uncomment this to get curl to tell you what its up to*/
#if CURL_DEBUG
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif
        if(CURLE_OK != (curl_retval = curl_easy_perform(curl))) {
			switch(curl_retval) {
				//Transferred a partial file
				//all defined in curl/curl.h 
				default: //suggest quitting on unhandled error
					*state_code = curl_retval;
			};

            curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &dl_size);
			*download_size = dl_size;
            curl_retval=curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response);

            //see: http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
            switch(http_response){
				//eg connection down  from kick-off ~suggest retrying till some max limit
				case 200: //yay we at least got to our url
					*state_code = CURL_HTTP_200;
					break;
				case 404:
					ret = 1;
					break;
				case 206:
				case 416: //http://www.checkupdown.com/status/E416.html
				default: //suggest quitting on an unhandled error
					*state_code = CURL_HTTP_OTHER;
					break;
            };
		} else { //our work here is done ;)
            ret = 0;
        }
		fclose(fp);

        if (curl){
			curl_easy_cleanup(curl);
		}
	}

	return ret;
}

// net_visit
// return : 0=succeed
// 			1-failed/err with some reason that could not download, reason code 
//				saved in state_code argument.
int 
net_visit(char *url, 
			struct mycurl_string *s,
			int method,
			char *post_buf,
			long timeout, 
			int *state_code,
			double *down_size) {

	CURL *curl;
	CURLcode curl_retval;
	long http_response;
	double dl_size;
	int could_be_resume = 0;
	struct stat st={0};
	int file_stat = 0;
	int ret = 1;

	/* dl_lowspeed_time seconds while below low spped limit before aborting 
	 * dl_lowspeed_bytes is the limitation. 
	 */
    long dl_lowspeed_bytes = 1000; //1K
	*state_code = CURL_OK;
    long dl_lowspeed_time = 60; //sec
	if (timeout <= 0) {
		*state_code = CURL_TIMEOUT_SET_ERR;
		return ret;
	}

	curl = curl_easy_init();
	if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        /*callbacks*/
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_mycurl_string);
        curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, dl_progress);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, dl_lowspeed_bytes); //bytes/sec

		/* seconds while below low spped limit before aborting */
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, dl_lowspeed_time); 
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, s);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1); // handle 302 and 301

		if (method == POST) {
			char *self_post_buf = post_buf == NULL ? "/0":post_buf;
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, self_post_buf);
		}
        /*digitals to descrip info,
		 *uncomment this to get curl to tell you what its up to*/
#if CURL_DEBUG
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif
        if(CURLE_OK != (curl_retval = curl_easy_perform(curl))) {
			switch(curl_retval) {
				//Transferred a partial file
				//all defined in curl/curl.h 
				default: //suggest quitting on unhandled error
					*state_code = curl_retval;
			};

            curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &dl_size);
			*down_size = dl_size;
            curl_retval=curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response);

            switch(http_response){
				case 200: //yay we at least got to our url
					*state_code = CURL_HTTP_200;
					break;
				case 404:
					ret = 1;
					break;
				case 206:
				case 416: //http://www.checkupdown.com/status/E416.html
				default: //suggest quitting on an unhandled error
					*state_code = CURL_HTTP_OTHER;
					break;
            };
		} else { //our work here is done ;)
            ret = 0;
        }

        if (curl){
			curl_easy_cleanup(curl);
		}
	}

	return ret;
}