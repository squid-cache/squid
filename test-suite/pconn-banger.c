
#include "config.h"

/*
 * On some systems, FD_SETSIZE is set to something lower than the
 * actual number of files which can be opened.  IRIX is one case,
 * NetBSD is another.  So here we increase FD_SETSIZE to our
 * configure-discovered maximum *before* any system includes.
 */
#define CHANGE_FD_SETSIZE 1

/* Cannot increase FD_SETSIZE on Linux */
#if defined(_SQUID_LINUX_)
#undef CHANGE_FD_SETSIZE
#define CHANGE_FD_SETSIZE 0
#endif

/* Cannot increase FD_SETSIZE on FreeBSD before 2.2.0, causes select(2)
 * to return EINVAL. */
/* Marian Durkovic <marian@svf.stuba.sk> */
/* Peter Wemm <peter@spinner.DIALix.COM> */
#if defined(_SQUID_FREEBSD_)
#include <osreldate.h>
#if __FreeBSD_version < 220000
#undef CHANGE_FD_SETSIZE
#define CHANGE_FD_SETSIZE 0
#endif
#endif

/* Increase FD_SETSIZE if SQUID_MAXFD is bigger */
#if CHANGE_FD_SETSIZE && SQUID_MAXFD > DEFAULT_FD_SETSIZE
#define FD_SETSIZE SQUID_MAXFD
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#ifdef HAVE_BSTRING_H
#include <bstring.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif

#define PROXY_PORT 3128
#define PROXY_ADDR "127.0.0.1"
#define MAX_FDS 1024
#define READ_BUF_SZ 4096
#define min(x,y) ((x)<(y)? (x) : (y))

static int proxy_port = PROXY_PORT;
static char *proxy_addr = PROXY_ADDR;
static char *progname;
static int noutstanding = 0;
static int done_reading_urls = 0;
static int opt_ims = 0;
static int max_connections = 64;
static time_t lifetime = 60;
static const char *const crlf = "\r\n";

#define REPLY_HDR_SZ 8192

struct _r {
    char *url;
    int content_length;
    int hdr_length;
    int hdr_offset;
    int bytes_read;
    char reply_hdrs[REPLY_HDR_SZ];
    struct _r *next;
};

static struct _r *Requests;

char *
mkrfc850(t)
     time_t *t;
{
    static char buf[128];
    struct tm *gmt = gmtime(t);
    buf[0] = '\0';
    (void) strftime(buf, 127, "%A, %d-%b-%y %H:%M:%S GMT", gmt);
    return buf;
}


char *
mime_headers_end(const char *mime)
{
    const char *p1, *p2;
    const char *end = NULL;

    p1 = strstr(mime, "\n\r\n");
    p2 = strstr(mime, "\n\n");

    if (p1 && p2)
	end = p1 < p2 ? p1 : p2;
    else
	end = p1 ? p1 : p2;
    if (end)
	end += (end == p1 ? 3 : 2);

    return (char *) end;
}

void
sig_intr(int sig)
{
    printf("\rWaiting for open connections to finish...\n");
    signal(sig, SIG_DFL);
}

int
open_http_socket(void)
{
    int s;
    struct sockaddr_in S;
    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	perror("socket");
	return -1;
    }
    memset(&S, '\0', sizeof(struct sockaddr_in));
    S.sin_family = AF_INET;
    S.sin_port = htons(proxy_port);
    S.sin_addr.s_addr = inet_addr(proxy_addr);
    if (connect(s, (struct sockaddr *) &S, sizeof(S)) < 0) {
	close(s);
	perror("connect");
	return -1;
    }
    return s;
}

int
send_request(int fd, const char *url)
{
    char buf[4096];
    int len;
    time_t w;
    struct _r *r;
    struct _r **R;
    buf[0] = '\0';
    strcat(buf, "GET ");
    strcat(buf, url);
    strcat(buf, " HTTP/1.0\r\n");
    strcat(buf, "Accept: */*\r\n");
    strcat(buf, "Proxy-Connection: Keep-Alive\r\n");
    if (opt_ims && (lrand48() & 0x03) == 0) {
	w = time(NULL) - (lrand48() & 0x3FFFF);
	strcat(buf, "If-Modified-Since: ");
	strcat(buf, mkrfc850(&w));
	strcat(buf, "\r\n");
    }
    strcat(buf, "\r\n");
    len = strlen(buf);
    if (write(fd, buf, len) < 0) {
	close(fd);
	perror("write");
	return -1;
    }
    r = calloc(1, sizeof(struct _r));
    r->url = strdup(url);
    for (R = &Requests; *R; R = &(*R)->next);
    *R = r;
    fprintf(stderr, "REQUESTED %s\n", url);
    noutstanding++;
    return 0;
}

static int
get_header_int_value(const char *hdr, const char *buf, const char *end)
{
    const char *t;
    for (t = buf; t < end; t += strcspn(t, crlf), t += strspn(t, crlf)) {
	if (strncasecmp(t, hdr, strlen(hdr)) == 0) {
	    t += strlen(hdr);
	    while (isspace(*t))
		t++;
	    return atoi(t);
	}
    }
    return 0;
}

int
handle_read(char *buf, int len)
{
    struct _r *r = Requests;
    const char *end;
    int hlen;
    if (len < 0) {
	perror("read");
	Requests = r->next;
	free(r);
	noutstanding--;
	return -1;
    }
    if (len == 0) {
	fprintf(stderr, "DONE: %s, server closed socket, read %d bytes\n", r->url, r->bytes_read);
	Requests = r->next;
	free(r);
	noutstanding--;
	return -1;
    }
    if (r->hdr_length == 0) {
	hlen = min(len, REPLY_HDR_SZ - r->hdr_length);
	strncpy(r->reply_hdrs + r->hdr_length, buf, hlen);
	r->hdr_offset += hlen;
	*(r->reply_hdrs + REPLY_HDR_SZ - 1) = '\0';
    }
    if (r->hdr_length == 0 && (end = mime_headers_end(r->reply_hdrs)) != NULL) {
	fprintf(stderr, "FOUND EOH FOR %s\n", r->url);
	r->hdr_length = end - r->reply_hdrs;
	fprintf(stderr, "HDR_LENGTH = %d\n", r->hdr_length);
	r->content_length = get_header_int_value("content-length:", r->reply_hdrs, end);
	fprintf(stderr, "CONTENT_LENGTH = %d\n", r->content_length);
    }
    if (r->content_length && r->hdr_length) {
	int bytes_left = r->content_length + r->hdr_length - r->bytes_read;
	int bytes_used = len > bytes_left ? bytes_left : len;
	r->bytes_read += bytes_used;
	len -= bytes_used;
	if (r->bytes_read == r->content_length + r->hdr_length) {
	    fprintf(stderr, "DONE: %s, (%d == %d+%d)\n",
		r->url,
		r->bytes_read,
		r->hdr_length,
		r->content_length);
	    Requests = r->next;
	    free(r);
	    noutstanding--;
	} else {
	    assert(r->bytes_read < r->content_length + r->hdr_length);
	}
	if (len) {
	    assert(bytes_used > 0);
	    xmemmove(buf, buf + bytes_used, len);
	    return handle_read(buf, len);
	}
    }
    return 0;
}

int
read_reply(int fd)
{
    static char buf[READ_BUF_SZ];
    int len;
    int x;
    len = read(fd, buf, READ_BUF_SZ);
    x = handle_read(buf, len);
    if (x < 0)
	close(fd);
    return x;
}

void
main_loop(void)
{
    static int pconn_fd = -1;
    static char buf[8192];
    struct timeval to;
    fd_set R;
    struct _r *r;
    struct _r *nextr;
    int x;
    int timeouts;
    while (!done_reading_urls || noutstanding) {
	if (timeouts == 20) {
	    close(pconn_fd);
	    pconn_fd = -1;
	    r = Requests;
	    Requests = Requests->next;
	    free(r);
	    noutstanding--;
	}
	if (pconn_fd < 0) {
	    pconn_fd = open_http_socket();
	    if (pconn_fd < 0) {
		perror("socket");
		exit(1);
	    }
	    nextr = Requests;
	    Requests = NULL;
	    while ((r = nextr) != NULL) {
		nextr = r->next;
		send_request(pconn_fd, r->url);
		free(r);
		noutstanding--;
	    }
	    timeouts = 0;
	}
	if (noutstanding < 10 && !done_reading_urls) {
	    char *t;
	    if (fgets(buf, 8191, stdin) == NULL) {
		printf("Done Reading URLS\n");
		done_reading_urls = 1;
		break;
	    }
	    if ((t = strchr(buf, '\n')))
		*t = '\0';
	    send_request(pconn_fd, buf);
	    timeouts = 0;
	}
	FD_ZERO(&R);
	to.tv_sec = 1;
	to.tv_usec = 0;
	FD_SET(pconn_fd, &R);
	x = select(pconn_fd + 1, &R, NULL, NULL, &to);
	if (x < 0) {
	    if (errno != EINTR)
		perror("select");
	    continue;
	} else if (x == 0) {
	    assert(Requests != NULL);
	    fprintf(stderr, "TIMEOUT %s; %d, %d\n", Requests->url,
		++timeouts, noutstanding);
	    continue;
	}
	if (FD_ISSET(pconn_fd, &R)) {
	    timeouts = 0;
	    if (read_reply(pconn_fd) != 0)
		pconn_fd = -1;
	}
    }
}

void
usage(void)
{
    fprintf(stderr, "usage: %s: -p port -h host -n max\n", progname);
}

int
main(argc, argv)
     int argc;
     char *argv[];
{
    int c;
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    progname = strdup(argv[0]);
    while ((c = getopt(argc, argv, "p:h:n:il:")) != -1) {
	switch (c) {
	case 'p':
	    proxy_port = atoi(optarg);
	    break;
	case 'h':
	    proxy_addr = strdup(optarg);
	    break;
	case 'n':
	    max_connections = atoi(optarg);
	    break;
	case 'i':
	    opt_ims = 1;
	    break;
	case 'l':
	    lifetime = (time_t) atoi(optarg);
	    break;
	default:
	    usage();
	    return 1;
	}
    }
    signal(SIGINT, sig_intr);
    signal(SIGPIPE, SIG_IGN);
    main_loop();
    return 0;
}
