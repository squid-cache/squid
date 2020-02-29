/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_TIME_H
#include <time.h>
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
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#define PROXY_PORT "3128"
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
static int opt_checksum = 0;
static int opt_reopen = 1;
static int max_outstanding = 10;
static time_t lifetime = 60;
static const char *const crlf = "\r\n";
static int trace_fd = -1;
static int total_bytes_read = 0;

#define REPLY_HDR_SZ 8192

struct _r {
    char url[1024];
    int content_length;
    int hdr_length;
    int hdr_offset;
    int bytes_read;
    char reply_hdrs[REPLY_HDR_SZ];
    struct _r *next;
    long sum;
    long validsize;
    long validsum;
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
    fprintf(stderr, "\rWaiting for open connections to finish...\n");
    signal(sig, SIG_DFL);
    done_reading_urls = 1;
}

int
open_http_socket(void)
{
    int s;
    struct addrinfo *AI = NULL;
    struct addrinfo hints;

    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    getaddrinfo(proxy_addr, proxy_port, &hints, AI);

    if ((s = socket(AI->ai_family, AI->ai_socktype, AI->ai_protocol)) < 0) {
        perror("socket");
        s = -1;
    } else if (connect(s, AI->ai_addr, AI->ai_addrlen) < 0) {
        close(s);
        perror("connect");
        s = -1;
    }

    freeaddrinfo(AI);
    return s;
}

int
send_request(int fd, const char *data)
{
    char msg[4096], buf[4096];
    int len;
    time_t w;
    struct _r *r;
    struct _r **R;
    char *method, *url, *file, *size, *checksum;
    char *tmp = xstrdup(data);
    struct stat st;
    int file_fd = -1;
    method = strtok(tmp, " ");
    url = strtok(NULL, " ");
    file = strtok(NULL, " ");
    size = strtok(NULL, " ");
    checksum = strtok(NULL, " ");
    if (!url) {
        url = method;
        method = "GET";
    }
    if (file && strcmp(file, "-") == 0)
        file = NULL;
    if (size && strcmp(size, "-") == 0)
        size = NULL;
    if (checksum && strcmp(checksum, "-") == 0)
        checksum = NULL;
    msg[0] = '\0';
    snprintf(buf, sizeof(buf)-1, "%s %s HTTP/1.0\r\n", method, url);
    strcat(msg, buf);
    strcat(msg, "Accept: */*\r\n");
    strcat(msg, "Proxy-Connection: Keep-Alive\r\n");
    if (opt_ims && (lrand48() & 0x03) == 0) {
        w = time(NULL) - (lrand48() & 0x3FFFF);
        snprintf(buf, sizeof(buf)-1, "If-Modified-Since: %s\r\n", mkrfc850(&w));
        strcat(msg, buf);
    }
    if (file) {
        if ((file_fd = open(file, O_RDONLY)) < 0) {
            perror("open");
            return -1;
        }
        if (fstat(file_fd, &st)) {
            perror("fstat");
            close(file_fd);
            return -1;
        }
        snprintf(buf, sizeof(buf)-1, "Content-length: %d\r\n", st.st_size);
        strcat(msg, buf);
    }
    strcat(msg, "\r\n");
    len = strlen(msg);
    if (write(fd, msg, len) < 0) {
        close(fd);
        perror("request write");
        close(file_fd);
        return -1;
    }
    if (file) {
        while ((len = read(file_fd, buf, sizeof buf)) > 0) {
            if (write(fd, buf, len) < 0) {
                close(fd);
                perror("body write");
                close(file_fd);
                return -1;
            }
        }
        if (len < 0) {
            perror("file read");
            close(file_fd);
            return -1;
        }
        close(file_fd);
    }
    r = calloc(1, sizeof(struct _r));
    strcpy(r->url, url);
    if (size)
        r->validsize = atoi(size);
    else
        r->validsize = -1;
    if (checksum)
        r->validsum = atoi(checksum);
    for (R = &Requests; *R; R = &(*R)->next);
    *R = r;
    /*    fprintf(stderr, "REQUESTED %s\n", url); */
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
            while (xisspace(*t))
                t++;
            return atoi(t);
        }
    }
    return -1;
}

static const char *
get_header_string_value(const char *hdr, const char *buf, const char *end)
{
    const char *t;
    static char result[8192];
    for (t = buf; t < end; t += strcspn(t, crlf), t += strspn(t, crlf)) {
        if (strncasecmp(t, hdr, strlen(hdr)) == 0) {
            t += strlen(hdr);
            while (xisspace(*t))
                t++;
            strcpy(result, "");
            strncat(result, t, strcspn(t, crlf));
            return result;
        }
    }
    return NULL;
}

void
request_done(struct _r *r)
{
#if 0
    fprintf(stderr, "DONE: %s, (%d+%d)\n",
            r->url,
            r->hdr_length,
            r->content_length);
#endif
    if (r->content_length != r->bytes_read)
        fprintf(stderr, "ERROR! Short reply, expected %d bytes got %d\n",
                r->content_length, r->bytes_read);
    else if (r->validsize >= 0) {
        if (r->validsize != r->bytes_read)
            fprintf(stderr, "WARNING: %s Object size mismatch, expected %d got %d\n",
                    r->url, r->validsize, r->bytes_read);
        else if (opt_checksum && r->sum != r->validsum)
            fprintf(stderr, "WARNING: %s Checksum error. Expected %d got %d\n",
                    r->url, r->validsum, r->sum);
    }
}
int
handle_read(char *inbuf, int len)
{
    struct _r *r = Requests;
    const char *end;
    const char *url;
    static char buf[READ_BUF_SZ];
    int hlen, blen;
    if (len < 0) {
        perror("read");
        Requests = r->next;
        request_done(r);
        free(r);
        noutstanding--;
        if (trace_fd >= 0)
            write(trace_fd, "\n[CLOSED]\n", 10);
        return -1;
    }
    total_bytes_read += len;
    memcpy(buf, inbuf, len);
    if (len == 0) {
        fprintf(stderr, "WARNING: %s, server closed socket after %d+%d bytes\n", r->url, r->hdr_offset, r->bytes_read);
        /* XXX, If no data was received and it isn't the first request on this
         * connection then the request should be restarted rather than aborted
         * but this is a simple test program an not a full blown HTTP client.
         */
        request_done(r);
        Requests = r->next;
        free(r);
        noutstanding--;
        return -1;
    }
    if (trace_fd > 0)
        write(trace_fd, buf, len);
    while (len > 0) {
        /* Build headers */
        if (r->hdr_length == 0) {
            hlen = min(len, REPLY_HDR_SZ - r->hdr_offset - 1);
            memcpy(r->reply_hdrs + r->hdr_offset, buf, hlen);
            r->hdr_offset += hlen;
            r->reply_hdrs[r->hdr_offset] = '\0';
            len -= hlen;
            /* Save any remaining read data */
            memmove(buf, buf + hlen, len);
        }
        /* Process headers */
        if (r->hdr_length == 0 && (end = mime_headers_end(r->reply_hdrs)) != NULL) {
#if 0
            fprintf(stderr, "FOUND EOH FOR %s\n", r->url);
            */
#endif
            r->hdr_length = end - r->reply_hdrs;
#if 0
            fprintf(stderr, "HDR_LENGTH = %d\n", r->hdr_length);
#endif
            /* "unread" any body contents received */
            blen = r->hdr_offset - r->hdr_length;
            assert(blen >= 0);
            if (blen > 0) {
                memmove(buf + blen, buf, len);
                memcpy(buf, r->reply_hdrs + r->hdr_length, blen);
                len += blen;
            }
            r->reply_hdrs[r->hdr_length] = '\0';    /* Null terminate headers */
            /* Parse headers */
            r->content_length = get_header_int_value("content-length:", r->reply_hdrs, end);
            /*          fprintf(stderr, "CONTENT_LENGTH = %d\n", r->content_length); */
            url = get_header_string_value("X-Request-URI:", r->reply_hdrs, end);
            if (url != NULL && strcmp(r->url, url) != 0)
                fprintf(stderr, "WARNING: %s got reply %s\n", r->url, url);
#if XREQUESTURI || 0
            fprintf(stderr, "LOCATION = %s\n", get_header_string_value("X-Request-URI:", r->reply_hdrs, end));
#endif
        }
        if (!(len == 0 || r->hdr_length > 0)) {
            fprintf(stderr, "ERROR!!!\n");
            assert((len == 0 || r->hdr_length > 0));
        }
        /* Process body */
        if (r->hdr_length != 0) {
            int i;
            int bytes_left, bytes_used;
            if (r->content_length >= 0) {
                bytes_left = r->content_length - r->bytes_read;
                assert(bytes_left >= 0);
                bytes_used = len < bytes_left ? len : bytes_left;
            } else {
                bytes_left = len + 1;   /* Unknown end... */
                bytes_used = len;
            }
            if (opt_checksum) {
                for (i = 0; i < bytes_used; i++)
                    r->sum += (int) buf[i] & 0xFF;
            }
            r->bytes_read += bytes_used;
            len -= bytes_used;
            if (bytes_left == bytes_used) {
                request_done(r);
                Requests = r->next;
                free(r);
                noutstanding--;
                r = Requests;
            } else if (r->content_length > -1) {
                assert(r->bytes_read < r->content_length);
            }
            memmove(buf, buf + bytes_used, len);
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
    if (x < 0) {
        perror("read reply");
        close(fd);
    }
    return x;
}

void
main_loop(void)
{
    static int pconn_fd = -1;
    static char buf[8192];
    struct timeval to;
    struct timeval now, last, start;
    fd_set R;
    struct _r *r;
    struct _r *nextr;
    int x;
    int timeouts;
    int nrequests = 0, rrequests = 0, reqpersec = 0;

    gettimeofday(&start, NULL);
    last = start;

    pconn_fd = open_http_socket();
    if (pconn_fd < 0) {
        perror("socket");
        exit(1);
    }
    while (!done_reading_urls || noutstanding) {
        if (!opt_reopen && pconn_fd < 0) {
            fprintf(stderr, "TERMINATED: Connection closed\n");
            break;
        }
        if (pconn_fd < 0) {
            pconn_fd = open_http_socket();
            if (pconn_fd < 0) {
                perror("socket");
                exit(1);
            }
            nextr = Requests;
            Requests = NULL;
            noutstanding = 0;
            while ((r = nextr) != NULL) {
                nextr = r->next;
                if (send_request(pconn_fd, r->url) != 0) {
                    close(pconn_fd);
                    pconn_fd = -1;
                    nextr = r;
                    for (r = Requests; r != NULL && r->next; r = r->next);
                    if (r != NULL)
                        r->next = nextr;
                    else
                        Requests = nextr;
                    break;
                }
                free(r);
            }
            timeouts = 0;
            if (pconn_fd < 0)
                continue;
        }
        if (timeouts == 200) {
            close(pconn_fd);
            pconn_fd = -1;
            r = Requests;
            Requests = Requests->next;
            fprintf(stderr, "ABORT %s\n", Requests->url);
            free(r);
            noutstanding--;
        }
        if (pconn_fd >= 0 && noutstanding < max_outstanding && !done_reading_urls) {
            char *t;
            if (fgets(buf, 8191, stdin) == NULL) {
                fprintf(stderr, "Done Reading URLS\n");
                done_reading_urls = 1;
                continue;
            }
            rrequests++;
            if ((t = strchr(buf, '\n')))
                *t = '\0';
            if (send_request(pconn_fd, buf) != 0) {
                close(pconn_fd);
                pconn_fd = -1;
                continue;
            }
            nrequests++;
            reqpersec++;
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
        gettimeofday(&now, NULL);
        if (now.tv_sec > last.tv_sec) {
            int dt;
            int nreq;
            last = now;
            dt = (int) (now.tv_sec - start.tv_sec);
            nreq = 0;
            for (r = Requests; r; r = r->next)
                nreq++;
            printf("T+ %6d: %9d req (%+4d), %4d pend, %3d/sec avg, %dmb, %dkb/sec avg\n",
                   dt,
                   nrequests,
                   reqpersec,
                   nreq,
                   (int) (nrequests / dt),
                   (int) total_bytes_read / 1024 / 1024,
                   (int) total_bytes_read / 1024 / dt);
            reqpersec = 0;
        }
    }
}

void
usage(void)
{
    fprintf(stderr, "usage: %s: -p port -h host -n max -t tracefile -i -c -l lifetime\n", progname);
}

int
main(argc, argv)
int argc;
char *argv[];
{
    int c;
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    progname = xstrdup(argv[0]);
    while ((c = getopt(argc, argv, "p:h:n:t:icl:r")) != -1) {
        switch (c) {
        case 'p':
            proxy_port = atoi(optarg);
            break;
        case 'h':
            proxy_addr = xstrdup(optarg);
            break;
        case 'n':
            max_outstanding = atoi(optarg);
            break;
        case 'i':
            opt_ims = 1;
            break;
        case 'c':
            opt_checksum = 1;
            break;
        case 'l':
            lifetime = (time_t) atoi(optarg);
            break;
        case 't':
            trace_fd = open(optarg, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            break;
        case 'r':
            opt_reopen = !opt_reopen;
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

