/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

/*
 * On some systems, FD_SETSIZE is set to something lower than the
 * actual number of files which can be opened.  IRIX is one case,
 * NetBSD is another.  So here we increase FD_SETSIZE to our
 * configure-discovered maximum *before* any system includes.
 */
#define CHANGE_FD_SETSIZE 1

/* Cannot increase FD_SETSIZE on Linux */
#if _SQUID_LINUX_
#undef CHANGE_FD_SETSIZE
#define CHANGE_FD_SETSIZE 0
#endif

/* Cannot increase FD_SETSIZE on FreeBSD before 2.2.0, causes select(2)
 * to return EINVAL. */
/* Marian Durkovic <marian@svf.stuba.sk> */
/* Peter Wemm <peter@spinner.DIALix.COM> */
#if _SQUID_FREEBSD_
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
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
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
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#define READ_BUF_SZ 4096
#define URL_BUF_SZ 4096

struct _thing {
    int rfd;
    int wfd;
    int state;
    pid_t pid;
    char url[URL_BUF_SZ];
    struct _thing *next;
};
typedef struct _thing thing;

static thing *things = NULL;
static fd_set R1;
static int maxfd = 0;
static struct timeval now;
#if DEBUG
static int debug = 1;
#else
static int debug = 0;
#endif

int
tvSubMsec(struct timeval t1, struct timeval t2)
{
    return (t2.tv_sec - t1.tv_sec) * 1000 + (t2.tv_usec - t1.tv_usec) / 1000;
}

static int
get_url(const char *url)
{
    char host[URL_BUF_SZ];
    char path[URL_BUF_SZ];
    char request[URL_BUF_SZ];
    char reply[READ_BUF_SZ];
    char *t;
    int x;
    int s;
    int nr = 0;
    struct hostent *h;
    struct sockaddr_in S;
    unsigned short port = 80;
    assert(!strncmp(url, "http://", 7));
    strncpy(host, url + 7, URL_BUF_SZ);
    if ((t = strchr(host, '/')))
        *t = '\0';
    if ((t = strchr(host, ':'))) {
        *t = '\0';
        port = (unsigned short) atoi(t + 1);
    }
#if 0
    if ((int) port != 80)
        return 0;
#endif
    t = strchr(url + 7, '/');
    strncpy(path, (t ? t : "/"), URL_BUF_SZ);
    memset(&S, '\0', sizeof(S));
    h = gethostbyname(host);
    if (!h)
        return 0;
    memcpy(&S.sin_addr.s_addr, h->h_addr_list[0], sizeof(S.sin_addr.s_addr));
    S.sin_port = htons(port);
    S.sin_family = AF_INET;
    if (debug) {
        char tmp[16];
        fprintf(stderr, "%s (%s) %d %s\n", host, inet_ntop(AF_INET, &S.sin_addr,tmp,sizeof(tmp)), (int) port, path);
    }
    s = socket(PF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return -errno;
    }
    x = connect(s, (struct sockaddr *) &S, sizeof(S));
    if (x < 0) {
        perror(host);
        return -errno;
    }
    snprintf(request, URL_BUF_SZ,
             "GET %s HTTP/1.1\r\n"
             "Accept: */*\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             path,
             host);
    x = write(s, request, strlen(request));
    if (x < 0) {
        perror("write");
        return -errno;
    }
    do {
        x = read(s, reply, READ_BUF_SZ);
        if (x > 0)
            nr += x;
    } while (x > 0);
    close(s);
    return nr;
}

static void
child_main_loop(void)
{
    char buf[URL_BUF_SZ];
    char *t;
    int n;
    struct timeval t1;
    struct timeval t2;
    if (debug)
        fprintf(stderr, "Child PID %d entering child_main_loop\n", (int) getpid());
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    while (fgets(buf, URL_BUF_SZ, stdin)) {
        t = strchr(buf, '\n');
        if (t == NULL)
            continue;
        *t = '\0';
        if (strncmp(buf, "http://", 7))
            continue;
        gettimeofday(&t1, NULL);
        n = get_url(buf);
        gettimeofday(&t2, NULL);
        printf("%d %d\n", n, tvSubMsec(t1, t2));
    }
}

static thing *
create_a_thing(char *argv[])
{
    int p2c[2];
    int c2p[2];
    int prfd, pwfd, crfd, cwfd;
    pid_t pid;
    thing *t;
    if (pipe(p2c) < 0)
        abort();
    if (pipe(c2p) < 0)
        abort();
    prfd = p2c[0];
    cwfd = p2c[1];
    crfd = c2p[0];
    pwfd = c2p[1];
    if ((pid = fork()) < 0)
        abort();
    if (pid > 0) {      /* parent */
        /* close shared socket with child */
        close(crfd);
        close(cwfd);
        t = calloc(1, sizeof(*t));
        t->wfd = pwfd;
        t->rfd = prfd;
        if (pwfd > maxfd)
            maxfd = pwfd;
        if (prfd > maxfd)
            maxfd = prfd;
        t->pid = pid;
        return t;
    }
    /* child */
    close(prfd);
    close(pwfd);
    dup2(crfd, 0);
    dup2(cwfd, 1);
    close(crfd);
    close(cwfd);
    child_main_loop();
    exit(0);
}

static void
create_children(char *argv[])
{
    thing *t;
    thing **T = &things;
    int i;
    for (i = 0; i < 20; i++) {
        t = create_a_thing(argv);
        assert(t);
        if (debug)
            fprintf(stderr, "Thing #%d on FD %d/%d\n",
                    i, t->rfd, t->wfd);
        *T = t;
        T = &t->next;
    }
}

char *
parent_read_url(void)
{
    static char buf[URL_BUF_SZ];
    while (fgets(buf, URL_BUF_SZ, stdin)) {
        if (strncmp(buf, "http://", 7))
            continue;
        return buf;
    }
    return NULL;
}

static thing *
get_idle_thing(void)
{
    thing *t;
    thing *n = things;
    while ((t = n)) {
        n = t->next;
        if (t->state == 0)
            break;
    }
    return t;
}

static void
dispatch(thing * t, char *url)
{
    int x;
    char *s;
    assert(t->state == 0);
    x = write(t->wfd, url, strlen(url));
    if (x < 0)
        perror("write");
    if (debug)
        fprintf(stderr, "dispatched URL to thing PID %d, %d bytes\n", (int) t->pid, x);
    strncpy(t->url, url, URL_BUF_SZ);
    if ((s = strchr(t->url, '\n')))
        *s = '\0';
    t->state = 1;
    FD_SET(t->rfd, &R1);
}

static void
read_reply(thing * t)
{
    char buf[128];
    int i;
    int x;
    int j;
    x = read(t->rfd, buf, 128);
    if (x < 0) {
        perror("read");
    } else if (2 == sscanf(buf, "%d %d", &i, &j)) {
        gettimeofday(&now, NULL);
        printf("%d.%06d %9d %9d %s\n", (int) now.tv_sec, (int) now.tv_usec, i, j, t->url);
    }
    t->state = 0;
    FD_CLR(t->rfd, &R1);
}

static void
parent_main_loop(void)
{
    thing *t;
    char *url;
    fd_set R2;
    int x;
    struct timeval to;
    FD_ZERO(&R1);
    for (;;) {
        while ((t = get_idle_thing()) && (url = parent_read_url()))
            dispatch(t, url);
        R2 = R1;
        to.tv_sec = 60;
        to.tv_usec = 0;
        x = select(maxfd + 1, &R2, NULL, NULL, &to);
        if (x < 0) {
            perror("select");
            continue;
        } else if (x == 0) {
            return;
        }
        for (t = things; t; t = t->next) {
            if (t->state != 1)
                continue;
            if (!FD_ISSET(t->rfd, &R2))
                continue;
            read_reply(t);
        }
    }
}

static void
sig_child(int sig)
{
    int status;
    pid_t pid;
    do {
        pid = waitpid(-1, &status, WNOHANG);
    } while (pid > 0 || (pid < 0 && errno == EINTR));
    signal(sig, sig_child);
}

int
main(int argc, char *argv[])
{
    int i;
    signal(SIGCHLD, sig_child);
    create_children(argv);
    parent_main_loop();
    for (i = 3; i <= maxfd; i++)
        close(i);
    sleep(1);
}

