
#define FD_SETSIZE 1024

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/select.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define PROXY_PORT 3128
#define PROXY_ADDR "127.0.0.1"
#define MAX_FDS 1024
#define READ_BUF_SZ 4096

static int proxy_port = PROXY_PORT;
static char *proxy_addr = PROXY_ADDR;
static char *progname;
static int reqpersec;
static int nrequests;
static int opt_ims = 0;
static int max_connections = 64;

typedef void (CB) (int, void *);

struct _f {
    CB *cb;
    void *data;
};

struct _f FD[MAX_FDS];
int nfds = 0;
int maxfd = 0;


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

void
fd_close(int fd)
{
    close(fd);
    FD[fd].cb = NULL;
    FD[fd].data = NULL;
    nfds--;
    if (fd == maxfd) {
	while (FD[fd].cb == NULL)
	    fd--;
	maxfd = fd;
    }
}

void
fd_open(int fd, CB * cb, void *data)
{
    FD[fd].cb = cb;
    FD[fd].data = data;
    if (fd > maxfd)
	maxfd = fd;
    nfds++;
}

void
sig_intr(int sig)
{
    fd_close(0);
    printf("\rWaiting for open connections to finish...\n");
    signal(sig, SIG_DFL);
}

void
read_reply(int fd, void *data)
{
    static char buf[READ_BUF_SZ];
    if (read(fd, buf, READ_BUF_SZ) <= 0) {
	fd_close(fd);
	reqpersec++;
	nrequests++;
    }
}

int
request(url)
     char *url;
{
    int s;
    char buf[4096];
    int len;
    time_t w;
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
    buf[0] = '\0';
    strcat(buf, "GET ");
    strcat(buf, url);
    strcat(buf, " HTTP/1.0\r\n");
    strcat(buf, "Accept: */*\r\n");
    if (opt_ims && (lrand48() & 0x03) == 0) {
	w = time(NULL) - (lrand48() & 0x3FFFF);
	strcat(buf, "If-Modified-Since: ");
	strcat(buf, mkrfc850(&w));
	strcat(buf, "\r\n");
    }
    strcat(buf, "\r\n");
    len = strlen(buf);
    if (write(s, buf, len) < 0) {
	close(s);
	perror("write");
	return -1;
    }
/*
 * if (fcntl(s, F_SETFL, O_NDELAY) < 0)
 * perror("fcntl O_NDELAY");
 */
    return s;
}

void
read_url(int fd, void *junk)
{
    static char buf[8192];
    char *t;
    int s;
    if (fgets(buf, 8191, stdin) == NULL) {
	printf("Done Reading URLS\n");
	fd_close(0);
	return;
    }
    if ((t = strchr(buf, '\n')))
	*t = '\0';
    s = request(buf);
    if (s < 0) {
	max_connections = nfds - 1;
	printf("NOTE: max_connections set at %d\n", max_connections);
    }
    fd_open(s, read_reply, NULL);
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
    int i;
    int c;
    int dt;
    fd_set R;
    struct timeval start;
    struct timeval now;
    struct timeval last;
    struct timeval to;
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    progname = strdup(argv[0]);
    gettimeofday(&start, NULL);
    last = start;
    while ((c = getopt(argc, argv, "p:h:n:i")) != -1) {
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
	default:
	    usage();
	    return 1;
	}
    }
    fd_open(0, read_url, NULL);
    signal(SIGINT, sig_intr);
    while (nfds) {
	FD_ZERO(&R);
	to.tv_sec = 0;
	to.tv_usec = 100000;
	if (nfds < max_connections && FD[0].cb)
	    FD_SET(0, &R);
	for (i = 1; i <= maxfd; i++) {
	    if (FD[i].cb == NULL)
		continue;
	    FD_SET(i, &R);
	}
	if (select(maxfd + 1, &R, NULL, NULL, &to) < 0) {
	    if (errno != EINTR)
		perror("select");
	    continue;
	}
	for (i = 0; i <= maxfd; i++) {
	    if (!FD_ISSET(i, &R))
		continue;
	    FD[i].cb(i, FD[i].data);
	}
	gettimeofday(&now, NULL);
	if (now.tv_sec > last.tv_sec) {
	    last = now;
	    dt = (int) (now.tv_sec - start.tv_sec);
	    printf("T+ %6d: %9d req (%+4d), %4d conn, %3d/sec avg\n",
		dt,
		nrequests,
		reqpersec,
		nfds,
		(int) (nrequests / dt));
	    reqpersec = 0;
	}
    }
    return 0;
}
