/* $Id: dnsserver.cc,v 1.5 1996/04/16 05:05:20 wessels Exp $ */

#include "squid.h"

extern int h_errno;

int do_debug = 0;

/* error messages from gethostbyname() */
#define my_h_msgs(x) (\
	((x) == HOST_NOT_FOUND) ? \
		"Host not found (authoritative)" : \
	((x) == TRY_AGAIN) ? \
		"Host not found (non-authoritative)" : \
	((x) == NO_RECOVERY) ? \
		"Non recoverable errors" : \
	((x) == NO_DATA) ? \
		"Valid name, no data record of requested type" : \
	((x) == NO_ADDRESS) ? \
		"No address, look for MX record" : \
		"Unknown DNS problem")

/* 
 * Modified to use UNIX domain sockets between squid and the dnsservers to
 * save an FD per DNS server, Hong Mei, USC.
 * 
 * Before forking a dnsserver, squid creates listens on a UNIX domain
 * socket.  After the fork(), squid closes its end of the rendevouz socket
 * but then immediately connects to it to establish the connection to the
 * dnsserver process.  We use AF_UNIX to prevent other folks from
 * connecting to our little dnsservers after we fork but before we connect
 * to them.
 * 
 * Squid creates UNIX domain sockets named dns.PID.NN, e.g. dns.19215.11
 * 
 * In ipcache_init():
 *       . dnssocket = ipcache_opensocket(getDnsProgram())
 *       . dns_child_table[i]->inpipe = dnssocket
 *       . dns_child_table[i]->outpipe = dnssocket
 * 
 * The dnsserver inherits socket(socket_from_ipcache) from squid which it
 * uses to rendevouz with.  The child takes responsibility for cleaning up
 * the UNIX domain pathnames by setting a few signal handlers.
 * 
 */

int main(argc, argv)
     int argc;
     char *argv[];
{
    char request[256];
    char msg[256];
    struct hostent *result = NULL;
    FILE *logfile = NULL;
    long start;
    long stop;
    char *t = NULL;
    char buf[256];
    int socket_from_cache, fd;
    int a1, a2, a3, a4;
    int addr_count = 0;
    int alias_count = 0;
    int i;
    char *dnsServerPathname = NULL;
    int c;
    extern char *optarg;

    while ((c = getopt(argc, argv, "vhdp:")) != -1)
	switch (c) {
	case 'v':
	case 'h':
	    printf("dnsserver version %s\n", SQUID_VERSION);
	    exit(0);
	    break;
	case 'd':
	    sprintf(buf, "dnsserver.%d.log", (int) getpid());
	    logfile = fopen(buf, "a");
	    do_debug++;
	    if (!logfile)
		fprintf(stderr, "Could not open dnsserver's log file\n");
	    break;
	case 'p':
	    dnsServerPathname = xstrdup(optarg);
	    break;
	default:
	    fprintf(stderr, "usage: dnsserver -h -d -p socket-filename\n");
	    exit(1);
	    break;
	}

    socket_from_cache = 3;

    /* accept DNS look up from ipcache */
    if (dnsServerPathname) {
	fd = accept(socket_from_cache, (struct sockaddr *) 0, (int *) 0);
	unlink(dnsServerPathname);
	if (fd < 0) {
	    fprintf(stderr, "dnsserver: accept: %s\n", xstrerror());
	    exit(1);
	}
	close(socket_from_cache);

	/* point stdout to fd */
	dup2(fd, 1);
	dup2(fd, 0);
	close(fd);
    }
    while (1) {
	memset(request, '\0', 256);

	/* read from ipcache */
	if (fgets(request, 255, stdin) == (char *) NULL)
	    exit(1);
	if ((t = strrchr(request, '\n')) != NULL)
	    *t = '\0';		/* strip NL */
	if ((t = strrchr(request, '\r')) != NULL)
	    *t = '\0';		/* strip CR */
	if (strcmp(request, "$shutdown") == 0) {
	    exit(0);
	}
	if (strcmp(request, "$hello") == 0) {
	    printf("$alive\n");
	    printf("$end\n");
	    fflush(stdout);
	    continue;
	}
	/* check if it's already an IP address in text form. */
	if (sscanf(request, "%d.%d.%d.%d", &a1, &a2, &a3, &a4) == 4) {
	    printf("$name %s\n", request);
	    printf("$h_name %s\n", request);
	    printf("$h_len %d\n", 4);
	    printf("$ipcount %d\n", 1);
	    printf("%s\n", request);
	    printf("$aliascount %d\n", 0);
	    printf("$end\n");
	    fflush(stdout);
	    continue;
	}
	start = time(NULL);
	result = gethostbyname(request);
	if (!result) {
	    if (h_errno == TRY_AGAIN) {
		sleep(2);
		result = gethostbyname(request);	/* try a little harder */
	    }
	}
	stop = time(NULL);

	msg[0] = '\0';
	if (!result) {
	    if (h_errno == TRY_AGAIN) {
		sprintf(msg, "Name Server for domain '%s' is unavailable.",
		    request);
	    } else {
		sprintf(msg, "DNS Domain '%s' is invalid: %s.\n",
		    request, my_h_msgs(h_errno));
	    }
	}
	if (!result || (strlen(result->h_name) == 0)) {
	    if (logfile) {
		fprintf(logfile, "%s %d\n", request, (int) (stop - start));
		fflush(logfile);
	    }
	    printf("$fail %s\n", request);
	    printf("$message %s\n", msg[0] ? msg : "Unknown Error");
	    printf("$end\n");
	    fflush(stdout);
	    continue;
	} else {

	    printf("$name %s\n", request);
	    printf("$h_name %s\n", result->h_name);
	    printf("$h_len %d\n", result->h_length);

	    addr_count = alias_count = 0;
	    while (result->h_addr_list[addr_count] && addr_count < 255)
		++addr_count;
	    printf("$ipcount %d\n", addr_count);
	    for (i = 0; i < addr_count; i++) {
		struct in_addr addr;
		memcpy((char *) &addr, result->h_addr_list[i], result->h_length);
		printf("%s\n", inet_ntoa(addr));
	    }

#ifdef SEND_ALIASES
	    while ((alias_count < 255) && result->h_aliases[alias_count])
		++alias_count;
#endif
	    printf("$aliascount %d\n", alias_count);
	    for (i = 0; i < alias_count; i++) {
		printf("%s\n", result->h_aliases[i]);
	    }

	    printf("$end\n");
	    fflush(stdout);
	    continue;
	}
    }

    exit(0);
    /*NOTREACHED */
}
