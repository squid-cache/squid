
/* $Id: client.cc,v 1.6 1996/05/03 22:56:22 wessels Exp $ */

#include "squid.h"

#ifndef BUFSIZ
#define BUFSIZ 8192
#endif

/* Local functions */
static int client_comm_connect();
static void usage();

static void usage(progname)
     char *progname;
{
    fprintf(stderr, "\
Usage: %s [-rs] [-h host] [-p port] url\n\
Options:\n\
    -r         Force cache to reload URL.\n\
    -s         Silent.  Do not print data to stdout.\n\
    -h host    Retrieve URL from cache on hostname.  Default is localhost.\n\
    -p port    Port number of cache.  Default is %d.\n\
    -m method  Request method, default is GET\n\
", progname, CACHE_HTTP_PORT);
    exit(1);
}

int main(argc, argv)
     int argc;
     char *argv[];
{
    int conn, c, len, bytesWritten;
    int port, to_stdout, reload;
    char url[BUFSIZ], msg[BUFSIZ], buf[BUFSIZ], hostname[BUFSIZ];
    char *method = "GET";
    extern char *optarg;
    time_t ims = 0;

    /* set the defaults */
    strcpy(hostname, "localhost");
    port = CACHE_HTTP_PORT;
    to_stdout = 1;
    reload = 0;

    if (argc < 2) {
	usage(argv[0]);		/* need URL */
    } else if (argc >= 2) {
	strcpy(url, argv[argc - 1]);
	if (url[0] == '-')
	    usage(argv[0]);
	while ((c = getopt(argc, argv, "fsrnp:c:h:i:m:?")) != -1)
	    switch (c) {
	    case 'h':		/* host:arg */
	    case 'c':		/* backward compat */
		if (optarg != NULL)
		    strcpy(hostname, optarg);
		break;
	    case 's':		/* silent */
	    case 'n':		/* backward compat */
		to_stdout = 0;
		break;
	    case 'r':		/* reload */
		reload = 1;
		break;
	    case 'p':		/* port number */
		sscanf(optarg, "%d", &port);
		if (port < 1)
		    port = CACHE_HTTP_PORT;	/* default */
		break;
	    case 'i':		/* IMS */
		ims = (time_t) atoi(optarg);
		break;
	    case 'm':
		method = xstrdup(optarg);
		break;
	    case '?':		/* usage */
	    default:
		usage(argv[0]);
		break;
	    }
    }
    /* Connect to the server */
    if ((conn = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	perror("client: socket");
	exit(1);
    }
    if (client_comm_connect(conn, hostname, port) < 0) {
	if (errno == 0) {
	    fprintf(stderr, "client: ERROR: Cannot connect to %s:%d: Host unknown.\n", hostname, port);
	} else {
	    char tbuf[BUFSIZ];
	    sprintf(tbuf, "client: ERROR: Cannot connect to %s:%d",
		hostname, port);
	    perror(tbuf);
	}
	exit(1);
    }
    /* Build the HTTP request */
    sprintf(msg, "%s %s HTTP/1.0\r\n", method, url);
    if (reload) {
	sprintf(buf, "Pragma: no-cache\r\n");
	strcat(msg, buf);
    }
    sprintf(buf, "Accept: */*\r\n");
    strcat(msg, buf);
    if (ims) {
	sprintf(buf, "If-Modified-Since: %s\r\n", mkrfc850(&ims));
	strcat(msg, buf);
    }
    sprintf(buf, "\r\n");
    strcat(msg, buf);

    /* Send the HTTP request */
    bytesWritten = write(conn, msg, strlen(msg));
    if (bytesWritten < 0) {
	perror("client: ERROR: write");
	exit(1);
    } else if (bytesWritten != strlen(msg)) {
	fprintf(stderr, "client: ERROR: Cannot send request?: %s\n", msg);
	exit(1);
    }
    /* Read the data */
    while ((len = read(conn, buf, sizeof(buf))) > 0) {
	if (to_stdout)
	    fwrite(buf, len, 1, stdout);
    }
    (void) close(conn);		/* done with socket */
    exit(0);
    /*NOTREACHED */
    return 0;
}

static int client_comm_connect(sock, dest_host, dest_port)
     int sock;			/* Type of communication to use. */
     char *dest_host;		/* Server's host name. */
     int dest_port;		/* Server's port. */
{
    struct hostent *hp;
    static struct sockaddr_in to_addr;

    /* Set up the destination socket address for message to send to. */
    to_addr.sin_family = AF_INET;

    if ((hp = gethostbyname(dest_host)) == 0) {
	return (-1);
    }
    memcpy(&to_addr.sin_addr, hp->h_addr, hp->h_length);
    to_addr.sin_port = htons(dest_port);
    return connect(sock, (struct sockaddr *) &to_addr, sizeof(struct sockaddr_in));
}
