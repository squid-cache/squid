#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define RECV_BUF_SIZE 8192

/*
 * This program must be run from inetd.  First add something like this
 * to /etc/services:
 * 
 * cached_announce 3131/udp             # harvest cached announcements
 * 
 * And then add something like this to /etc/inetd/conf:
 * 
 * cached_announce dgram udp       wait cached /tmp/recv-announce recv-announce /tmp/recv-announce.log
 * 
 * 
 * A single instance of this process will continue to handle incoming
 * requests.  If it dies, or is killed, inetd should restart it when the
 * next message arrives.
 * 
 */

/* 
 * usage: recv-announce logfile
 */

void sig_handle()
{
    fflush(stdout);
    close(2);
    close(1);
    close(0);
    exit(0);
}


int main(argc, argv)
     int argc;
     char *argv[];
{
    char buf[RECV_BUF_SIZE];
    struct sockaddr_in R;
    int len;
    struct hostent *hp = NULL;
    char logfile[BUFSIZ];
    char *t = NULL;
    char ip[4];

    for (len = 0; len < 32; len++) {
	signal(len, sig_handle);
    }


    if (argc > 1)
	strcpy(logfile, argv[1]);
    else
	strcpy(logfile, "/tmp/recv-announce.log");

    close(1);
    if (open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0660) < 0) {
	perror(logfile);
	exit(1);
    }
    close(2);
    dup(1);


    while (1) {
	memset(buf, '\0', RECV_BUF_SIZE);
	memset(&R, '\0', len = sizeof(R));

	if (recvfrom(0, buf, RECV_BUF_SIZE, 0, &R, &len) < 0) {
	    perror("recv");
	    exit(2);
	}
	memcpy(ip, &R.sin_addr.s_addr, 4);
	hp = gethostbyaddr(ip, 4, AF_INET);
	printf("==============================================================================\n");
	printf("Received from %s [%s]\n",
	    inet_ntoa(R.sin_addr),
	    (hp && hp->h_name) ? hp->h_name : "Unknown");
	fputs(buf, stdout);
	fflush(stdout);
    }
}
