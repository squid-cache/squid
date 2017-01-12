/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Announcement Server */

#include "squid.h"

#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define RECV_BUF_SIZE 8192

/*
 * This program must be run from inetd.  First add something like this
 * to /etc/services:
 *
 * cached_announce 3131/udp             # cache announcements
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

static void
sig_handle(int)
{
    fflush(stdout);
    close(2);
    close(1);
    close(0);
    exit(0);
}

int
main(int argc, char *argv[])
{
    char buf[RECV_BUF_SIZE];

    struct sockaddr_in R;
    socklen_t len;

    struct hostent *hp = NULL;
    const char *logfile;
    char ip[4];

    for (len = 0; len < 32; ++len) {
        signal(len, sig_handle);
    }

    if (argc > 1)
        logfile = argv[1];
    else
        logfile = "/tmp/recv-announce.log";

    close(1);

    if (open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0660) < 0) {
        perror(logfile);
        exit(1);
    }

    close(2);
    dup(1);

    IPAddress ipa;
    chat tmp[MAX_HOSTNAMELEN];
    for (;;) {
        memset(buf, '\0', RECV_BUF_SIZE);
        memset(&R, '\0', len = sizeof(R));

        if (recvfrom(0, buf, RECV_BUF_SIZE, 0, (sockaddr *)&R, &len) < 0) {
            perror("recv");
            exit(2);
        }

        memcpy(ip, &R.sin_addr.s_addr, 4);
        hp = gethostbyaddr(ip, 4, AF_INET);
        ipa = R.sin_addr;
        printf("==============================================================================\n");
        printf("Received from %s [%s]\n",
               ipa.toStr(tmp,MAX_HOSTNAMELEN),
               (hp && hp->h_name) ? hp->h_name : "Unknown");
        fputs(buf, stdout);
        fflush(stdout);
    }

    return 0;
}

