/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 *      RADIUS
 *      Remote Authentication Dial In User Service
 *
 *
 *      Livingston Enterprises, Inc.
 *      6920 Koll Center Parkway
 *      Pleasanton, CA   94566
 *
 *      Copyright 1992 Livingston Enterprises, Inc.
 *
 *      Permission to use, copy, modify, and distribute this software for any
 *      purpose and without fee is hereby granted, provided that this
 *      copyright and permission notice appear on all copies and supporting
 *      documentation, the name of Livingston Enterprises, Inc. not be used
 *      in advertising or publicity pertaining to distribution of the
 *      program without specific prior permission, and notice be given
 *      in supporting documentation that copying and distribution is by
 *      permission of Livingston Enterprises, Inc.
 *
 *      Livingston Enterprises, Inc. makes no representations about
 *      the suitability of this software for any purpose.  It is
 *      provided "as is" without express or implied warranty.
 *
 * The new parts of the code is Copyright (C) 1998 R.M. van Selm <selm@cistron.nl>
 * with modifications
 *      Copyright (C) 2004 Henrik Nordstrom <hno@squid-cache.org>
 *      Copyright (C) 2006 Henrik Nordstrom <hno@squid-cache.org>
 */

/* basic_radius_auth is a RADIUS authenticator for Squid-2.5 and later.
 * The authenticator reads a line with a user and password combination.
 * If access is granted OK is returned. Else ERR.
 *
 * basic_radius_auth-1.0 is based on modules from the Cistron-radiusd-1.5.4.
 *
 * Currently you should only start 1 authentificator at a time because the
 * the ID's of the different programs can start to conflict. I'm not sure it
 * would help anyway. I think the RADIUS server is close by and I don't think
 * it will handle requests in parallel anyway (correct me if I'm wrong here)
 *
 * Marc van Selm <selm@cistron.nl>
 * with contributions from
 * Henrik Nordstrom <hno@squid-cache.org>
 * and many others
 */

#include "squid.h"
#include "auth/basic/RADIUS/radius-util.h"
#include "auth/basic/RADIUS/radius.h"
#include "helper/protocol_defines.h"
#include "md5.h"

#include <cctype>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <random>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if _SQUID_WINDOWS_
#include <io.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_GETOPT_H
#include <getopt.h>
#endif

/* AYJ: helper input buffer may be a lot larger than this used to expect... */
#define MAXPWNAM    254
#define MAXPASS     254
#define MAXLINE     254

static void md5_calc(uint8_t out[16], void *in, size_t len);

static int i_send_buffer[2048];
static int i_recv_buffer[2048];
static char *send_buffer = (char *) i_send_buffer;
static char *recv_buffer = (char *) i_recv_buffer;
static int sockfd;
static u_char request_id;
static char vector[AUTH_VECTOR_LEN];
static char secretkey[MAXPASS + 1] = "";
static char server[MAXLINE] = "";
static char identifier[MAXLINE] = "";
static char svc_name[MAXLINE] = "radius";
static int nasport = 111;
static int nasporttype = 0;
static uint32_t nas_ipaddr;
static uint32_t auth_ipaddr;
static int retries = 10;

char progname[] = "basic_radius_auth";

#if _SQUID_WINDOWS_
void
Win32SockCleanup(void)
{
    WSACleanup();
    return;
}
#endif

/*
 *    Diff two timeval, b - a
 */
static int
timeval_diff(const struct timeval *a, const struct timeval *b)
{
    return (b->tv_sec - a->tv_sec) * 1000000 + (b->tv_usec - a->tv_usec);
}

/*
 *    Time since a timeval
 */
static int
time_since(const struct timeval *when)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return timeval_diff(when, &now);
}

/*
 *     MD5 digest
 */
static void
md5_calc(uint8_t out[16], void *in, size_t len)
{
    SquidMD5_CTX ctx;
    SquidMD5Init(&ctx);
    SquidMD5Update(&ctx, in, len);
    SquidMD5Final(out, &ctx);
}

/*
 *    Receive and verify the result.
 */
static int
result_recv(char *buffer, int length)
{
    AUTH_HDR *auth;
    int totallen;
    unsigned char reply_digest[AUTH_VECTOR_LEN];
    unsigned char calc_digest[AUTH_VECTOR_LEN];
    int secretlen;
    /* VALUE_PAIR   *req; */

    auth = (AUTH_HDR *) buffer;
    totallen = ntohs(auth->length);

    if (totallen != length) {
        debug("Received invalid reply length from server (want %d/ got %d)\n", totallen, length);
        return -1;
    }
    if (auth->id != request_id) {
        /* Duplicate response of an earlier query, ignore */
        return -1;
    }
    /* Verify the reply digest */
    memcpy(reply_digest, auth->vector, AUTH_VECTOR_LEN);
    memcpy(auth->vector, vector, AUTH_VECTOR_LEN);
    secretlen = strlen(secretkey);
    memcpy(buffer + length, secretkey, secretlen);
    md5_calc(calc_digest, (unsigned char *) auth, length + secretlen);

    if (memcmp(reply_digest, calc_digest, AUTH_VECTOR_LEN) != 0) {
        debug("WARNING: Received invalid reply digest from server\n");
        return -1;
    }
    if (auth->code != PW_AUTHENTICATION_ACK)
        return 1;

    return 0;
}

/*
 *    Generate a random vector.
 */
static void
random_vector(char *aVector)
{
    static std::mt19937 mt(time(0));
    static xuniform_int_distribution<uint8_t> dist;

    for (int i = 0; i < AUTH_VECTOR_LEN; ++i)
        aVector[i] = static_cast<char>(dist(mt) & 0xFF);
}

/* read the config file
 * The format should be something like:
 * # basic_radius_auth configuration file
 * # MvS: 28-10-1998
 * server suncone.cistron.nl
 * secret testje
 */
static int
rad_auth_config(const char *cfname)
{
    FILE *cf;
    char line[MAXLINE];
    int srv = 0, crt = 0;

    if ((cf = fopen(cfname, "r")) == NULL) {
        perror(cfname);
        return -1;
    }
    while (fgets(line, MAXLINE, cf) != NULL) {
        if (!memcmp(line, "server", 6))
            srv = sscanf(line, "server %s", server);
        if (!memcmp(line, "secret", 6))
            crt = sscanf(line, "secret %s", secretkey);
        if (!memcmp(line, "identifier", 10))
            sscanf(line, "identifier %s", identifier);
        if (!memcmp(line, "service", 7))
            sscanf(line, "service %s", svc_name);
        if (!memcmp(line, "port", 4))
            sscanf(line, "port %s", svc_name);
        if (!memcmp(line, "timeout", 7))
            sscanf(line, "timeout %d", &retries);
    }
    fclose(cf);
    if (srv && crt)
        return 0;
    return -1;
}

static void
urldecode(char *dst, const char *src, int size)
{
    char tmp[3];
    tmp[2] = '\0';
    while (*src && size > 1) {
        if (*src == '%' && src[1] != '\0' && src[2] != '\0') {
            ++src;
            tmp[0] = *src;
            ++src;
            tmp[1] = *src;
            ++src;
            *dst = strtol(tmp, NULL, 16);
            ++dst;
        } else {
            *dst = *src;
            ++dst;
            ++src;
        }
        --size;
    }
    *dst = '\0';
}

static void
authenticate(int socket_fd, const char *username, const char *passwd)
{
    AUTH_HDR *auth;
    unsigned short total_length;
    u_char *ptr;
    int length;
    char passbuf[MAXPASS];
    u_char md5buf[256];
    int secretlen;
    u_char cbc[AUTH_VECTOR_LEN];
    int i, j;
    uint32_t ui;
    struct sockaddr_in saremote;
    fd_set readfds;
    socklen_t salen;
    int retry = retries;

    /*
     *    Build an authentication request
     */
    auth = (AUTH_HDR *) send_buffer;
    auth->code = PW_AUTHENTICATION_REQUEST;
    auth->id = ++request_id;
    random_vector(vector);
    memcpy(auth->vector, vector, AUTH_VECTOR_LEN);
    total_length = AUTH_HDR_LEN;
    ptr = auth->data;

    /*
     *    User Name
     */
    *ptr = PW_USER_NAME;
    ++ptr;
    length = strlen(username);
    if (length > MAXPWNAM) {
        length = MAXPWNAM;
    }
    *ptr = length + 2;
    ptr = (unsigned char*)send_buffer + sizeof(AUTH_HDR);
    memcpy(ptr, username, length);
    ptr += length;
    total_length += length + 2;

    /*
     *    Password
     */
    length = strlen(passwd);
    if (length > MAXPASS) {
        length = MAXPASS;
    }
    memset(passbuf, 0, MAXPASS);
    memcpy(passbuf, passwd, length);

    /*
     * Length is rounded up to multiple of 16,
     * and the password is encoded in blocks of 16
     * with cipher block chaining
     */
    length = ((length / AUTH_VECTOR_LEN) + 1) * AUTH_VECTOR_LEN;

    *ptr = PW_PASSWORD;
    ++ptr;
    *ptr = length + 2;
    ++ptr;

    secretlen = strlen(secretkey);
    /* Set up the Cipher block chain */
    memcpy(cbc, auth->vector, AUTH_VECTOR_LEN);
    for (j = 0; j < length; j += AUTH_VECTOR_LEN) {
        /* Calculate the MD5 Digest */
        strcpy((char *) md5buf, secretkey);
        memcpy(md5buf + secretlen, cbc, AUTH_VECTOR_LEN);
        md5_calc(cbc, md5buf, secretlen + AUTH_VECTOR_LEN);

        /* Xor the password into the MD5 digest */
        for (i = 0; i < AUTH_VECTOR_LEN; ++i) {
            *ptr = (cbc[i] ^= passbuf[j + i]);
            ++ptr;
        }
    }
    total_length += length + 2;

    *ptr = PW_NAS_PORT_ID;
    ++ptr;
    *ptr = 6;
    ++ptr;

    ui = htonl(nasport);
    memcpy(ptr, &ui, 4);
    ptr += 4;
    total_length += 6;

    *ptr = PW_NAS_PORT_TYPE;
    ++ptr;
    *ptr = 6;
    ++ptr;

    ui = htonl(nasporttype);
    memcpy(ptr, &ui, 4);
    ptr += 4;
    total_length += 6;

    if (*identifier) {
        int len = strlen(identifier);
        *ptr = PW_NAS_ID;
        ++ptr;
        *ptr = len + 2;
        ++ptr;
        memcpy(ptr, identifier, len);
        ptr += len;
        total_length += len + 2;
    } else {
        *ptr = PW_NAS_IP_ADDRESS;
        ++ptr;
        *ptr = 6;
        ++ptr;

        ui = htonl(nas_ipaddr);
        memcpy(ptr, &ui, 4);
        ptr += 4;
        total_length += 6;
    }

    /* Klaus Weidner <kw@w-m-p.com> changed this
     * from htonl to htons. It might have caused
     * you trouble or not. That depends on the byte
     * order of your system.
     * The symptom was that the radius server
     * ignored the requests, because they had zero
     * length according to the data header.
     */
    auth->length = htons(total_length);

    while (retry) {
        --retry;
        int time_spent;
        struct timeval sent;
        /*
         *    Send the request we've built.
         */
        gettimeofday(&sent, NULL);
        if (send(socket_fd, (char *) auth, total_length, 0) < 0) {
            int xerrno = errno;
            // EAGAIN is expected at high traffic, just retry
            // TODO: block/sleep a few ms to let the apparently full buffer drain ?
            if (xerrno != EAGAIN && xerrno != EWOULDBLOCK)
                fprintf(stderr,"ERROR: RADIUS send() failure: %s\n", xstrerr(xerrno));
            continue;
        }
        while ((time_spent = time_since(&sent)) < 1000000) {
            struct timeval tv;
            int rc, len;
            if (!time_spent) {
                tv.tv_sec = 1;
                tv.tv_usec = 0;
            } else {
                tv.tv_sec = 0;
                tv.tv_usec = 1000000 - time_spent;
            }
            FD_ZERO(&readfds);
            FD_SET(socket_fd, &readfds);
            if (select(socket_fd + 1, &readfds, NULL, NULL, &tv) == 0)  /* Select timeout */
                break;
            salen = sizeof(saremote);
            len = recvfrom(socket_fd, recv_buffer, sizeof(i_recv_buffer),
                           0, (struct sockaddr *) &saremote, &salen);

            if (len < 0)
                continue;

            rc = result_recv(recv_buffer, len);
            if (rc == 0) {
                SEND_OK("");
                return;
            }
            if (rc == 1) {
                SEND_ERR("");
                return;
            }
        }
    }

    fprintf(stderr, "%s: No response from RADIUS server\n", progname);
    SEND_ERR("No response from RADIUS server");
    return;
}

int
main(int argc, char **argv)
{
    struct sockaddr_in salocal;
    struct sockaddr_in saremote;
    struct servent *svp;
    unsigned short svc_port;
    char username[MAXPWNAM];
    char passwd[MAXPASS];
    char *ptr;
    char buf[HELPER_INPUT_BUFFER];
    const char *cfname = NULL;
    int err = 0;
    socklen_t salen;
    int c;

    while ((c = getopt(argc, argv, "h:p:f:w:i:t:")) != -1) {
        switch (c) {
        case 'd':
            debug_enabled = 1;
            break;
        case 'f':
            cfname = optarg;
            break;
        case 'h':
            strncpy(server, optarg, sizeof(server)-1);
            server[sizeof(server)-1] = '\0';
            break;
        case 'p':
            strncpy(svc_name, optarg, sizeof(svc_name)-1);
            svc_name[sizeof(svc_name)-1] = '\0';
            break;
        case 'w':
            strncpy(secretkey, optarg, sizeof(secretkey)-1);
            secretkey[sizeof(secretkey)-1] = '\0';
            break;
        case 'i':
            strncpy(identifier, optarg, sizeof(identifier)-1);
            identifier[sizeof(identifier)-1] = '\0';
            break;
        case 't':
            retries = atoi(optarg);
            break;
        }
    }
    /* make standard output line buffered */
    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
        return 1;

    if (cfname) {
        if (rad_auth_config(cfname) < 0) {
            fprintf(stderr, "FATAL: %s: can't open configuration file '%s'.\n", argv[0], cfname);
            exit(1);
        }
    }
    if (!*server) {
        fprintf(stderr, "FATAL: %s: Server not specified\n", argv[0]);
        exit(1);
    }
    if (!*secretkey) {
        fprintf(stderr, "FATAL: %s: Shared secret not specified\n", argv[0]);
        exit(1);
    }
#if _SQUID_WINDOWS_
    {
        WSADATA wsaData;
        WSAStartup(2, &wsaData);
        atexit(Win32SockCleanup);
    }
#endif
    /*
     *    Open a connection to the server.
     */
    svp = getservbyname(svc_name, "udp");
    if (svp != NULL)
        svc_port = ntohs((unsigned short) svp->s_port);
    else
        svc_port = atoi(svc_name);
    if (svc_port == 0)
        svc_port = PW_AUTH_UDP_PORT;

    /* Get the IP address of the authentication server */
    if ((auth_ipaddr = get_ipaddr(server)) == 0) {
        fprintf(stderr, "FATAL: %s: Couldn't find host %s\n", argv[0], server);
        exit(1);
    }
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }
    memset(&saremote, 0, sizeof(saremote));
    saremote.sin_family = AF_INET;
    saremote.sin_addr.s_addr = htonl(auth_ipaddr);
    saremote.sin_port = htons(svc_port);

    if (connect(sockfd, (struct sockaddr *) &saremote, sizeof(saremote)) < 0) {
        perror("connect");
        exit(1);
    }
    salen = sizeof(salocal);
    if (getsockname(sockfd, (struct sockaddr *) &salocal, &salen) < 0) {
        perror("getsockname");
        exit(1);
    }
#ifdef O_NONBLOCK
    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK) < 0) {
        int xerrno = errno;
        fprintf(stderr,"%s| ERROR: fcntl() failure: %s\n", argv[0], xstrerr(xerrno));
        exit(1);
    }
#endif
    nas_ipaddr = ntohl(salocal.sin_addr.s_addr);
    while (fgets(buf, HELPER_INPUT_BUFFER, stdin) != NULL) {
        char *end;
        /* protect me form to long lines */
        if ((end = strchr(buf, '\n')) == NULL) {
            err = 1;
            continue;
        }
        if (err) {
            SEND_ERR("");
            err = 0;
            continue;
        }
        if (strlen(buf) > HELPER_INPUT_BUFFER) {
            SEND_ERR("");
            continue;
        }
        /* Strip off the trailing newline */
        *end = '\0';

        /* Parse out the username and password */
        ptr = buf;
        while (isspace(*ptr))
            ++ptr;
        if ((end = strchr(ptr, ' ')) == NULL) {
            SEND_ERR("No password");
            continue;
        }
        *end = '\0';
        urldecode(username, ptr, MAXPWNAM);
        ptr = end + 1;
        while (isspace(*ptr))
            ++ptr;
        urldecode(passwd, ptr, MAXPASS);

        authenticate(sockfd, username, passwd);
    }
    close(sockfd);
    exit(1);
}

