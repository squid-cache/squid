/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_CMSG_H
#define SQUID_COMPAT_CMSG_H

/*
 * Compatibility-layer for CMSG_
 */

// cmsg.h is found through sys/socket.h
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

// mswsock.h defines WSA_CMSG definitions
#if HAVE_MSWSOCK_H
#include <mswsock.h>
#endif
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

// sockaddr_un might be in sys/un.h if not pulled in already
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#if !HAVE_CMSGHDR
struct cmsghdr {
    unsigned int cmsg_len;
    int cmsg_level;
    int cmsg_type;
    unsigned char cmsg_data[16]; /* dummy */
    /* followed by UCHAR cmsg_data[]; */
};
#endif

/* lifted off https://metacpan.org/source/SAMPO/Socket-PassAccessRights-0.03/passfd.c */
// check for WSA_CMSG first because Windows defines CMSG_DATA for other uses
#if defined(WSA_CMSG_DATA)
# define SQUID_CMSG_DATA(cmsg) WSA_CMSG_DATA(cmsg)
#elif defined(CMSG_DATA)
# define SQUID_CMSG_DATA(cmsg) CMSG_DATA(cmsg)
#else
# define SQUID_CMSG_DATA(cmsg) ((cmsg)->cmsg_data)
#endif

#ifndef CMSG_NXTHDR
# define CMSG_NXTHDR(mhdr, X) __cmsg_nxthdr (mhdr, X)
#endif

#ifndef CMSG_FIRSTHDR
# define CMSG_FIRSTHDR(mhdr) \
  ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr)        \
   ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) NULL)
#endif

#ifndef CMSG_ALIGN
# define CMSG_ALIGN(len) (((len) + sizeof (size_t) - 1) \
             & ~(sizeof (size_t) - 1))
#endif

#ifndef CMSG_SPACE
# define CMSG_SPACE(len) (CMSG_ALIGN (len) \
             + CMSG_ALIGN (sizeof (struct cmsghdr)))
#undef HAVE_CONSTANT_CMSG_SPACE
#define HAVE_CONSTANT_CMSG_SPACE 1
#endif

#ifndef CMSG_LEN
# define CMSG_LEN(len)   (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len))
#endif

#if !HAVE_IOVEC
struct iovec {
    void *iov_base;
    size_t iov_len;
};
#endif

#if !HAVE_MSGHDR
struct msghdr {
    void *msg_name;             /* Address to send to/receive from.  */
    socklen_t msg_namelen;      /* Length of address data.  */

    struct iovec *msg_iov;      /* Vector of data to send/receive into.  */
    size_t msg_iovlen;          /* Number of elements in the vector.  */

    void *msg_control;          /* Ancillary data (eg BSD filedesc passing). */
    size_t msg_controllen;      /* Ancillary data buffer length.
                                   !! The type should be socklen_t but the
                                   definition of the kernel is incompatible
                                   with this.  */

    int msg_flags;              /* Flags on received message.  */
};
#endif

#if !HAVE_SOCKADDR_UN
struct sockaddr_un {
    char sun_family;
    char sun_path[256];   /* pathname */
};
#endif

#ifndef SUN_LEN
# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)        \
        + strlen ((ptr)->sun_path))
#endif

#ifndef SCM_RIGHTS
#define SCM_RIGHTS 1
#endif
#ifndef SCM_CREDENTIALS
#define SCM_CREDENTIALS 2
#endif
#ifndef SCM_SECURITY
#define SCM_SECURITY 3
#endif

#ifndef AF_LOCAL
#define AF_LOCAL 1
#endif

// CMSG_SPACE is not constant on some systems (in particular Max OS X),
// provide a replacement that can be used at build time in that case
// NP: this must go below our replacement definitions.

#if HAVE_CONSTANT_CMSG_SPACE
#define SQUID_CMSG_SPACE CMSG_SPACE
#else
// add 16 bytes for header and data alignment
#define SQUID_CMSG_SPACE(len) (sizeof(struct cmsghdr) + (len) + 16)
#endif

#endif /* SQUID_COMPAT_CMSG_H */

