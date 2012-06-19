#ifndef SQUID_COMPAT_CMSG_H
#define SQUID_COMPAT_CMSG_H

// CMSG_SPACE is not constant on some systems (in particular Max OS X),
// provide a replacement that can be used at build time in that case

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if HAVE_CONSTANT_CMSG_SPACE
#define SQUID_CMSG_SPACE CMSG_SPACE
#else
// add 16 bytes for header and data alignment
#define SQUID_CMSG_SPACE(len) (sizeof(struct cmsghdr) + (len) + 16)
#endif

#endif /* SQUID_COMPAT_CMSG_H */
