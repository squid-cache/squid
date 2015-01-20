/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/xstrerror.h"

#include <cstring>

#if _SQUID_WINDOWS_
static struct _wsaerrtext {
    int err;
    const char *errconst;
    const char *errdesc;
} _wsaerrtext[] = {

    { WSA_E_CANCELLED, "WSA_E_CANCELLED", "Lookup cancelled." },
    { WSA_E_NO_MORE, "WSA_E_NO_MORE", "No more data available." },
    { WSAEACCES, "WSAEACCES", "Permission denied." },
    { WSAEADDRINUSE, "WSAEADDRINUSE", "Address already in use." },
    { WSAEADDRNOTAVAIL, "WSAEADDRNOTAVAIL", "Cannot assign requested address." },
    { WSAEAFNOSUPPORT, "WSAEAFNOSUPPORT", "Address family not supported by protocol family." },
    { WSAEALREADY, "WSAEALREADY", "Operation already in progress." },
    { WSAEBADF, "WSAEBADF", "Bad file number." },
    { WSAECANCELLED, "WSAECANCELLED", "Operation cancelled." },
    { WSAECONNABORTED, "WSAECONNABORTED", "Software caused connection abort." },
    { WSAECONNREFUSED, "WSAECONNREFUSED", "Connection refused." },
    { WSAECONNRESET, "WSAECONNRESET", "Connection reset by peer." },
    { WSAEDESTADDRREQ, "WSAEDESTADDRREQ", "Destination address required." },
    { WSAEDQUOT, "WSAEDQUOT", "Disk quota exceeded." },
    { WSAEFAULT, "WSAEFAULT", "Bad address." },
    { WSAEHOSTDOWN, "WSAEHOSTDOWN", "Host is down." },
    { WSAEHOSTUNREACH, "WSAEHOSTUNREACH", "No route to host." },
    { WSAEINPROGRESS, "WSAEINPROGRESS", "Operation now in progress." },
    { WSAEINTR, "WSAEINTR", "Interrupted function call." },
    { WSAEINVAL, "WSAEINVAL", "Invalid argument." },
    { WSAEINVALIDPROCTABLE, "WSAEINVALIDPROCTABLE", "Invalid procedure table from service provider." },
    { WSAEINVALIDPROVIDER, "WSAEINVALIDPROVIDER", "Invalid service provider version number." },
    { WSAEISCONN, "WSAEISCONN", "Socket is already connected." },
    { WSAELOOP, "WSAELOOP", "Too many levels of symbolic links." },
    { WSAEMFILE, "WSAEMFILE", "Too many open files." },
    { WSAEMSGSIZE, "WSAEMSGSIZE", "Message too long." },
    { WSAENAMETOOLONG, "WSAENAMETOOLONG", "File name is too long." },
    { WSAENETDOWN, "WSAENETDOWN", "Network is down." },
    { WSAENETRESET, "WSAENETRESET", "Network dropped connection on reset." },
    { WSAENETUNREACH, "WSAENETUNREACH", "Network is unreachable." },
    { WSAENOBUFS, "WSAENOBUFS", "No buffer space available." },
    { WSAENOMORE, "WSAENOMORE", "No more data available." },
    { WSAENOPROTOOPT, "WSAENOPROTOOPT", "Bad protocol option." },
    { WSAENOTCONN, "WSAENOTCONN", "Socket is not connected." },
    { WSAENOTEMPTY, "WSAENOTEMPTY", "Directory is not empty." },
    { WSAENOTSOCK, "WSAENOTSOCK", "Socket operation on nonsocket." },
    { WSAEOPNOTSUPP, "WSAEOPNOTSUPP", "Operation not supported." },
    { WSAEPFNOSUPPORT, "WSAEPFNOSUPPORT", "Protocol family not supported." },
    { WSAEPROCLIM, "WSAEPROCLIM", "Too many processes." },
    { WSAEPROTONOSUPPORT, "WSAEPROTONOSUPPORT", "Protocol not supported." },
    { WSAEPROTOTYPE, "WSAEPROTOTYPE", "Protocol wrong type for socket." },
    { WSAEPROVIDERFAILEDINIT, "WSAEPROVIDERFAILEDINIT", "Unable to initialise a service provider." },
    { WSAEREFUSED, "WSAEREFUSED", "Refused." },
    { WSAEREMOTE, "WSAEREMOTE", "Too many levels of remote in path." },
    { WSAESHUTDOWN, "WSAESHUTDOWN", "Cannot send after socket shutdown." },
    { WSAESOCKTNOSUPPORT, "WSAESOCKTNOSUPPORT", "Socket type not supported." },
    { WSAESTALE, "WSAESTALE", "Stale NFS file handle." },
    { WSAETIMEDOUT, "WSAETIMEDOUT", "Connection timed out." },
    { WSAETOOMANYREFS, "WSAETOOMANYREFS", "Too many references." },
    { WSAEUSERS, "WSAEUSERS", "Too many users." },
    { WSAEWOULDBLOCK, "WSAEWOULDBLOCK", "Resource temporarily unavailable." },
    { WSANOTINITIALISED, "WSANOTINITIALISED", "Successful WSAStartup not yet performed." },
    { WSASERVICE_NOT_FOUND, "WSASERVICE_NOT_FOUND", "Service not found." },
    { WSASYSCALLFAILURE, "WSASYSCALLFAILURE", "System call failure." },
    { WSASYSNOTREADY, "WSASYSNOTREADY", "Network subsystem is unavailable." },
    { WSATYPE_NOT_FOUND, "WSATYPE_NOT_FOUND", "Class type not found." },
    { WSAVERNOTSUPPORTED, "WSAVERNOTSUPPORTED", "Winsock.dll version out of range." },
    { WSAEDISCON, "WSAEDISCON", "Graceful shutdown in progress."    }
};
#endif

const char *
xstrerr(int error)
{
    static char xstrerror_buf[BUFSIZ];

    if (error == 0)
        return "(0) No error.";

#if _SQUID_WINDOWS_
    // Description of WSAGetLastError()
    for (size_t i = 0; i < sizeof(_wsaerrtext) / sizeof(struct _wsaerrtext); ++i) {
        if (_wsaerrtext[i].err == error) {
            // small optimization, save using a temporary buffer and two copies...
            snprintf(xstrerror_buf, BUFSIZ, "(%d) %s, %s", error, _wsaerrtext[i].errconst, _wsaerrtext[i].errdesc);
            return xstrerror_buf;
        }
    }
#endif

    const char *errmsg = strerror(error);

    if (!errmsg || !*errmsg)
        errmsg = "Unknown error";

    snprintf(xstrerror_buf, BUFSIZ, "(%d) %s", error, errmsg);

    return xstrerror_buf;
}

