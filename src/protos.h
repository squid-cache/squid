/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#ifndef SQUID_PROTOS_H
#define SQUID_PROTOS_H

/* for routines still in this file that take CacheManager parameters */
#include "ip/Address.h"
/* for parameters that still need these */
#include "enums.h"
/* some parameters stil need this */
#include "wordlist.h"
#include "anyp/ProtocolType.h"

class HttpRequestMethod;
#if USE_DELAY_POOLS
class ClientInfo;
#endif

class FwdState;

class HttpRequest;
class HttpReply;


#if SQUID_SNMP
SQUIDCEXTERN PF snmpHandleUdp;
SQUIDCEXTERN void snmpInit(void);
SQUIDCEXTERN void snmpOpenPorts(void);
SQUIDCEXTERN void snmpClosePorts(void);
SQUIDCEXTERN const char * snmpDebugOid(oid * Name, snint Len, MemBuf &outbuf);

SQUIDCEXTERN void addr2oid(Ip::Address &addr, oid *Dest);
SQUIDCEXTERN void oid2addr(oid *Dest, Ip::Address &addr, u_int code);

SQUIDCEXTERN Ip::Address *client_entry(Ip::Address *current);
extern variable_list *snmp_basicFn(variable_list *, snint *);
extern variable_list *snmp_confFn(variable_list *, snint *);
extern variable_list *snmp_sysFn(variable_list *, snint *);
extern variable_list *snmp_prfSysFn(variable_list *, snint *);
extern variable_list *snmp_prfProtoFn(variable_list *, snint *);
extern variable_list *snmp_prfPeerFn(variable_list *, snint *);
extern variable_list *snmp_netIpFn(variable_list *, snint *);
extern variable_list *snmp_netFqdnFn(variable_list *, snint *);
extern variable_list *snmp_netDnsFn(variable_list *, snint *);
extern variable_list *snmp_meshPtblFn(variable_list *, snint *);
extern variable_list *snmp_meshCtblFn(variable_list *, snint *);
#endif /* SQUID_SNMP */

#include "comm/forward.h"

extern void shut_down(int);
extern void rotate_logs(int);
extern void reconfigure(int);

#include "fatal.h"


/*
 * ipc.c
 */
SQUIDCEXTERN pid_t ipcCreate(int type,
                             const char *prog,
                             const char *const args[],
                             const char *name,
                             Ip::Address &local_addr,
                             int *rfd,
                             int *wfd,
                             void **hIpc);

/*
 * prototypes for system functions missing from system includes
 */

#if _SQUID_SOLARIS_

SQUIDCEXTERN int getrusage(int, struct rusage *);
SQUIDCEXTERN int getpagesize(void);
#if !defined(_XPG4_2) && !(defined(__EXTENSIONS__) || \
(!defined(_POSIX_C_SOURCE) && !defined(_XOPEN_SOURCE)))
SQUIDCEXTERN int gethostname(char *, int);
#endif
#endif

/*
 * hack to allow snmp access to the statistics counters
 */
class StatCounters;
        SQUIDCEXTERN StatCounters *snmpStatGet(int);

        /* CygWin & Windows NT Port */
        /* win32.c */
#if _SQUID_WINDOWS_
        SQUIDCEXTERN int WIN32_Subsystem_Init(int *, char ***);
        SQUIDCEXTERN void WIN32_sendSignal(int);
        SQUIDCEXTERN void WIN32_Abort(int);
        SQUIDCEXTERN void WIN32_Exit(void);
        SQUIDCEXTERN void WIN32_SetServiceCommandLine(void);
        SQUIDCEXTERN void WIN32_InstallService(void);
        SQUIDCEXTERN void WIN32_RemoveService(void);
        SQUIDCEXTERN int SquidMain(int, char **);
#endif /* _SQUID_WINDOWS_ */
#if _SQUID_MSWIN_

        SQUIDCEXTERN int WIN32_pipe(int[2]);

            SQUIDCEXTERN int WIN32_getrusage(int, struct rusage *);
    SQUIDCEXTERN void WIN32_ExceptionHandlerInit(void);

    SQUIDCEXTERN int Win32__WSAFDIsSet(int fd, fd_set* set);
    SQUIDCEXTERN DWORD WIN32_IpAddrChangeMonitorInit();

#endif

    extern char *strtokFile(void);

#if USE_AUTH

#if HAVE_AUTH_MODULE_NEGOTIATE && HAVE_KRB5 && HAVE_GSSAPI
    /* upstream proxy authentication */
    SQUIDCEXTERN char *peer_proxy_negotiate_auth(char *principal_name, char *proxy);
#endif

    namespace Auth {
    /* call to ensure the auth component schemes exist. */
    extern void Init(void);
    } // namespace Auth

#endif /* USE_AUTH */

#endif /* SQUID_PROTOS_H */
