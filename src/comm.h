#ifndef __COMM_H__
#define __COMM_H__

#include "squid.h"
#include "AsyncEngine.h"
#include "base/AsyncCall.h"
#include "StoreIOBuffer.h"
#include "Array.h"
#include "ip/IpAddress.h"

#define COMMIO_FD_READCB(fd)    (&commfd_table[(fd)].readcb)
#define COMMIO_FD_WRITECB(fd)   (&commfd_table[(fd)].writecb)

typedef enum {
    COMM_OK = 0,
    COMM_ERROR = -1,
    COMM_NOMESSAGE = -3,
    COMM_TIMEOUT = -4,
    COMM_SHUTDOWN = -5,
    COMM_IDLE = -6, /* there are no active fds and no pending callbacks. */
    COMM_INPROGRESS = -7,
    COMM_ERR_CONNECT = -8,
    COMM_ERR_DNS = -9,
    COMM_ERR_CLOSING = -10,
#if USE_IPV6
    COMM_ERR_PROTOCOL = -11, /* IPv4 or IPv6 cannot be used on the fd socket */
#endif
    COMM_ERR__END__ = -999999 /* Dummy entry to make syntax valid (comma on line above), do not use. New entries added above */
} comm_err_t;

class DnsLookupDetails;
typedef void CNCB(int fd, const DnsLookupDetails &dns, comm_err_t status, int xerrno, void *data);

typedef void IOCB(int fd, char *, size_t size, comm_err_t flag, int xerrno, void *data);


/* comm.c */
extern bool comm_iocallbackpending(void); /* inline candidate */

extern int comm_listen(int fd);
SQUIDCEXTERN int commSetNonBlocking(int fd);
SQUIDCEXTERN int commUnsetNonBlocking(int fd);
SQUIDCEXTERN void commSetCloseOnExec(int fd);
SQUIDCEXTERN void commSetTcpKeepalive(int fd, int idle, int interval, int timeout);
extern void _comm_close(int fd, char const *file, int line);
#define comm_close(fd) (_comm_close((fd), __FILE__, __LINE__))
SQUIDCEXTERN void comm_reset_close(int fd);
#if LINGERING_CLOSE
SQUIDCEXTERN void comm_lingering_close(int fd);
#endif
SQUIDCEXTERN void commConnectStart(int fd, const char *, u_short, CNCB *, void *);
void commConnectStart(int fd, const char *, u_short, AsyncCall::Pointer &cb);

SQUIDCEXTERN int comm_connect_addr(int sock, const IpAddress &addr);
SQUIDCEXTERN void comm_init(void);
SQUIDCEXTERN void comm_exit(void);

SQUIDCEXTERN int comm_open(int, int, IpAddress &, int, const char *note);

/**
 * Open a port specially bound for listening or sending through a specific port.
 * This is a wrapper providing IPv4/IPv6 failover around comm_openex().
 * Please use for all listening sockets and bind() outbound sockets.
 *
 * It will open a socket bound for:
 *  - IPv4 if IPv6 is disabled or address is IPv4-native.
 *  - IPv6 if address is IPv6-native
 *  - IPv6 dual-stack mode if able to open [::]
 *
 * When an open performs failover it update the given address to feedback
 * the new IPv4-only status of the socket. Further displays of the IP
 * (in debugs or cachemgr) will occur in Native IPv4 format.
 * A reconfigure is needed to reset the stored IP in most cases and attempt a port re-open.
 */
SQUIDCEXTERN int comm_open_listener(int sock_type, int proto, IpAddress &addr, int flags, const char *note);

SQUIDCEXTERN int comm_openex(int, int, IpAddress &, int, unsigned char TOS, const char *);
SQUIDCEXTERN u_short comm_local_port(int fd);
SQUIDCEXTERN int comm_set_tos(int fd, int tos);

SQUIDCEXTERN void commSetSelect(int, unsigned int, PF *, void *, time_t);
SQUIDCEXTERN void commResetSelect(int);

SQUIDCEXTERN int comm_udp_sendto(int sock, const IpAddress &to, const void *buf, int buflen);
extern void comm_write(int fd, const char *buf, int len, IOCB *callback, void *callback_data, FREE *func);
extern void comm_write(int fd, const char *buf, int size, AsyncCall::Pointer &callback, FREE * free_func = NULL);
SQUIDCEXTERN void comm_write_mbuf(int fd, MemBuf *mb, IOCB * handler, void *handler_data);
extern void comm_write_mbuf(int fd, MemBuf *mb, AsyncCall::Pointer &callback);
SQUIDCEXTERN void commCallCloseHandlers(int fd);
SQUIDCEXTERN int commSetTimeout(int fd, int, PF *, void *);
extern int commSetTimeout(int fd, int, AsyncCall::Pointer &calback);
SQUIDCEXTERN int ignoreErrno(int);
SQUIDCEXTERN void commCloseAllSockets(void);
SQUIDCEXTERN void checkTimeouts(void);


/*
 * comm_select.c
 */
SQUIDCEXTERN void comm_select_init(void);
SQUIDCEXTERN comm_err_t comm_select(int);
SQUIDCEXTERN void comm_quick_poll_required(void);

class ConnectionDetail;
typedef void IOACB(int fd, int nfd, ConnectionDetail *details, comm_err_t flag, int xerrno, void *data);
extern void comm_accept(int fd, IOACB *handler, void *handler_data);
extern void comm_accept(int fd, AsyncCall::Pointer &call);
extern void comm_add_close_handler(int fd, PF *, void *);
extern void comm_add_close_handler(int fd, AsyncCall::Pointer &);
extern void comm_remove_close_handler(int fd, PF *, void *);
extern void comm_remove_close_handler(int fd, AsyncCall::Pointer &);


extern int comm_has_pending_read_callback(int fd);
extern bool comm_monitors_read(int fd);
extern void comm_read(int fd, char *buf, int len, IOCB *handler, void *data);
extern void comm_read(int fd, char *buf, int len, AsyncCall::Pointer &callback);
extern void comm_read_cancel(int fd, IOCB *callback, void *data);
extern void comm_read_cancel(int fd, AsyncCall::Pointer &callback);
extern int comm_udp_recvfrom(int fd, void *buf, size_t len, int flags, IpAddress &from);
extern int comm_udp_recv(int fd, void *buf, size_t len, int flags);
extern ssize_t comm_udp_send(int s, const void *buf, size_t len, int flags);
extern bool comm_has_incomplete_write(int);

/** The read channel has closed and the caller does not expect more data
 * but needs to detect connection aborts. The current detection method uses
 * 0-length reads: We read until the error occurs or the writer closes
 * the connection. If there is a read error, we close the connection.
 */
extern void commStartHalfClosedMonitor(int fd);
extern bool commHasHalfClosedMonitor(int fd);
// XXX: remove these wrappers which minimize client_side.cc changes in a commit
inline void commMarkHalfClosed(int fd) { commStartHalfClosedMonitor(fd); }
inline bool commIsHalfClosed(int fd) { return commHasHalfClosedMonitor(fd); }

/* Not sure where these should live yet */

class Acceptor
{

public:
    typedef void AcceptorFunction (int, int, ConnectionDetail *, comm_err_t, int, void *);
    AcceptorFunction *theFunction;
    int acceptFD;
    void *theData;
};

class AcceptLimiter
{

public:
    static AcceptLimiter &Instance();
    void defer (int, Acceptor::AcceptorFunction *, void *);
    void kick();

    bool deferring() const;

private:
    static AcceptLimiter Instance_;
    Vector<Acceptor> deferred;
};

/* A comm engine that calls comm_select */

class CommSelectEngine : public AsyncEngine
{

public:
    virtual int checkEvents(int timeout);
};

#endif
