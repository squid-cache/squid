#ifndef __COMM_H__
#define __COMM_H__

#include "squid.h"
#include "AsyncEngine.h"
#include "CompletionDispatcher.h"
#include "StoreIOBuffer.h"
#include "Array.h"

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
} comm_err_t;
typedef void IOFCB(int fd, StoreIOBuffer receivedData, comm_err_t flag, int xerrno, void *data);
typedef void IOWCB(int fd, char *buffer, size_t len, comm_err_t flag, int xerrno, void *data);

typedef void CWCB(int fd, char *, size_t size, comm_err_t flag, void *data);
typedef void CNCB(int fd, comm_err_t status, int xerrno, void *data);

typedef void IOCB(int fd, char *, size_t size, comm_err_t flag, int xerrno, void *data);

/* comm.c */
extern void comm_calliocallback(void);
extern bool comm_iocallbackpending(void); /* inline candidate */

extern int comm_listen(int fd);
SQUIDCEXTERN int commSetNonBlocking(int fd);
SQUIDCEXTERN int commUnsetNonBlocking(int fd);
SQUIDCEXTERN void commSetCloseOnExec(int fd);
extern void _comm_close(int fd, char const *file, int line);
#define comm_close(fd) (_comm_close((fd), __FILE__, __LINE__))
SQUIDCEXTERN void comm_reset_close(int fd);
#if LINGERING_CLOSE
SQUIDCEXTERN void comm_lingering_close(int fd);
#endif
SQUIDCEXTERN void commConnectStart(int fd, const char *, u_short, CNCB *, void *);

SQUIDCEXTERN int comm_connect_addr(int sock, const struct sockaddr_in *);
SQUIDCEXTERN void comm_init(void);

SQUIDCEXTERN int comm_open(int, int, struct IN_ADDR, u_short port, int, const char *note);

SQUIDCEXTERN int comm_openex(int, int, struct IN_ADDR, u_short, int, unsigned char TOS, const char *);
SQUIDCEXTERN u_short comm_local_port(int fd);
SQUIDCEXTERN int comm_set_tos(int fd, int tos);

SQUIDCEXTERN void commSetSelect(int, unsigned int, PF *, void *, time_t);

SQUIDCEXTERN int comm_udp_sendto(int, const struct sockaddr_in *, int, const void *, int);
extern void comm_write(int fd, const char *buf, int len, IOCB *callback, void *callback_data, FREE *func);
SQUIDCEXTERN void comm_write_mbuf(int fd, MemBuf *mb, IOCB * handler, void *handler_data);
SQUIDCEXTERN void commCallCloseHandlers(int fd);
SQUIDCEXTERN int commSetTimeout(int fd, int, PF *, void *);
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
extern void comm_add_close_handler(int fd, PF *, void *);
extern void comm_remove_close_handler(int fd, PF *, void *);

extern int comm_has_pending_read_callback(int fd);
extern bool comm_has_pending_read(int fd);
extern void comm_read(int fd, char *buf, int len, IOCB *handler, void *data);
extern void comm_read_cancel(int fd, IOCB *callback, void *data);
extern void fdc_open(int fd, unsigned int type, char const *desc);
extern int comm_udp_recvfrom(int fd, void *buf, size_t len, int flags,

                                 struct sockaddr *from, socklen_t *fromlen);
extern int comm_udp_recv(int fd, void *buf, size_t len, int flags);
extern ssize_t comm_udp_send(int s, const void *buf, size_t len, int flags);
extern void commMarkHalfClosed(int);
extern int commIsHalfClosed(int);
extern void commCheckHalfClosed(void *);
extern bool comm_has_incomplete_write(int);

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

/* App layer doesn't want any more data from the socket, as the read channel is
 * closed, but we need to detect aborts, so this lets us do so.
 */

class AbortChecker
{

public:
    static AbortChecker &Instance();
    /* the current method of checking, is via a 0 length read every second.
     * if nothing is returned by the next IO loop, we let it be.
     * If an error occurs, we close the conn.
     * Note that some tcp environments may allow direct polling for the socket status
     * and this could be adjusted to use that method for the test. (in which case
     * the singleton should be refactored to have the tcp engine register the
     * instance with it).
     */
    static IOCB AbortCheckReader;
    void monitor (int);
    void stopMonitoring (int);
    void doIOLoop();

private:
    static AbortChecker Instance_;
    static void AddCheck (int const &, void *);
    static int IntCompare (int const &, int const &);
    static void RemoveCheck (int const &, void *);
    AbortChecker() : fds (NULL), checking (false), lastCheck (0){}

    mutable SplayNode<int> *fds;
    bool checking;
    time_t lastCheck;
    bool contains (int const) const;

    void remove
        (int const);

    void add
        (int const);

    void addCheck (int const);

    void removeCheck (int const);
};

/* a dispatcher for comms events */

class CommDispatcher : public CompletionDispatcher
{

public:
    virtual bool dispatch();
};

/* A comm engine that calls comm_select */

class CommSelectEngine : public AsyncEngine
{

public:
    virtual int checkEvents(int timeout);
};

#endif
