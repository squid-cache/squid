#ifndef __COMM_H__
#define __COMM_H__

#include "StoreIOBuffer.h"

typedef void IOFCB(int fd, StoreIOBuffer recievedData, comm_err_t flag, int xerrno, void *data);
typedef void IOWCB(int fd, char *data, size_t len, comm_err_t flag, int xerrno, void *data);
/* fill sb with up to length data from fd */
extern void comm_fill_immediate(int fd, StoreIOBuffer sb, IOFCB *callback, void *data);

class ConnectionDetail;
typedef void IOACB(int fd, int nfd, ConnectionDetail *details, comm_err_t flag, int xerrno, void *data);
extern void comm_accept(int fd, IOACB *handler, void *handler_data);
extern void comm_add_close_handler(int fd, PF *, void *);
extern void comm_remove_close_handler(int fd, PF *, void *);

extern int comm_has_pending_read_callback(int fd);
extern bool comm_has_pending_read(int fd);
extern void comm_read(int fd, char *buf, int len, IOCB *handler, void *data);
extern void comm_read_cancel(int fd, IOCB *callback, void *data);
extern void fdc_open(int fd, unsigned int type, char *desc);
extern int comm_udp_recvfrom(int fd, void *buf, size_t len, int flags,

                                 struct sockaddr *from, socklen_t *fromlen);
extern int comm_udp_recv(int fd, void *buf, size_t len, int flags);
extern ssize_t comm_udp_send(int s, const void *buf, size_t len, int flags);
extern void comm_accept_setcheckperiod(int fd, int mdelay);

extern void comm_write(int s, const char *buf, size_t len, IOWCB *callback, void *callback_data);
#include "Store.h"
extern void commMarkHalfClosed(int);

/* Where should this belong? */

class CommIO
{

public:
    static inline void NotifyIOCompleted();
    static void ResetNotifications();
    static void Initialise();

private:
    static void NULLFDHandler(int, void *);
    static void FlushPipe();
    static bool Initialised;
    static bool DoneSignalled;
    static int DoneFD;
    static int DoneReadFD;
};

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

/* Inline code. TODO: make structued approach to inlining */
void
CommIO::NotifyIOCompleted()
{
    if (!Initialised)
        Initialise();

    if (!DoneSignalled) {
        DoneSignalled = true;
        write(DoneFD, "!", 1);
    }
};

#endif
