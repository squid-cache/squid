/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FDE_H
#define SQUID_FDE_H

#include "comm.h"
#include "defines.h"
#include "ip/Address.h"
#include "ip/forward.h"
#include "security/forward.h"
#include "typedefs.h" //DRCB, DWCB

#if USE_DELAY_POOLS
class ClientInfo;
#endif

/**
 * READ_HANDLER functions return < 0 if, and only if, they fail with an error.
 * On error, they must pass back an error code in 'errno'.
 */
typedef int READ_HANDLER(int, char *, int);

/**
 * WRITE_HANDLER functions return < 0 if, and only if, they fail with an error.
 * On error, they must pass back an error code in 'errno'.
 */
typedef int WRITE_HANDLER(int, const char *, int);

class dwrite_q;
class _fde_disk
{
public:
    DWCB *wrt_handle;
    void *wrt_handle_data;
    dwrite_q *write_q;
    dwrite_q *write_q_tail;
    off_t offset;
    _fde_disk() { memset(this, 0, sizeof(_fde_disk)); }
};

class fde
{

public:
    fde() { clear(); };

    /// True if comm_close for this fd has been called
    bool closing() { return flags.close_request; }

    /* NOTE: memset is used on fdes today. 20030715 RBC */
    static void DumpStats (StoreEntry *);

    char const *remoteAddr() const;
    void dumpStats (StoreEntry &, int);
    bool readPending(int);
    void noteUse();

public:

    /// global table of FD and their state.
    static fde* Table;

    unsigned int type;
    unsigned short remote_port;

    Ip::Address local_addr;
    tos_t tosToServer;          /**< The TOS value for packets going towards the server.
                                        See also tosFromServer. */
    nfmark_t nfmarkToServer;    /**< The netfilter mark for packets going towards the server.
                                        See also nfmarkFromServer. */
    int sock_family;
    char ipaddr[MAX_IPSTRLEN];            /* dotted decimal address of peer */
    char desc[FD_DESC_SZ];

    struct _fde_flags {
        bool open;
        bool close_request; ///< true if file_ or comm_close has been called
        bool write_daemon;
        bool socket_eof;
        bool nolinger;
        bool nonblocking;
        bool ipc;
        bool called_connect;
        bool nodelay;
        bool close_on_exec;
        bool read_pending;
        //bool write_pending; //XXX seems not to be used
        bool transparent;
    } flags;

    int64_t bytes_read;
    int64_t bytes_written;

    struct {
        int uses;                   /* ie # req's over persistent conn */
    } pconn;

#if USE_DELAY_POOLS
    ClientInfo * clientInfo;/* pointer to client info used in client write limiter or NULL if not present */
#endif
    unsigned epoll_state;

    _fde_disk disk;
    PF *read_handler;
    void *read_data;
    PF *write_handler;
    void *write_data;
    AsyncCall::Pointer timeoutHandler;
    time_t timeout;
    time_t writeStart;
    void *lifetime_data;
    AsyncCall::Pointer closeHandler;
    AsyncCall::Pointer halfClosedReader; /// read handler for half-closed fds
    READ_HANDLER *read_method;
    WRITE_HANDLER *write_method;
    Security::SessionPointer ssl;
    Security::ContextPointer dynamicTlsContext; ///< cached and then freed when fd is closed
#if _SQUID_WINDOWS_
    struct {
        long handle;
    } win32;
#endif
    tos_t tosFromServer;                /**< Stores the TOS flags of the packets from the remote server.
                                            See FwdState::dispatch(). Note that this differs to
                                            tosToServer in that this is the value we *receive* from the,
                                            connection, whereas tosToServer is the value to set on packets
                                            *leaving* Squid.  */
    unsigned int nfmarkFromServer;      /**< Stores the Netfilter mark value of the connection from the remote
                                            server. See FwdState::dispatch(). Note that this differs to
                                            nfmarkToServer in that this is the value we *receive* from the,
                                            connection, whereas nfmarkToServer is the value to set on packets
                                            *leaving* Squid.   */

    /** Clear the fde class back to NULL equivalent. */
    inline void clear() {
        type = 0;
        remote_port = 0;
        local_addr.setEmpty();
        tosToServer = '\0';
        nfmarkToServer = 0;
        sock_family = 0;
        memset(ipaddr, '\0', MAX_IPSTRLEN);
        memset(desc,'\0',FD_DESC_SZ);
        memset(&flags,0,sizeof(_fde_flags));
        bytes_read = 0;
        bytes_written = 0;
        pconn.uses = 0;
#if USE_DELAY_POOLS
        clientInfo = NULL;
#endif
        epoll_state = 0;
        read_handler = NULL;
        read_data = NULL;
        write_handler = NULL;
        write_data = NULL;
        timeoutHandler = NULL;
        timeout = 0;
        writeStart = 0;
        lifetime_data = NULL;
        closeHandler = NULL;
        halfClosedReader = NULL;
        read_method = NULL;
        write_method = NULL;
        ssl.reset();
        dynamicTlsContext.reset();
#if _SQUID_WINDOWS_
        win32.handle = (long)NULL;
#endif
        tosFromServer = '\0';
        nfmarkFromServer = 0;
    }
};

#define fd_table fde::Table

int fdNFree(void);

#define FD_READ_METHOD(fd, buf, len) (*fd_table[fd].read_method)(fd, buf, len)
#define FD_WRITE_METHOD(fd, buf, len) (*fd_table[fd].write_method)(fd, buf, len)

#endif /* SQUID_FDE_H */

