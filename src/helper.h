/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 84    Helper process maintenance */

#ifndef SQUID_HELPER_H
#define SQUID_HELPER_H

#include "base/AsyncCall.h"
#include "base/InstanceId.h"
#include "cbdata.h"
#include "comm/forward.h"
#include "dlink.h"
#include "helper/ChildConfig.h"
#include "helper/forward.h"
#include "helper/Reply.h"
#include "helper/Request.h"
#include "helper/ReservationId.h"
#include "ip/Address.h"
#include "sbuf/SBuf.h"

#include <list>
#include <map>
#include <queue>
#include <unordered_map>

class Packable;
class wordlist;

namespace Helper
{
/// Holds the  required data to serve a helper request.
class Xaction {
    MEMPROXY_CLASS(Helper::Xaction);
public:
    Xaction(HLPCB *c, void *d, const char *b): request(c, d, b) {}
    Helper::Request request;
    Helper::Reply reply;
};
}

class HelperServerBase;
/**
 * Managers a set of individual helper processes with a common queue of requests.
 *
 * With respect to load, a helper goes through these states (roughly):
 *   idle:   no processes are working on requests (and no requests are queued);
 *   normal: some, but not all processes are working (and no requests are queued);
 *   busy:   all processes are working (and some requests are possibly queued);
 *   overloaded: a busy helper with more than queue-size requests in the queue.
 *
 * A busy helper queues new requests and issues a WARNING every 10 minutes or so.
 * An overloaded helper either drops new requests or keeps queuing them, depending on
 *   whether the caller can handle dropped requests (trySubmit vs helperSubmit APIs).
 * If an overloaded helper has been overloaded for 3+ minutes, an attempt to use
 *   it results in on-persistent-overload action, which may kill worker.
 */
class helper
{
    CBDATA_CLASS(helper);

public:
    explicit helper(const char *name) : id_name(name) {}
    virtual ~helper();

    /// \returns next request in the queue, or nil.
    Helper::Xaction *nextRequest();

    /// If possible, submit request. Otherwise, either kill Squid or return false.
    bool trySubmit(const char *buf, HLPCB * callback, void *data);

    /// Submits a request to the helper or add it to the queue if none of
    /// the servers is available.
    void submitRequest(Helper::Xaction *r);

    /// Dump some stats about the helper state to a Packable object
    void packStatsInto(Packable *p, const char *label = NULL) const;
    /// whether the helper will be in "overloaded" state after one more request
    /// already overloaded helpers return true
    bool willOverload() const;

    /// Updates interall statistics and start new helper server processes after
    /// an unexpected server exit
    /// \param needsNewServers true if new servers must started, false otherwise
    void handleKilledServer(HelperServerBase *srv, bool &needsNewServers);

public:
    wordlist *cmdline = nullptr;
    dlink_list servers;
    std::queue<Helper::Xaction *> queue;
    const char *id_name = nullptr;
    Helper::ChildConfig childs;          ///< configuration settings for number running
    int ipc_type = 0;
    Ip::Address addr;
    unsigned int droppedRequests = 0;    ///< requests not sent during helper overload
    time_t overloadStart = 0;            ///< when the helper became overloaded (zero if it is not)
    time_t last_queue_warn = 0;
    time_t last_restart = 0;
    time_t timeout = 0;                  ///< requests timeout
    bool retryTimedOut = false;          ///< whether the timed-out requests must retried
    bool retryBrokenHelper = false;      ///< whether the requests must retried on BH replies
    SBuf onTimedOutResponse;             ///< the response to use when helper response timedout
    char eom = '\n';                     ///< the char which marks the end of (response) message

    struct _stats {
        int requests = 0;
        int replies = 0;
        int timedout = 0;
        int queue_size = 0;
        int avg_svc_time = 0;
    } stats;

protected:
    friend void helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data);
    bool queueFull() const;
    bool overloaded() const;
    void syncQueueStats();
    bool prepSubmit();
    void submit(const char *buf, HLPCB * callback, void *data);
};

class statefulhelper : public helper
{
    CBDATA_CLASS(statefulhelper);

public:
    typedef std::unordered_map<Helper::ReservationId, helper_stateful_server *> Reservations;

    explicit statefulhelper(const char *name) : helper(name) {}
    virtual ~statefulhelper() {}

public:
    /// reserve the given server
    void reserveServer(helper_stateful_server * srv);

    /// undo reserveServer(), clear the reservation and kick the queue
    void cancelReservation(const Helper::ReservationId reservation);

private:
    friend void helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPCB * callback, void *data, const Helper::ReservationId & reservation);

    /// \return the previously reserved server (if the reservation is still valid) or nil
    helper_stateful_server *findServer(const Helper::ReservationId & reservation);

    void submit(const char *buf, HLPCB * callback, void *data, const Helper::ReservationId & reservation);
    bool trySubmit(const char *buf, HLPCB * callback, void *data, const Helper::ReservationId & reservation);

    ///< reserved servers indexed by reservation IDs
    Reservations reservations;
};

/// represents a single helper process abstraction
class HelperServerBase: public CbdataParent
{
public:
    HelperServerBase(Ip::Address &, int aPid, void *aIpc, int rfd, int wfd);
    virtual ~HelperServerBase();

    /** Closes pipes to the helper safely.
     * Handles the case where the read and write pipes are the same FD.
     *
     * \param name displayed for the helper being shutdown if logging an error
     */
    void closePipesSafely(const char *name);

    /** Closes the reading pipe.
     * If the read and write sockets are the same the write pipe will
     * also be closed. Otherwise its left open for later handling.
     *
     * \param name displayed for the helper being shutdown if logging an error
     */
    void closeWritePipeSafely(const char *name);

    // TODO: Teach each child to report its child-specific state instead.
    /// whether the server is locked for exclusive use by a client
    virtual bool reserved() = 0;

    /// dequeues and sends a Helper::Unknown answer to all queued requests
    virtual void dropQueued();

    /// the helper object that created this server
    virtual helper *getParent() const = 0;

public:
    /// Helper program identifier; does not change when contents do,
    ///   including during assignment
    const InstanceId<HelperServerBase> index;
    int pid = 0;
    Ip::Address addr;
    Comm::ConnectionPointer readPipe;
    Comm::ConnectionPointer writePipe;
    void *hIpc = nullptr;

    char *rbuf = nullptr;
    size_t rbuf_sz = 0;
    size_t roffset = 0;

    struct timeval dispatch_time;
    struct timeval answer_time;

    dlink_node link;

    struct _helper_flags {
        bool writing = false;
        bool closing = false;
        bool shutdown = false;
    } flags;

    typedef std::list<Helper::Xaction *> Requests;
    Requests requests; ///< requests in order of submission/expiration

    struct {
        uint64_t uses = 0;     ///< requests sent to this helper
        uint64_t replies = 0;  ///< replies received from this helper
        uint64_t pending = 0;  ///< queued lookups waiting to be sent to this helper
        uint64_t releases = 0; ///< times release() has been called on this helper (if stateful)
        uint64_t timedout = 0; ///< requests which timed-out
    } stats;
};

class MemBuf;
class CommTimeoutCbParams;

// TODO: Rename to StatelessHelperServer and rename HelperServerBase to HelperServer.
/// represents a single "stateless helper" process
class helper_server : public HelperServerBase
{
    CBDATA_CHILD(helper_server);

public:
    helper_server(helper *hlp, int pid, void *hIpc, int rfd, int wfd);
    virtual ~helper_server();

    uint64_t nextRequestId = 0;

    MemBuf *wqueue = nullptr;
    MemBuf *writebuf = nullptr;

    helper *parent = nullptr;

    /// The helper request Xaction object for the current reply .
    /// A helper reply may be distributed to more than one of the retrieved
    /// packets from helper. This member stores the Xaction object as long as
    /// the end-of-message for current reply is not retrieved.
    Helper::Xaction *replyXaction = nullptr;

    /// Whether to ignore current message, because it is timed-out or other reason
    bool ignoreToEom = false;

    // STL says storing std::list iterators is safe when changing the list
    typedef std::map<uint64_t, Requests::iterator> RequestIndex;
    RequestIndex requestsIndex; ///< maps request IDs to requests

    /// Search in queue for the request with requestId, return the related
    /// Xaction object and remove it from queue.
    /// If concurrency is disabled then the requestId is ignored and the
    /// Xaction of the next request in queue is retrieved.
    Helper::Xaction *popRequest(int requestId);

    /// Run over the active requests lists and forces a retry, or timedout reply
    /// or the configured "on timeout response" for timedout requests.
    void checkForTimedOutRequests(bool const retry);

    /*HelperServerBase API*/
    virtual bool reserved() override {return false;}
    virtual void dropQueued() override;
    virtual helper *getParent() const override {return parent;}

    /// Read timeout handler
    static void requestTimeout(const CommTimeoutCbParams &io);

    /// close handler to handle exited server processes
    static void HelperServerClosed(helper_server *srv);
};

// TODO: Rename to StatefulHelperServer and rename HelperServerBase to HelperServer.
/// represents a single "stateful helper" process
class helper_stateful_server : public HelperServerBase
{
    CBDATA_CHILD(helper_stateful_server);

public:
    helper_stateful_server(statefulhelper *hlp, int pid, void *hIpc, int rfd, int wfd);
    virtual ~helper_stateful_server();

    void reserve();
    void clearReservation();

    /* HelperServerBase API */
    virtual bool reserved() override {return reservationId.reserved();}
    virtual helper *getParent() const override {return parent;}

    /// close handler to handle exited server processes
    static void HelperServerClosed(helper_stateful_server *srv);

    statefulhelper *parent = nullptr;

    // Reservations temporary lock the server for an exclusive "client" use. The
    // client keeps the reservation ID as a proof of her reservation. If a
    // reservation expires, and the server is reserved for another client, then
    // the reservation ID presented by the late client will not match ours.
    Helper::ReservationId reservationId; ///< "confirmation ID" of the last
    time_t reservationStart = 0;         ///< when the last "reservation" was made
};

/* helper.c */
void helperOpenServers(helper * hlp);
void helperStatefulOpenServers(statefulhelper * hlp);
void helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data);
void helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPCB * callback, void *data, uint64_t reservation);
void helperShutdown(helper * hlp);
void helperStatefulShutdown(statefulhelper * hlp);

#endif /* SQUID_HELPER_H */

