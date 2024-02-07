/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 84    Helper process maintenance */

#ifndef SQUID_SRC_HELPER_H
#define SQUID_SRC_HELPER_H

#include "base/AsyncCall.h"
#include "base/InstanceId.h"
#include "base/RefCount.h"
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

class CommTimeoutCbParams;
class MemBuf;
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

class SessionBase;

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
class Client: public RefCountable
{
public:
    using Pointer = RefCount<Client>;

    /// \returns a newly created instance of the named helper client
    /// \param name admin-visible helper category (with this process lifetime)
    static Pointer Make(const char *name);

    virtual ~Client();

    /// \returns next request in the queue, or nil.
    Xaction *nextRequest();

    /// If possible, submit request. Otherwise, either kill Squid or return false.
    bool trySubmit(const char *buf, HLPCB * callback, void *data);

    /// Submits a request to the helper or add it to the queue if none of
    /// the servers is available.
    void submitRequest(Xaction *);

    /// Dump some stats about the helper state to a Packable object
    void packStatsInto(Packable *p, const char *label = nullptr) const;
    /// whether the helper will be in "overloaded" state after one more request
    /// already overloaded helpers return true
    bool willOverload() const;

    /// Updates internal statistics and starts new helper processes after
    /// an unexpected server exit
    void handleKilledServer(SessionBase *);

    /// Reacts to unexpected helper process death(s), including a failure to start helper(s)
    /// and an unexpected exit of a previously started helper. \sa handleKilledServer()
    /// \param madeProgress whether the died helper(s) responded to any requests
    void handleFewerServers(bool madeProgress);

    /// satisfies all queued requests with a Helper::Unknown answer
    /// \prec no existing servers will be able to process queued requests
    /// \sa SessionBase::dropQueued()
    void dropQueued();

    /// sends transaction response to the transaction initiator
    void callBack(Xaction &);

    /// Starts required helper process(es).
    /// The caller is responsible for checking that new processes are needed.
    virtual void openSessions();

public:
    wordlist *cmdline = nullptr;
    dlink_list servers;
    std::queue<Xaction *> queue;
    const char *id_name = nullptr;
    ChildConfig childs; ///< Configuration settings for number running.
    int ipc_type = 0;
    Ip::Address addr;
    unsigned int droppedRequests = 0; ///< requests not sent during helper overload
    time_t overloadStart = 0; ///< when the helper became overloaded (zero if it is not)
    time_t last_queue_warn = 0;
    time_t last_restart = 0;
    time_t timeout = 0; ///< Requests timeout
    bool retryTimedOut = false; ///< Whether the timed-out requests must retried
    bool retryBrokenHelper = false; ///< Whether the requests must retried on BH replies
    SBuf onTimedOutResponse; ///< The response to use when helper response timedout
    char eom = '\n';   ///< The char which marks the end of (response) message, normally '\n'

    struct _stats {
        int requests = 0;
        int replies = 0;
        int timedout = 0;
        int queue_size = 0;
        int avg_svc_time = 0;
    } stats;

protected:
    /// \param name admin-visible helper category (with this process lifetime)
    explicit Client(const char * const name): id_name(name) {}

    bool queueFull() const;
    bool overloaded() const;
    void syncQueueStats();
    bool prepSubmit();
    void submit(const char *buf, HLPCB * callback, void *data);
};

} // namespace Helper

// TODO: Rename to a *Client.
class statefulhelper: public Helper::Client
{
public:
    using Pointer = RefCount<statefulhelper>;
    typedef std::unordered_map<Helper::ReservationId, helper_stateful_server *> Reservations;

    ~statefulhelper() override = default;

    static Pointer Make(const char *name);

    /// reserve the given server
    void reserveServer(helper_stateful_server * srv);

    /// undo reserveServer(), clear the reservation and kick the queue
    void cancelReservation(const Helper::ReservationId reservation);

    /* Helper::Client API */
    void openSessions() override;

private:
    friend void helperStatefulSubmit(const statefulhelper::Pointer &, const char *buf, HLPCB *, void *cbData, const Helper::ReservationId &);

    explicit statefulhelper(const char * const name): Helper::Client(name) {}

    /// \return the previously reserved server (if the reservation is still valid) or nil
    helper_stateful_server *findServer(const Helper::ReservationId & reservation);

    void submit(const char *buf, HLPCB * callback, void *data, const Helper::ReservationId & reservation);
    bool trySubmit(const char *buf, HLPCB * callback, void *data, const Helper::ReservationId & reservation);

    ///< reserved servers indexed by reservation IDs
    Reservations reservations;
};

namespace Helper
{

/// represents a single helper process
class SessionBase: public CbdataParent
{
public:
    ~SessionBase() override;

    /// close handler to handle exited server processes
    static void HelperServerClosed(SessionBase *);

    /** Closes pipes to the helper safely.
     * Handles the case where the read and write pipes are the same FD.
     */
    void closePipesSafely();

    /** Closes the reading pipe.
     * If the read and write sockets are the same the write pipe will
     * also be closed. Otherwise its left open for later handling.
     */
    void closeWritePipeSafely();

    // TODO: Teach each child to report its child-specific state instead.
    /// whether the server is locked for exclusive use by a client
    virtual bool reserved() = 0;

    /// our creator (parent) object
    virtual Client &helper() const = 0;

    /// dequeues and sends an Unknown answer to all queued requests
    virtual void dropQueued();

public:
    /// Helper program identifier; does not change when contents do,
    ///   including during assignment
    const InstanceId<SessionBase> index;

    int pid;
    Ip::Address addr;
    Comm::ConnectionPointer readPipe;
    Comm::ConnectionPointer writePipe;
    void *hIpc;

    char *rbuf;
    size_t rbuf_sz;
    size_t roffset;

    struct timeval dispatch_time;
    struct timeval answer_time;

    dlink_node link;

    struct _helper_flags {
        bool writing;
        bool closing;
        bool shutdown;
    } flags;

    using Requests = std::list<Xaction *>;
    Requests requests; ///< requests in order of submission/expiration

    struct {
        uint64_t uses;     //< requests sent to this helper
        uint64_t replies;  //< replies received from this helper
        uint64_t pending;  //< queued lookups waiting to be sent to this helper
        uint64_t releases; //< times release() has been called on this helper (if stateful)
        uint64_t timedout; //< requests which timed-out
    } stats;
    void initStats();
};

/// represents a single "stateless helper" process;
/// supports concurrent helper requests
class Session: public SessionBase
{
    CBDATA_CHILD(Session);

public:
    uint64_t nextRequestId;

    MemBuf *wqueue;
    MemBuf *writebuf;

    Client::Pointer parent;

    /// The helper request Xaction object for the current reply .
    /// A helper reply may be distributed to more than one of the retrieved
    /// packets from helper. This member stores the Xaction object as long as
    /// the end-of-message for current reply is not retrieved.
    Xaction *replyXaction;

    /// Whether to ignore current message, because it is timed-out or other reason
    bool ignoreToEom;

    // STL says storing std::list iterators is safe when changing the list
    typedef std::map<uint64_t, Requests::iterator> RequestIndex;
    RequestIndex requestsIndex; ///< maps request IDs to requests

    ~Session() override;

    /// Search in queue for the request with requestId, return the related
    /// Xaction object and remove it from queue.
    /// If concurrency is disabled then the requestId is ignored and the
    /// Xaction of the next request in queue is retrieved.
    Xaction *popRequest(int requestId);

    /// Run over the active requests lists and forces a retry, or timedout reply
    /// or the configured "on timeout response" for timedout requests.
    void checkForTimedOutRequests(bool const retry);

    /* SessionBase API */
    bool reserved() override {return false;}
    void dropQueued() override;
    Client &helper() const override { return *parent; }

    /// Read timeout handler
    static void requestTimeout(const CommTimeoutCbParams &io);
};

} // namespace Helper

// TODO: Rename to a *Session, matching renamed statefulhelper.
/// represents a single "stateful helper" process;
/// supports exclusive transaction reservations
class helper_stateful_server: public Helper::SessionBase
{
    CBDATA_CHILD(helper_stateful_server);

public:
    ~helper_stateful_server() override;
    void reserve();
    void clearReservation();

    /* Helper::SessionBase API */
    bool reserved() override {return reservationId.reserved();}
    Helper::Client &helper() const override { return *parent; }

    statefulhelper::Pointer parent;

    // Reservations temporary lock the server for an exclusive "client" use. The
    // client keeps the reservation ID as a proof of her reservation. If a
    // reservation expires, and the server is reserved for another client, then
    // the reservation ID presented by the late client will not match ours.
    Helper::ReservationId reservationId; ///< "confirmation ID" of the last
    time_t reservationStart; ///< when the last `reservation` was made
};

void helperSubmit(const Helper::Client::Pointer &, const char *buf, HLPCB *, void *cbData);
void helperStatefulSubmit(const statefulhelper::Pointer &, const char *buf, HLPCB *, void *cbData, uint64_t reservation);
void helperShutdown(const Helper::Client::Pointer &);
void helperStatefulShutdown(const statefulhelper::Pointer &);

#endif /* SQUID_SRC_HELPER_H */

