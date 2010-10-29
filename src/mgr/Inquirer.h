/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_INQUIRER_H
#define SQUID_MGR_INQUIRER_H

#include "base/AsyncJobCalls.h"
#include "base/AsyncJob.h"
#include "ipc/StrandCoords.h"
#include "MemBuf.h"
#include "mgr/Action.h"
#include "mgr/Request.h"
#include <map>

class CommIoCbParams;
class CommCloseCbParams;

namespace Mgr
{

/// Coordinator's job that sends a cache manage request to each strand,
/// aggregating individual strand responses and dumping the result if needed
class Inquirer: public AsyncJob
{
public:
    Inquirer(Action::Pointer anAction, int aFd, const Request &aCause,
             const Ipc::StrandCoords &coords);
    virtual ~Inquirer();

    /// finds and calls the right Inquirer upon strand's response
    static void HandleRemoteAck(const Mgr::Response& response);

protected:
    /* AsyncJob API */
    virtual void start();
    virtual void swanSong();
    virtual bool doneAll() const;
    virtual const char *status() const;

private:
    typedef UnaryMemFunT<Inquirer, Response, const Response&> HandleAckDialer;

    void inquire();
    void noteWroteHeader(const CommIoCbParams& params);
    void noteCommClosed(const CommCloseCbParams& params);

    void handleRemoteAck(const Response& response);

    static AsyncCall::Pointer DequeueRequest(unsigned int requestId);

    static void RequestTimedOut(void* param);
    void requestTimedOut();
    void removeTimeoutEvent();

    void close();
    void removeCloseHandler();

private:
    Action::Pointer aggrAction; //< action to aggregate

    Request cause; ///< cache manager request received from HTTP client
    int fd; ///< HTTP client socket descriptor

    Ipc::StrandCoords strands; ///< all strands we want to query, in order
    Ipc::StrandCoords::const_iterator pos; ///< strand we should query now

    unsigned int requestId; ///< ID of our outstanding request to strand
    AsyncCall::Pointer writer; ///< comm_write callback
    AsyncCall::Pointer closer; ///< comm_close handler
    const double timeout; ///< number of seconds to wait for strand response

    /// maps requestId to Inquirer::handleRemoteAck callback
    typedef std::map<unsigned int, AsyncCall::Pointer> RequestsMap;
    static RequestsMap TheRequestsMap; ///< pending strand requests

    static unsigned int LastRequestId; ///< last requestId used

    CBDATA_CLASS2(Inquirer);
};

} // namespace Mgr

#endif /* SQUID_MGR_INQUIRER_H */
