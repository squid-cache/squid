/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_ACTION_H
#define SQUID_MGR_ACTION_H

#include "ipc/forward.h"
#include "mgr/forward.h"

class StoreEntry;

namespace Mgr
{

/// Base API for organizing the processing of a compiled cache manager command.
/// Not a job because all methods are synchronous (but they may start jobs).
class Action: public RefCountable
{
public:
    typedef RefCount<Action> Pointer;

public:
    Action(const CommandPointer &aCmd);
    virtual ~Action();

    /* for local Cache Manager use */

    /// collect + fillEntry: collect local information and fill the store entry
    void run(StoreEntry *entry, bool writeHttpHeader);

    /// prepare store entry, dump info, close store entry (if possible)
    void fillEntry(StoreEntry *entry, bool writeHttpHeader);

    /* for global Coordinator use */

    /// incrementally merge in remote information (of the same action type)
    virtual void add(const Action &action);

    /* global-local communication */

    /// respond to Coordinator request; default is to collect and sendResponse
    virtual void respond(const Request &request);

    /// pack collected action info into a message to be sent to Coordinator
    virtual void pack(Ipc::TypedMsgHdr &) const {}

    /// unpack action info from the message received by Coordinator
    virtual void unpack(const Ipc::TypedMsgHdr &) {}

    /// notify Coordinator that this action is done with local processing
    void sendResponse(unsigned int requestId);

    /* Action properties */

    /// whether at least some local kid info can be combined and, hence, the
    /// combined data should be written at the end of the coordinated response
    virtual bool aggregatable() const { return true; } // most kid classes are

    bool atomic() const; ///< dump() call writes everything before returning
    const char *name() const; ///< label as seen in the cache manager menu
    const Command &command() const; ///< the cause of this action

    StoreEntry *createStoreEntry() const; ///< creates store entry from params

    ///< Content-Type: header value for this report
    virtual const char *contentType() const {return "text/plain;charset=utf-8";}

protected:
    /// calculate and keep local action-specific information
    virtual void collect() {}

    /** start writing action-specific info to Store entry;
     * may collect info during dump, especially if collect() did nothing
     * non-atomic() actions may continue writing asynchronously after returning
     */
    virtual void dump(StoreEntry *) {}

private:
    const CommandPointer cmd; ///< the command that caused this action

private:
    Action(const Action &); // not implemented
    Action &operator= (const Action &); // not implemented
};

} // namespace Mgr

#endif /* SQUID_MGR_ACTION_H */

