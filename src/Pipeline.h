/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PIPELINE_H
#define SQUID_SRC_PIPELINE_H

#include "base/RefCount.h"
#include "http/forward.h"

#include <list>

/**
 * A queue of transactions awaiting completion.
 *
 * Transactions in the queue may be fully processed, but not yet delivered,
 * or only partially processed.
 *
 * - HTTP/1 pipelined requests can be processed out of order but
 *   responses MUST be written to the client in-order.
 *   The front() context is for the response writing transaction.
 *   The back context may still be reading a request payload/body.
 *   Other contexts are in deferred I/O state, but may be accumulating
 *   payload/body data to be written later.
 *
 * - HTTP/2 multiplexed streams can be processed and delivered in any order.
 *
 * For consistency we treat the pipeline as a FIFO queue in both cases.
 */
class Pipeline
{
    Pipeline(const Pipeline &) = delete;
    Pipeline & operator =(const Pipeline &) = delete;

public:
    Pipeline() : nrequests(0) {}
    ~Pipeline() = default;

    /// register a new request context to the pipeline
    void add(const Http::StreamPointer &);

    /// get the first request context in the pipeline
    Http::StreamPointer front() const;

    /// get the last request context in the pipeline
    Http::StreamPointer back() const;

    /// how many requests are currently pipelined
    size_t count() const {return requests.size();}

    /// whether there are none or any requests currently pipelined
    bool empty() const {return requests.empty();}

    /// deregister the front request from the pipeline
    void popMe(const Http::StreamPointer &);

    /// Number of requests seen in this pipeline (so far).
    /// Includes incomplete transactions.
    uint32_t nrequests;

private:
    /// requests parsed from the connection but not yet completed.
    std::list<Http::StreamPointer> requests;
};

#endif /* SQUID_SRC_PIPELINE_H */

