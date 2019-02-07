/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "client_side_request.h"
#include "http/Stream.h"
#include "HttpHdrContRange.h"
#include "HttpHeaderTools.h"
#include "Store.h"
#include "TimeOrTag.h"

Http::Stream::Stream(const Comm::ConnectionPointer &aConn, ClientHttpRequest *aReq) :
    clientConnection(aConn),
    http(aReq),
    reply(nullptr),
    writtenToSocket(0),
    mayUseConnection_(false),
    connRegistered_(false)
{
    assert(http != nullptr);
    memset(reqbuf, '\0', sizeof (reqbuf));
    flags.deferred = 0;
    flags.parsed_ok = 0;
    deferredparams.node = nullptr;
    deferredparams.rep = nullptr;
}

Http::Stream::~Stream()
{
    if (auto node = getTail()) {
        if (auto ctx = dynamic_cast<Http::Stream *>(node->data.getRaw())) {
            /* We are *always* the tail - prevent recursive free */
            assert(this == ctx);
            node->data = nullptr;
        }
    }
    httpRequestFree(http);
}

void
Http::Stream::registerWithConn()
{
    assert(!connRegistered_);
    assert(getConn());
    connRegistered_ = true;
    getConn()->pipeline.add(Http::StreamPointer(this));
}

bool
Http::Stream::startOfOutput() const
{
    return http->out.size == 0;
}

void
Http::Stream::writeComplete(size_t size)
{
    const StoreEntry *entry = http->storeEntry();
    debugs(33, 5, clientConnection << ", sz " << size <<
           ", off " << (http->out.size + size) << ", len " <<
           (entry ? entry->objectLen() : 0));

    http->out.size += size;

    if (clientHttpRequestStatus(clientConnection->fd, http)) {
        initiateClose("failure or true request status");
        /* Do we leak here ? */
        return;
    }

    switch (socketState()) {

    case STREAM_NONE:
        pullData();
        break;

    case STREAM_COMPLETE: {
        debugs(33, 5, clientConnection << " Stream complete, keepalive is " <<
               http->request->flags.proxyKeepalive);
        ConnStateData *c = getConn();
        if (!http->request->flags.proxyKeepalive)
            clientConnection->close();
        finished();
        c->kick();
    }
    return;

    case STREAM_UNPLANNED_COMPLETE:
        initiateClose("STREAM_UNPLANNED_COMPLETE");
        return;

    case STREAM_FAILED:
        initiateClose("STREAM_FAILED");
        return;

    default:
        fatal("Hit unreachable code in Http::Stream::writeComplete\n");
    }
}

void
Http::Stream::pullData()
{
    debugs(33, 5, reply << " written " << http->out.size << " into " << clientConnection);

    /* More data will be coming from the stream. */
    StoreIOBuffer readBuffer;
    /* XXX: Next requested byte in the range sequence */
    /* XXX: length = getmaximumrangelenfgth */
    readBuffer.offset = getNextRangeOffset();
    readBuffer.length = HTTP_REQBUF_SZ;
    readBuffer.data = reqbuf;
    /* we may note we have reached the end of the wanted ranges */
    clientStreamRead(getTail(), http, readBuffer);
}

bool
Http::Stream::multipartRangeRequest() const
{
    return http->multipartRangeRequest();
}

int64_t
Http::Stream::getNextRangeOffset() const
{
    debugs (33, 5, "range: " << http->request->range <<
            "; http offset " << http->out.offset <<
            "; reply " << reply);

    // XXX: This method is called from many places, including pullData() which
    // may be called before prepareReply() [on some Squid-generated errors].
    // Hence, we may not even know yet whether we should honor/do ranges.

    if (http->request->range) {
        /* offset in range specs does not count the prefix of an http msg */
        /* check: reply was parsed and range iterator was initialized */
        assert(http->range_iter.valid);
        /* filter out data according to range specs */
        assert(canPackMoreRanges());
        {
            assert(http->range_iter.currentSpec());
            /* offset of still missing data */
            int64_t start = http->range_iter.currentSpec()->offset +
                            http->range_iter.currentSpec()->length -
                            http->range_iter.debt();
            debugs(33, 3, "clientPackMoreRanges: in:  offset: " << http->out.offset);
            debugs(33, 3, "clientPackMoreRanges: out:"
                   " start: " << start <<
                   " spec[" << http->range_iter.pos - http->request->range->begin() << "]:" <<
                   " [" << http->range_iter.currentSpec()->offset <<
                   ", " << http->range_iter.currentSpec()->offset +
                   http->range_iter.currentSpec()->length << "),"
                   " len: " << http->range_iter.currentSpec()->length <<
                   " debt: " << http->range_iter.debt());
            if (http->range_iter.currentSpec()->length != -1)
                assert(http->out.offset <= start);  /* we did not miss it */

            return start;
        }

    } else if (reply && reply->contentRange()) {
        /* request does not have ranges, but reply does */
        /** \todo FIXME: should use range_iter_pos on reply, as soon as reply->content_range
         *        becomes HttpHdrRange rather than HttpHdrRangeSpec.
         */
        return http->out.offset + reply->contentRange()->spec.offset;
    }

    return http->out.offset;
}

/**
 * increments iterator "i"
 * used by clientPackMoreRanges
 *
 * \retval true    there is still data available to pack more ranges
 * \retval false
 */
bool
Http::Stream::canPackMoreRanges() const
{
    /** first update iterator "i" if needed */
    if (!http->range_iter.debt()) {
        debugs(33, 5, "At end of current range spec for " << clientConnection);

        if (http->range_iter.pos != http->range_iter.end)
            ++http->range_iter.pos;

        http->range_iter.updateSpec();
    }

    assert(!http->range_iter.debt() == !http->range_iter.currentSpec());

    /* paranoid sync condition */
    /* continue condition: need_more_data */
    debugs(33, 5, "returning " << (http->range_iter.currentSpec() ? true : false));
    return http->range_iter.currentSpec() ? true : false;
}

/// Adapt stream status to account for Range cases
clientStream_status_t
Http::Stream::socketState()
{
    switch (clientStreamStatus(getTail(), http)) {

    case STREAM_NONE:
        /* check for range support ending */
        if (http->request->range) {
            /* check: reply was parsed and range iterator was initialized */
            assert(http->range_iter.valid);
            /* filter out data according to range specs */

            if (!canPackMoreRanges()) {
                debugs(33, 5, "Range request at end of returnable " <<
                       "range sequence on " << clientConnection);
                // we got everything we wanted from the store
                return STREAM_COMPLETE;
            }
        } else if (reply && reply->contentRange()) {
            /* reply has content-range, but Squid is not managing ranges */
            const int64_t &bytesSent = http->out.offset;
            const int64_t &bytesExpected = reply->contentRange()->spec.length;

            debugs(33, 7, "body bytes sent vs. expected: " <<
                   bytesSent << " ? " << bytesExpected << " (+" <<
                   reply->contentRange()->spec.offset << ")");

            // did we get at least what we expected, based on range specs?

            if (bytesSent == bytesExpected) // got everything
                return STREAM_COMPLETE;

            if (bytesSent > bytesExpected) // Error: Sent more than expected
                return STREAM_UNPLANNED_COMPLETE;
        }

        return STREAM_NONE;

    case STREAM_COMPLETE:
        return STREAM_COMPLETE;

    case STREAM_UNPLANNED_COMPLETE:
        return STREAM_UNPLANNED_COMPLETE;

    case STREAM_FAILED:
        return STREAM_FAILED;
    }

    fatal ("unreachable code\n");
    return STREAM_NONE;
}

void
Http::Stream::sendStartOfMessage(HttpReply *rep, StoreIOBuffer bodyData)
{
    prepareReply(rep);
    assert(rep);
    MemBuf *mb = rep->pack();

    // dump now, so we do not output any body.
    debugs(11, 2, "HTTP Client " << clientConnection);
    debugs(11, 2, "HTTP Client REPLY:\n---------\n" << mb->buf << "\n----------");

    /* Save length of headers for persistent conn checks */
    http->out.headers_sz = mb->contentSize();
#if HEADERS_LOG
    headersLog(0, 0, http->request->method, rep);
#endif

    if (bodyData.data && bodyData.length) {
        if (multipartRangeRequest())
            packRange(bodyData, mb);
        else if (http->request->flags.chunkedReply) {
            packChunk(bodyData, *mb);
        } else {
            size_t length = lengthToSend(bodyData.range());
            noteSentBodyBytes(length);
            mb->append(bodyData.data, length);
        }
    }

    getConn()->write(mb);
    delete mb;
}

void
Http::Stream::sendBody(StoreIOBuffer bodyData)
{
    if (!multipartRangeRequest() && !http->request->flags.chunkedReply) {
        size_t length = lengthToSend(bodyData.range());
        noteSentBodyBytes(length);
        getConn()->write(bodyData.data, length);
        return;
    }

    MemBuf mb;
    mb.init();
    if (multipartRangeRequest())
        packRange(bodyData, &mb);
    else
        packChunk(bodyData, mb);

    if (mb.contentSize())
        getConn()->write(&mb);
    else
        writeComplete(0);
}

size_t
Http::Stream::lengthToSend(Range<int64_t> const &available) const
{
    // the size of available range can always fit into a size_t type
    size_t maximum = available.size();

    if (!http->request->range)
        return maximum;

    assert(canPackMoreRanges());

    if (http->range_iter.debt() == -1)
        return maximum;

    assert(http->range_iter.debt() > 0);

    /* TODO this + the last line could be a range intersection calculation */
    if (available.start < http->range_iter.currentSpec()->offset)
        return 0;

    return min(http->range_iter.debt(), static_cast<int64_t>(maximum));
}

void
Http::Stream::noteSentBodyBytes(size_t bytes)
{
    debugs(33, 7, bytes << " body bytes");
    http->out.offset += bytes;

    if (!http->request->range)
        return;

    if (http->range_iter.debt() != -1) {
        http->range_iter.debt(http->range_iter.debt() - bytes);
        assert (http->range_iter.debt() >= 0);
    }

    /* debt() always stops at -1, below that is a bug */
    assert(http->range_iter.debt() >= -1);
}

/// \return true when If-Range specs match reply, false otherwise
static bool
clientIfRangeMatch(ClientHttpRequest * http, HttpReply * rep)
{
    const TimeOrTag spec = http->request->header.getTimeOrTag(Http::HdrType::IF_RANGE);

    /* check for parsing falure */
    if (!spec.valid)
        return false;

    /* got an ETag? */
    if (spec.tag.str) {
        ETag rep_tag = rep->header.getETag(Http::HdrType::ETAG);
        debugs(33, 3, "ETags: " << spec.tag.str << " and " <<
               (rep_tag.str ? rep_tag.str : "<none>"));

        if (!rep_tag.str)
            return false; // entity has no etag to compare with!

        if (spec.tag.weak || rep_tag.weak) {
            debugs(33, DBG_IMPORTANT, "Weak ETags are not allowed in If-Range: " <<
                   spec.tag.str << " ? " << rep_tag.str);
            return false; // must use strong validator for sub-range requests
        }

        return etagIsStrongEqual(rep_tag, spec.tag);
    }

    /* got modification time? */
    if (spec.time >= 0)
        return !http->storeEntry()->modifiedSince(spec.time);

    assert(0);          /* should not happen */
    return false;
}

// seems to be something better suited to Server logic
/** adds appropriate Range headers if needed */
void
Http::Stream::buildRangeHeader(HttpReply *rep)
{
    HttpHeader *hdr = rep ? &rep->header : nullptr;
    const char *range_err = nullptr;
    HttpRequest *request = http->request;
    assert(request->range);
    /* check if we still want to do ranges */
    int64_t roffLimit = request->getRangeOffsetLimit();
    auto contentRange = rep ? rep->contentRange() : nullptr;

    if (!rep)
        range_err = "no [parse-able] reply";
    else if ((rep->sline.status() != Http::scOkay) && (rep->sline.status() != Http::scPartialContent))
        range_err = "wrong status code";
    else if (rep->sline.status() == Http::scPartialContent)
        range_err = "too complex response"; // probably contains what the client needs
    else if (rep->sline.status() != Http::scOkay)
        range_err = "wrong status code";
    else if (hdr->has(Http::HdrType::CONTENT_RANGE)) {
        Must(!contentRange); // this is a 200, not 206 response
        range_err = "meaningless response"; // the status code or the header is wrong
    }
    else if (rep->content_length < 0)
        range_err = "unknown length";
    else if (rep->content_length != http->memObject()->getReply()->content_length)
        range_err = "INCONSISTENT length";  /* a bug? */

    /* hits only - upstream CachePeer determines correct behaviour on misses,
     * and client_side_reply determines hits candidates
     */
    else if (http->logType.isTcpHit() &&
             http->request->header.has(Http::HdrType::IF_RANGE) &&
             !clientIfRangeMatch(http, rep))
        range_err = "If-Range match failed";

    else if (!http->request->range->canonize(rep))
        range_err = "canonization failed";
    else if (http->request->range->isComplex())
        range_err = "too complex range header";
    else if (!http->logType.isTcpHit() && http->request->range->offsetLimitExceeded(roffLimit))
        range_err = "range outside range_offset_limit";

    /* get rid of our range specs on error */
    if (range_err) {
        /* XXX We do this here because we need canonisation etc. However, this current
         * code will lead to incorrect store offset requests - the store will have the
         * offset data, but we won't be requesting it.
         * So, we can either re-request, or generate an error
         */
        http->request->ignoreRange(range_err);
    } else {
        /* XXX: TODO: Review, this unconditional set may be wrong. */
        rep->sline.set(rep->sline.version, Http::scPartialContent);
        // web server responded with a valid, but unexpected range.
        // will (try-to) forward as-is.
        //TODO: we should cope with multirange request/responses
        // TODO: review, since rep->content_range is always nil here.
        bool replyMatchRequest = contentRange != nullptr ?
                                 request->range->contains(contentRange->spec) :
                                 true;
        const int spec_count = http->request->range->specs.size();
        int64_t actual_clen = -1;

        debugs(33, 3, "range spec count: " << spec_count <<
               " virgin clen: " << rep->content_length);
        assert(spec_count > 0);
        /* append appropriate header(s) */
        if (spec_count == 1) {
            if (!replyMatchRequest) {
                hdr->putContRange(contentRange);
                actual_clen = rep->content_length;
                //http->range_iter.pos = rep->content_range->spec.begin();
                (*http->range_iter.pos)->offset = contentRange->spec.offset;
                (*http->range_iter.pos)->length = contentRange->spec.length;

            } else {
                HttpHdrRange::iterator pos = http->request->range->begin();
                assert(*pos);
                /* append Content-Range */

                if (!contentRange) {
                    /* No content range, so this was a full object we are
                     * sending parts of.
                     */
                    httpHeaderAddContRange(hdr, **pos, rep->content_length);
                }

                /* set new Content-Length to the actual number of bytes
                 * transmitted in the message-body */
                actual_clen = (*pos)->length;
            }
        } else {
            /* multipart! */
            /* generate boundary string */
            http->range_iter.boundary = http->rangeBoundaryStr();
            /* delete old Content-Type, add ours */
            hdr->delById(Http::HdrType::CONTENT_TYPE);
            httpHeaderPutStrf(hdr, Http::HdrType::CONTENT_TYPE,
                              "multipart/byteranges; boundary=\"" SQUIDSTRINGPH "\"",
                              SQUIDSTRINGPRINT(http->range_iter.boundary));
            /* Content-Length is not required in multipart responses
             * but it is always nice to have one */
            actual_clen = http->mRangeCLen();

            /* http->out needs to start where we want data at */
            http->out.offset = http->range_iter.currentSpec()->offset;
        }

        /* replace Content-Length header */
        assert(actual_clen >= 0);
        hdr->delById(Http::HdrType::CONTENT_LENGTH);
        hdr->putInt64(Http::HdrType::CONTENT_LENGTH, actual_clen);
        debugs(33, 3, "actual content length: " << actual_clen);

        /* And start the range iter off */
        http->range_iter.updateSpec();
    }
}

clientStreamNode *
Http::Stream::getTail() const
{
    if (http->client_stream.tail)
        return static_cast<clientStreamNode *>(http->client_stream.tail->data);

    return nullptr;
}

clientStreamNode *
Http::Stream::getClientReplyContext() const
{
    return static_cast<clientStreamNode *>(http->client_stream.tail->prev->data);
}

ConnStateData *
Http::Stream::getConn() const
{
    assert(http && http->getConn());
    return http->getConn();
}

/// remembers the abnormal connection termination for logging purposes
void
Http::Stream::noteIoError(const int xerrno)
{
    if (http) {
        http->logType.err.timedout = (xerrno == ETIMEDOUT);
        // aborted even if xerrno is zero (which means read abort/eof)
        http->logType.err.aborted = (xerrno != ETIMEDOUT);
    }
}

void
Http::Stream::finished()
{
    ConnStateData *conn = getConn();

    /* we can't handle any more stream data - detach */
    clientStreamDetach(getTail(), http);

    assert(connRegistered_);
    connRegistered_ = false;
    conn->pipeline.popMe(Http::StreamPointer(this));
}

/// called when we encounter a response-related error
void
Http::Stream::initiateClose(const char *reason)
{
    debugs(33, 4, clientConnection << " because " << reason);
    getConn()->stopSending(reason); // closes ASAP
}

void
Http::Stream::deferRecipientForLater(clientStreamNode *node, HttpReply *rep, StoreIOBuffer receivedData)
{
    debugs(33, 2, "Deferring request " << http->uri);
    assert(flags.deferred == 0);
    flags.deferred = 1;
    deferredparams.node = node;
    deferredparams.rep = rep;
    deferredparams.queuedBuffer = receivedData;
}

void
Http::Stream::prepareReply(HttpReply *rep)
{
    reply = rep;
    if (http->request->range)
        buildRangeHeader(rep);
}

/**
 * Packs bodyData into mb using chunked encoding.
 * Packs the last-chunk if bodyData is empty.
 */
void
Http::Stream::packChunk(const StoreIOBuffer &bodyData, MemBuf &mb)
{
    const uint64_t length =
        static_cast<uint64_t>(lengthToSend(bodyData.range()));
    noteSentBodyBytes(length);

    mb.appendf("%" PRIX64 "\r\n", length);
    mb.append(bodyData.data, length);
    mb.append("\r\n", 2);
}

/**
 * extracts a "range" from *buf and appends them to mb, updating
 * all offsets and such.
 */
void
Http::Stream::packRange(StoreIOBuffer const &source, MemBuf *mb)
{
    HttpHdrRangeIter * i = &http->range_iter;
    Range<int64_t> available(source.range());
    char const *buf = source.data;

    while (i->currentSpec() && available.size()) {
        const size_t copy_sz = lengthToSend(available);
        if (copy_sz) {
            // intersection of "have" and "need" ranges must not be empty
            assert(http->out.offset < i->currentSpec()->offset + i->currentSpec()->length);
            assert(http->out.offset + (int64_t)available.size() > i->currentSpec()->offset);

            /*
             * put boundary and headers at the beginning of a range in a
             * multi-range
             */
            if (http->multipartRangeRequest() && i->debt() == i->currentSpec()->length) {
                assert(http->memObject());
                clientPackRangeHdr(
                    http->memObject()->getReply(),  /* original reply */
                    i->currentSpec(),       /* current range */
                    i->boundary,    /* boundary, the same for all */
                    mb);
            }

            // append content
            debugs(33, 3, "appending " << copy_sz << " bytes");
            noteSentBodyBytes(copy_sz);
            mb->append(buf, copy_sz);

            // update offsets
            available.start += copy_sz;
            buf += copy_sz;
        }

        if (!canPackMoreRanges()) {
            debugs(33, 3, "Returning because !canPackMoreRanges.");
            if (i->debt() == 0)
                // put terminating boundary for multiparts
                clientPackTermBound(i->boundary, mb);
            return;
        }

        int64_t nextOffset = getNextRangeOffset();
        assert(nextOffset >= http->out.offset);
        int64_t skip = nextOffset - http->out.offset;
        /* adjust for not to be transmitted bytes */
        http->out.offset = nextOffset;

        if (available.size() <= (uint64_t)skip)
            return;

        available.start += skip;
        buf += skip;

        if (copy_sz == 0)
            return;
    }
}

void
Http::Stream::doClose()
{
    clientConnection->close();
}

