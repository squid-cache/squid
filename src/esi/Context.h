/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ESI_CONTEXT_H
#define SQUID_SRC_ESI_CONTEXT_H

#include "clientStream.h"
#include "error/forward.h"
#include "esi/Element.h"
#include "esi/Esi.h"
#include "esi/Parser.h"
#include "http/forward.h"
#include "http/StatusCode.h"

class ESIVarState;
class ClientHttpRequest;

/* ESIContext */

class ESIContext : public esiTreeParent, public ESIParserClient
{
    CBDATA_CLASS(ESIContext);

public:
    typedef RefCount<ESIContext> Pointer;
    ESIContext() :
        thisNode(nullptr),
        http(nullptr),
        errorpage(ERR_NONE),
        errorstatus(Http::scNone),
        errormessage(nullptr),
        rep(nullptr),
        outbound_offset(0),
        readpos(0),
        pos(0),
        varState(nullptr),
        cachedASTInUse(false),
        reading_(true),
        processing(false) {
        memset(&flags, 0, sizeof(flags));
    }

    ~ESIContext() override;

    enum esiKick_t {
        ESI_KICK_FAILED,
        ESI_KICK_PENDING,
        ESI_KICK_SENT,
        ESI_KICK_INPROGRESS
    };

    /* when esi processing completes */
    void provideData(ESISegment::Pointer, ESIElement *source) override;
    void fail (ESIElement *source, char const*anError = nullptr) override;
    void startRead();
    void finishRead();
    bool reading() const;
    void setError();
    void setErrorMessage(char const *);

    void addStackElement (ESIElement::Pointer element);
    void addLiteral (const char *s, int len);

    void finishChildren ();

    clientStreamNode *thisNode; /* our stream node */
    /* the request we are processing. HMM: cbdataReferencing this will result
     * in a circular reference, so we don't. Note: we are automatically freed
     * when it is, so that's ok. */
    ClientHttpRequest *http;

    struct {
        unsigned int passthrough:1;
        unsigned int oktosend:1;
        unsigned int finished:1;

        /* an error has occurred, send full body replies
         * regardless. Note that we don't fail midstream
         * because we buffer until we can not fail
         */
        unsigned int error:1;

        unsigned int finishedtemplate:1; /* we've read the entire template */
        unsigned int clientwantsdata:1; /* we need to satisfy a read request */
        unsigned int kicked:1; /* note on reentering the kick routine */
        unsigned int detached:1; /* our downstream has detached */
    } flags;

    err_type errorpage; /* if we error what page to use */
    Http::StatusCode errorstatus; /* if we error, what code to return */
    char *errormessage; /* error to pass to error page */
    HttpReplyPointer rep; /* buffered until we pass data downstream */
    ESISegment::Pointer buffered; /* unprocessed data - for whatever reason */
    ESISegment::Pointer incoming;
    /* processed data we are waiting to send, or for
     * potential errors to be resolved
     */
    ESISegment::Pointer outbound;
    ESISegment::Pointer outboundtail; /* our write segment */
    /* the offset to the next character to send -
     * non zero if we haven't sent the entire segment
     * for some reason
     */
    size_t outbound_offset;
    int64_t readpos; /* the logical position we are reading from */
    int64_t pos; /* the logical position of outbound_offset in the data stream */

    class ParserState
    {

    public:
        ESIElement::Pointer stack[ESI_STACK_DEPTH_LIMIT]; /* a stack of esi elements that are open */
        int stackdepth; /* self explanatory */
        ESIParser::Pointer theParser;
        ESIElement::Pointer top();
        void init (ESIParserClient *);
        bool inited() const;
        ParserState();
        void freeResources();
        void popAll();
        unsigned int parsing:1; /* libexpat is not reentrant on the same context */

    private:
        bool inited_;
    }
    parserState; // TODO: refactor this to somewhere else

    ESIVarState *varState;
    ESIElement::Pointer tree;

    esiKick_t kick ();
    RefCount<ESIContext> cbdataLocker;
    bool failed() const {return flags.error != 0;}

    bool cachedASTInUse;

private:
    void fail ();
    void freeResources();
    void fixupOutboundTail();
    void trimBlanks();
    size_t send ();
    bool reading_;
    void appendOutboundData(ESISegment::Pointer theData);
    esiProcessResult_t process ();
    void parse();
    void parseOneBuffer();
    void updateCachedAST();
    bool hasCachedAST() const;
    void getCachedAST();
    void start(const char *el, const char **attr, size_t attrCount) override;
    void end(const char *el) override;
    void parserDefault (const char *s, int len) override;
    void parserComment (const char *s) override;
    bool processing;
};

#endif /* SQUID_SRC_ESI_CONTEXT_H */

