/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ESICONTEXT_H
#define SQUID_ESICONTEXT_H

#include "clientStream.h"
#include "err_type.h"
#include "esi/Element.h"
#include "esi/Parser.h"
#include "HttpReply.h"
#include "http/StatusCode.h"

class ESIVarState;
class ClientHttpRequest;

/* ESIContext */

class ESIContext : public esiTreeParent, public ESIParserClient
{

public:
    typedef RefCount<ESIContext> Pointer;
    ESIContext() :
        thisNode(NULL),
        http(NULL),
        errorpage(ERR_NONE),
        errorstatus(Http::scNone),
        errormessage(NULL),
        rep(NULL),
        outbound_offset(0),
        readpos(0),
        pos(0),
        varState(NULL),
        cachedASTInUse(false),
        reading_(true),
        processing(false) {
        memset(&flags, 0, sizeof(flags));
    }

    ~ESIContext();

    enum esiKick_t {
        ESI_KICK_FAILED,
        ESI_KICK_PENDING,
        ESI_KICK_SENT,
        ESI_KICK_INPROGRESS
    };

    /* when esi processing completes */
    void provideData(ESISegment::Pointer, ESIElement *source);
    void fail (ESIElement *source, char const*anError = NULL);
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
     * when it is, so thats ok. */
    ClientHttpRequest *http;

    struct {
        int passthrough:1;
        int oktosend:1;
        int finished:1;

        /* an error has occured, send full body replies
         * regardless. Note that we don't fail midstream
         * because we buffer until we can not fail
         */
        int error:1;

        int finishedtemplate:1; /* we've read the entire template */
        int clientwantsdata:1; /* we need to satisfy a read request */
        int kicked:1; /* note on reentering the kick routine */
        int detached:1; /* our downstream has detached */
    } flags;

    err_type errorpage; /* if we error what page to use */
    Http::StatusCode errorstatus; /* if we error, what code to return */
    char *errormessage; /* error to pass to error page */
    HttpReply::Pointer rep; /* buffered until we pass data downstream */
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
        ESIElement::Pointer stack[10]; /* a stack of esi elements that are open */
        int stackdepth; /* self explanatory */
        ESIParser::Pointer theParser;
        ESIElement::Pointer top();
        void init (ESIParserClient *);
        bool inited() const;
        ParserState();
        void freeResources();
        void popAll();
        int parsing:1; /* libexpat is not reentrant on the same context */

    private:
        bool inited_;
    }

    parserState; /* todo factor this off somewhere else; */
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
    virtual void start(const char *el, const char **attr, size_t attrCount);
    virtual void end(const char *el);
    virtual void parserDefault (const char *s, int len);
    virtual void parserComment (const char *s);
    bool processing;

    CBDATA_CLASS2(ESIContext);
};

#endif /* SQUID_ESICONTEXT_H */

