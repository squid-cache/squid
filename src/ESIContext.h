/*
 * $Id: ESIContext.h,v 1.4 2003/08/04 22:14:40 robertc Exp $
 *
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_ESICONTEXT_H
#define SQUID_ESICONTEXT_H

#include "ESIElement.h"
#include "clientStream.h"

class ESIVarState;

class ClientHttpRequest;

#include "ESIParser.h"

/* ESIContext */

class ESIContext : public esiTreeParent, public ESIParserClient
{

public:
    typedef RefCount<ESIContext> Pointer;
    void *operator new (size_t byteCount);
    void operator delete (void *address);
    ESIContext():reading_(true) {}

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

    struct
    {

int passthrough:
        1;

int oktosend:
        1;

int finished:
        1;

        /* an error has occured, send full body replies
         * regardless. Note that we don't fail midstream
         * because we buffer until we can not fail
         */

int error:
        1;

int finishedtemplate:
        1; /* we've read the entire template */

int clientwantsdata:
        1; /* we need to satisfy a read request */

int kicked:
        1; /* note on reentering the kick routine */

int detached:
        1; /* our downstream has detached */
    }

    flags;
    err_type errorpage; /* if we error what page to use */
    http_status errorstatus; /* if we error, what code to return */
    char *errormessage; /* error to pass to error page */
    HttpReply *rep; /* buffered until we pass data downstream */
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
    off_t readpos; /* the logical position we are reading from */
    off_t pos; /* the logical position of outbound_offset in the data stream */

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

    int parsing:
        1; /* libexpat is not reentrant on the same context */

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
    CBDATA_CLASS(ESIContext);
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
};

#endif /* SQUID_ESICONTEXT_H */
