/*
 * $Id: ESIInclude.h,v 1.3 2004/08/30 05:12:31 robertc Exp $
 *
 * DEBUG: section 86    ESI processing
 * AUTHOR: Robert Collins
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

#ifndef SQUID_ESIINCLUDE_H
#define SQUID_ESIINCLUDE_H

#include "squid.h"
#include "ESISegment.h"
#include "ESIElement.h"
#include "ESIContext.h"

class ESIInclude;
typedef RefCount<ESIInclude> ESIIncludePtr;

class ESIStreamContext : public RefCountable
{

public:
    typedef RefCount<ESIStreamContext> Pointer;
    void *operator new(size_t);
    void operator delete(void *);
    ESIStreamContext();
    ~ESIStreamContext();
    void freeResources();
    int finished;
    ESIIncludePtr include;
    ESISegment::Pointer localbuffer;
    ESISegment::Pointer buffer;

private:
    CBDATA_CLASS(ESIStreamContext);
};

/* ESIInclude */

class ESIInclude : public ESIElement
{

public:
    MEMPROXY_CLASS(ESIInclude);

    ESIInclude(esiTreeParentPtr, int attributes, const char **attr, ESIContext *);
    ~ESIInclude();
    void render(ESISegment::Pointer);
    esiProcessResult_t process (int dovars);
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const;
    void subRequestDone (ESIStreamContext::Pointer, bool);

    struct
    {

int onerrorcontinue:
        1; /* on error return zero data */

int failed:
        1; /* Failed to process completely */

int finished:
        1; /* Finished getting subrequest data */
    }

    flags;
    ESIStreamContext::Pointer src;
    ESIStreamContext::Pointer alt;
    ESISegment::Pointer srccontent;
    ESISegment::Pointer altcontent;
    ESIVarState *varState;
    char *srcurl, *alturl;
    void fail(ESIStreamContext::Pointer);
    void finish();

private:
    void Start (ESIStreamContext::Pointer, char const *, ESIVarState *);
    esiTreeParentPtr parent;
    void start();
    bool started;
    bool sent;
    ESIInclude(ESIInclude const &);
    bool dataNeeded() const;
    void prepareRequestHeaders(HttpHeader &tempheaders, ESIVarState *vars);
};

MEMPROXY_CLASS_INLINE(ESIInclude)

#endif /* SQUID_ESIINCLUDE_H */
