/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#ifndef SQUID_ESIINCLUDE_H
#define SQUID_ESIINCLUDE_H

#include "esi/Context.h"
#include "esi/Element.h"
#include "esi/Segment.h"

class ESIInclude;
typedef RefCount<ESIInclude> ESIIncludePtr;

class ESIStreamContext : public RefCountable
{
    CBDATA_CLASS(ESIStreamContext);

public:
    typedef RefCount<ESIStreamContext> Pointer;
    ESIStreamContext();
    ~ESIStreamContext() override;
    void freeResources();
    int finished;
    ESIIncludePtr include;
    ESISegment::Pointer localbuffer;
    ESISegment::Pointer buffer;
};

class ESIInclude : public ESIElement
{
    MEMPROXY_CLASS(ESIInclude);

public:
    ESIInclude(esiTreeParentPtr, int attributes, const char **attr, ESIContext *);
    ~ESIInclude() override;
    void render(ESISegment::Pointer) override;
    esiProcessResult_t process (int dovars) override;
    Pointer makeCacheable() const override;
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const override;
    void subRequestDone (ESIStreamContext::Pointer, bool);

    struct {
        unsigned int onerrorcontinue:1; /* on error return zero data */
        unsigned int failed:1; /* Failed to process completely */
        unsigned int finished:1; /* Finished getting subrequest data */
    } flags;
    ESIStreamContext::Pointer src;
    ESIStreamContext::Pointer alt;
    ESISegment::Pointer srccontent;
    ESISegment::Pointer altcontent;
    ESIVarState *varState;
    char *srcurl, *alturl;
    void includeFail(ESIStreamContext::Pointer);
    void finish() override;

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

#endif /* SQUID_ESIINCLUDE_H */

