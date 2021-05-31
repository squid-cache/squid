/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#ifndef SQUID_ESILITERAL_H
#define SQUID_ESILITERAL_H

#include "esi/Element.h"

class ESIContext;

class esiLiteral : public ESIElement
{
    MEMPROXY_CLASS(esiLiteral);

public:
    esiLiteral(ESISegment::Pointer);
    esiLiteral(ESIContext *, const char *s, int len);
    ~esiLiteral();

    void render(ESISegment::Pointer);
    esiProcessResult_t process (int dovars);
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const;
    /* optimise copies away later */
    ESISegment::Pointer buffer;

    struct {
        int donevars:1;
    } flags;

    ESIVarState *varState;
    void finish();

private:
    esiLiteral(esiLiteral const &);
};

#endif /* SQUID_ESILITERAL_H */

