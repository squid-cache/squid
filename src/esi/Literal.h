/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#ifndef SQUID_SRC_ESI_LITERAL_H
#define SQUID_SRC_ESI_LITERAL_H

#if HAVE_LIBEXPAT || HAVE_LIBXML2
#include "esi/Element.h"

class ESIContext;

class esiLiteral : public ESIElement
{
    MEMPROXY_CLASS(esiLiteral);

public:
    esiLiteral(ESISegment::Pointer);
    esiLiteral(ESIContext *, const char *s, int len);
    ~esiLiteral() override;

    void render(ESISegment::Pointer) override;
    esiProcessResult_t process (int dovars) override;
    Pointer makeCacheable() const override;
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const override;
    /* optimise copies away later */
    ESISegment::Pointer buffer;

    struct {
        unsigned int donevars:1;
    } flags;

    ESIVarState *varState;
    void finish() override;

private:
    esiLiteral(esiLiteral const &);
};

#endif /* HAVE_LIBEXPAT || HAVE_LIBXML2 */
#endif /* SQUID_SRC_ESI_LITERAL_H */

