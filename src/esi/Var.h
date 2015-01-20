/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#ifndef SQUID_ESIVAR_H
#define SQUID_ESIVAR_H

#include "esi/Element.h"
#include "esi/Sequence.h"

/* esiVar */

class ESIVar:public esiSequence
{

public:
    //    void *operator new (size_t byteCount);
    //    void operator delete (void *address);
    ESIVar(esiTreeParentPtr aParent) : esiSequence (aParent) {
        flags.dovars = 1;
    }
};

#endif /* SQUID_ESIVAR_H */

