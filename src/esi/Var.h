/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#ifndef SQUID_SRC_ESI_VAR_H
#define SQUID_SRC_ESI_VAR_H

#include "esi/Element.h"
#include "esi/Sequence.h"

/* esiVar */

class ESIVar:public esiSequence
{

public:
    ESIVar(esiTreeParentPtr aParent) : esiSequence (aParent) {
        flags.dovars = 1;
    }
};

#endif /* SQUID_SRC_ESI_VAR_H */

