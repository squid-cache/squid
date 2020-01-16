/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#ifndef SQUID_ESIEXCEPT_H
#define SQUID_ESIEXCEPT_H

#include "esi/Element.h"
#include "esi/Sequence.h"

/* esiExcept */

class esiExcept : public esiSequence
{

public:
    esiExcept(esiTreeParentPtr aParent) : esiSequence (aParent) {}
};

#endif /* SQUID_ESIEXCEPT_H */

