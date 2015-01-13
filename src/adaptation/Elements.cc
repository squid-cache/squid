/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "adaptation/Elements.h"

const char *Adaptation::crlf = "\r\n";

const char *
Adaptation::methodStr(Adaptation::Method method)
{
    switch (method) {

    case Adaptation::methodReqmod:
        return "REQMOD";
        break;

    case Adaptation::methodRespmod:
        return "RESPMOD";
        break;

    case Adaptation::methodOptions:
        return "OPTIONS";
        break;

    default:
        break;
    }

    return "NONE";
}

const char *
Adaptation::vectPointStr(Adaptation::VectPoint point)
{
    switch (point) {

    case Adaptation::pointPreCache:
        return "PRECACHE";
        break;

    case Adaptation::pointPostCache:
        return "POSTCACHE";
        break;

    default:
        break;
    }

    return "NONE";
}

