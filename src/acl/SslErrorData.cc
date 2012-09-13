/*
 * DEBUG: none
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "acl/SslErrorData.h"
#include "acl/Checklist.h"
#include "cache_cf.h"
#include "wordlist.h"

ACLSslErrorData::ACLSslErrorData() : values (NULL)
{}

ACLSslErrorData::ACLSslErrorData(ACLSslErrorData const &old) : values (NULL)
{
    assert (!old.values);
}

ACLSslErrorData::~ACLSslErrorData()
{
    if (values)
        delete values;
}

bool
ACLSslErrorData::match(const Ssl::Errors *toFind)
{
    for (const Ssl::Errors *err = toFind; err; err = err->next ) {
        if (values->findAndTune(err->element))
            return true;
    }
    return false;
}

/* explicit instantiation required for some systems */
/** \cond AUTODOCS-IGNORE */
// AYJ: 2009-05-20 : Removing. clashes with template <int> instantiation for other ACLs.
// template cbdata_type Ssl::Errors::CBDATA_CbDataList;
/** \endcond */

wordlist *
ACLSslErrorData::dump()
{
    wordlist *W = NULL;
    Ssl::Errors *data = values;

    while (data != NULL) {
        wordlistAdd(&W, Ssl::GetErrorName(data->element));
        data = data->next;
    }

    return W;
}

void
ACLSslErrorData::parse()
{
    Ssl::Errors **Tail;
    char *t = NULL;

    for (Tail = &values; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
        Ssl::Errors *q = Ssl::ParseErrorString(t);
        *(Tail) = q;
        Tail = &q->tail()->next;
    }
}

bool
ACLSslErrorData::empty() const
{
    return values == NULL;
}

ACLSslErrorData *
ACLSslErrorData::clone() const
{
    /* Splay trees don't clone yet. */
    assert (!values);
    return new ACLSslErrorData(*this);
}
