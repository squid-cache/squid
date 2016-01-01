/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/SslErrorData.h"
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
ACLSslErrorData::match(const Ssl::CertErrors *toFind)
{
    for (const Ssl::CertErrors *err = toFind; err; err = err->next ) {
        if (values->findAndTune(err->element.code))
            return true;
    }
    return false;
}

/* explicit instantiation required for some systems */
/** \cond AUTODOCS_IGNORE */
// AYJ: 2009-05-20 : Removing. clashes with template <int> instantiation for other ACLs.
// template cbdata_type Ssl::Errors::CBDATA_CbDataList;
/** \endcond */

SBufList
ACLSslErrorData::dump() const
{
    SBufList sl;
    Ssl::Errors *data = values;
    while (data != NULL) {
        sl.push_back(SBuf(Ssl::GetErrorName(data->element)));
        data = data->next;
    }
    return sl;
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

