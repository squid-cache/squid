/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/MethodData.h"
#include "cache_cf.h"
#include "HttpRequestMethod.h"

int ACLMethodData::ThePurgeCount = 0;

ACLMethodData::ACLMethodData() : values (NULL)
{}

ACLMethodData::ACLMethodData(ACLMethodData const &old) : values (NULL)
{
    assert (!old.values);
}

ACLMethodData::~ACLMethodData()
{
    if (values)
        delete values;
}

/// todo make this a pass-by-reference now that HTTPRequestMethods a full class?
bool
ACLMethodData::match(HttpRequestMethod toFind)
{
    return values->findAndTune(toFind);
}

/* explicit instantiation required for some systems */

/// \cond AUTODOCS_IGNORE
template cbdata_type CbDataList<HttpRequestMethod>::CBDATA_CbDataList;
/// \endcond

SBufList
ACLMethodData::dump() const
{
    SBufList sl;
    CbDataList<HttpRequestMethod> *data = values;

    while (data != NULL) {
        sl.push_back(data->element.image());
        data = data->next;
    }

    return sl;
}

void
ACLMethodData::parse()
{
    CbDataList<HttpRequestMethod> **Tail;
    char *t = NULL;

    for (Tail = &values; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
        CbDataList<HttpRequestMethod> *q = new CbDataList<HttpRequestMethod> (HttpRequestMethod(t, NULL));
        if (q->element == Http::METHOD_PURGE)
            ++ThePurgeCount; // configuration code wants to know
        *(Tail) = q;
        Tail = &q->next;
    }
}

bool
ACLMethodData::empty() const
{
    return values == NULL;
}

ACLData<HttpRequestMethod> *
ACLMethodData::clone() const
{
    assert (!values);
    return new ACLMethodData(*this);
}

