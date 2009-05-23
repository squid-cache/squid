/*
 * $Id$
 */

#include "squid.h"
#include "acl/SslErrorData.h"
#include "acl/Checklist.h"
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
ACLSslErrorData::match(ssl_error_t toFind)
{
    return values->findAndTune (toFind);
}

/* explicit instantiation required for some systems */
/** \cond AUTODOCS-IGNORE */
// AYJ: 2009-05-20 : Removing. clashes with template <int> instantiation for other ACLs.
// template cbdata_type CbDataList<ssl_error_t>::CBDATA_CbDataList;
/** \endcond */

wordlist *
ACLSslErrorData::dump()
{
    wordlist *W = NULL;
    CbDataList<ssl_error_t> *data = values;

    while (data != NULL) {
        wordlistAdd(&W, sslFindErrorString(data->element));
        data = data->next;
    }

    return W;
}

void
ACLSslErrorData::parse()
{
    CbDataList<ssl_error_t> **Tail;
    char *t = NULL;

    for (Tail = &values; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
        CbDataList<ssl_error_t> *q = new CbDataList<ssl_error_t>(sslParseErrorString(t));
        *(Tail) = q;
        Tail = &q->next;
    }
}

bool
ACLSslErrorData::empty() const
{
    return values == NULL;
}

ACLData<ssl_error_t> *
ACLSslErrorData::clone() const
{
    /* Splay trees don't clone yet. */
    assert (!values);
    return new ACLSslErrorData(*this);
}
