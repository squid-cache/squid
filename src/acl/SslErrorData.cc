/*
 * $Id$
 */

#include "squid-old.h"
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
