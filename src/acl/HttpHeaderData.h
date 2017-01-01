/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLHTTPHEADERDATA_H
#define SQUID_ACLHTTPHEADERDATA_H

class HttpHeader;
class wordlist;

/* becaue we inherit from it */
#include "acl/Data.h"
/* for String field */
#include "SquidString.h"
/* for http_hdr_type field */
#include "HttpHeader.h"
/* because weuse its MEMPROXY_CLASS() macros */
#include "MemPool.h"

/// \ingroup ACLAPI
class ACLHTTPHeaderData : public ACLData<HttpHeader*>
{

public:
    MEMPROXY_CLASS(ACLHTTPHeaderData);

    ACLHTTPHeaderData();
    virtual ~ACLHTTPHeaderData();
    virtual bool match(HttpHeader* hdr);
    virtual SBufList dump() const;
    virtual void parse();
    virtual bool empty() const;
    virtual ACLData<HttpHeader*> *clone() const;

private:
    http_hdr_type hdrId;                /**< set if header is known */
    String hdrName;                     /**< always set */
    ACLData<char const *> * regex_rule;
};

MEMPROXY_CLASS_INLINE(ACLHTTPHeaderData);

#endif /* SQUID_ACLHTTPHEADERDATA_H */

