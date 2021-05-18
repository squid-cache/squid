/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLHTTPHEADERDATA_H
#define SQUID_ACLHTTPHEADERDATA_H

#include "acl/Data.h"
#include "HttpHeader.h"
#include "sbuf/SBuf.h"
#include "SquidString.h"

class ACLHTTPHeaderData : public ACLData<HttpHeader*>
{
    MEMPROXY_CLASS(ACLHTTPHeaderData);

public:
    ACLHTTPHeaderData();
    virtual ~ACLHTTPHeaderData();
    virtual bool match(HttpHeader* hdr);
    virtual SBufList dump() const;
    virtual void parse();
    virtual bool empty() const;
    virtual ACLData<HttpHeader*> *clone() const;

private:
    Http::HdrType hdrId;            /**< set if header is known */
    SBuf hdrName;                   /**< always set */
    ACLData<char const *> * regex_rule;
};

#endif /* SQUID_ACLHTTPHEADERDATA_H */

