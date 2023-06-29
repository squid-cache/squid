/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
    ~ACLHTTPHeaderData() override;
    bool match(HttpHeader* hdr) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override;

private:
    /* ACLData API */
    const Acl::Options &lineOptions() override;

    Http::HdrType hdrId;            /**< set if header is known */
    SBuf hdrName;                   /**< always set */
    ACLData<char const *> * regex_rule;
};

#endif /* SQUID_ACLHTTPHEADERDATA_H */

