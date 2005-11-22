
/*
 * $Id: ICAPOptions.h,v 1.1 2005/11/21 23:32:59 wessels Exp $
 *
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
 *  sinks; see the CREDITS file for full details.
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
 */

#ifndef SQUID_ICAPOPTIONS_H
#define SQUID_ICAPOPTIONS_H

#include "squid.h"
#include "List.h"
#include "ICAPClient.h"

/* Maintains options supported by a given ICAP service.
 * See RFC 3507, Section "4.10.2 OPTIONS Response". */

class ICAPOptions
{

public:
    typedef void GetCallback(void *data, ICAPOptions *options);
    static void Get(ICAPServiceRep::Pointer &service, GetCallback *cb, void *data);

public:
    ICAPOptions();
    ~ICAPOptions();

    void configure(const HttpReply *reply);

    bool valid() const;
    bool fresh() const;
    time_t expire() const;

    typedef enum { TRANSFER_NONE, TRANSFER_PREVIEW, TRANSFER_IGNORE, TRANSFER_COMPLETE } transfer_type;
    transfer_type getTransferExt(const char *);

public:
    const char *error; // human-readable information; set iff !valid()

    // ICAP server MUST supply this info
    ICAP::Method method;
    String istag;

    // ICAP server MAY supply this info. If not, Squid supplies defaults.
    String service;
    String serviceId;
    int max_connections;
    bool allow204;
    int preview;

    // varios Transfer-* lists

    struct Transfers
    {
        List<String> *preview;
        List<String> *ignore;
        List<String> *complete;
        transfer_type other; // default X from Transfer-X: *
    }

    transfers;

protected:
    int ttl;
    time_t timestamp;

    //  The list of pairs "file extension <-> transfer type"

    struct TransferPair
    {
        char *ext;
        transfer_type type;
    };

    List<TransferPair> *transfer_ext;

private:
    void cfgMethod(ICAP::Method m);
    void cfgIntHeader(const HttpHeader *h, const char *fname, int &value);
};



#endif /* SQUID_ICAPOPTIONS_H */
