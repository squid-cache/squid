
/*
 * $Id$
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
 */

#ifndef SQUID_ICAPOPTIONS_H
#define SQUID_ICAPOPTIONS_H

#include "squid.h"
#include "adaptation/icap/ServiceRep.h"

class wordlist;

namespace Adaptation
{
namespace Icap
{

/* Maintains options supported by a given ICAP service.
 * See RFC 3507, Section "4.10.2 OPTIONS Response". */

class Options
{

public:
    typedef void GetCallback(void *data, Options *options);
    static void Get(ServiceRep::Pointer &service, GetCallback *cb, void *data);

public:
    Options();
    ~Options();

    void configure(const HttpReply *reply);

    bool valid() const;
    bool fresh() const;
    int ttl() const;
    time_t expire() const;
    time_t timestamp() const { return theTimestamp; };

    typedef enum { xferNone, xferPreview, xferIgnore, xferComplete } TransferKind;
    TransferKind transferKind(const String &urlPath) const;

public:
    const char *error; // human-readable information; set iff !valid()

    // ICAP server MUST supply this info
    Vector<ICAP::Method> methods;
    String istag;

    // ICAP server MAY supply this info. If not, Squid supplies defaults.
    String service;
    String serviceId;
    int max_connections;
    bool allow204;
    int preview;

protected:
    // Transfer-* extension list representation
    // maintains wordlist and does parsing/matching
    class TransferList
    {
    public:
        TransferList();
        ~TransferList();

        bool matches(const String &urlPath) const;

        void parse(const String &buf, bool &foundStar);
        void add(const char *extension);
        void report(int level, const char *prefix) const;

    public:
        wordlist *extensions; // TODO: optimize with a hash of some sort
        const char *name;  // header name, mostly for debugging
        TransferKind kind; // to simplify caller's life
    };

    // varios Transfer-* lists
    struct Transfers {
        TransferList preview;
        TransferList ignore;
        TransferList complete;
        TransferList *byDefault;  // Transfer-X that has '*'
    } theTransfers;

    int theTTL;
    time_t theTimestamp;

private:
    void cfgMethod(ICAP::Method m);
    void cfgIntHeader(const HttpHeader *h, const char *fname, int &value);
    void cfgTransferList(const HttpHeader *h, TransferList &l);
};




} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_ICAPOPTIONS_H */
