/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ICAPOPTIONS_H
#define SQUID_ICAPOPTIONS_H

#include "adaptation/icap/ServiceRep.h"

class HttpHeader;
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
    TransferKind transferKind(const SBuf &urlPath) const;

public:
    const char *error; // human-readable information; set iff !valid()

    // ICAP server MUST supply this info
    std::vector<ICAP::Method> methods;
    String istag;

    // ICAP server MAY supply this info. If not, Squid supplies defaults.
    String service;
    String serviceId;
    int max_connections;
    bool allow204;
    bool allow206;
    int preview;

protected:
    // Transfer-* extension list representation
    // maintains wordlist and does parsing/matching
    class TransferList
    {
    public:
        TransferList();
        ~TransferList();

        bool matches(const SBuf &urlPath) const;

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

