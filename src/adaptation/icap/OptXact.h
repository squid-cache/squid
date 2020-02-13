/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ICAPOPTXACT_H
#define SQUID_ICAPOPTXACT_H

#include "adaptation/icap/Launcher.h"
#include "adaptation/icap/Xaction.h"

namespace Adaptation
{
namespace Icap
{

/* OptXact sends an ICAP OPTIONS request to the ICAP service,
 * parses the ICAP response, and sends it to the initiator. A NULL response
 * means the ICAP service could not be contacted or did not return any
 * valid response. */

class OptXact: public Xaction
{
    CBDATA_CLASS(OptXact);

public:
    OptXact(ServiceRep::Pointer &aService);

protected:
    virtual void start();
    virtual void handleCommConnected();
    virtual void handleCommWrote(size_t size);
    virtual void handleCommRead(size_t size);

    void makeRequest(MemBuf &buf);
    bool parseResponse();

    void startReading();
    virtual bool doneReading() const { return commEof || readAll; }

    virtual void swanSong();

private:
    virtual void finalizeLogInfo();

    bool readAll; ///< read the entire OPTIONS response
};

// An Launcher that stores OptXact construction info and
// creates OptXact when needed
class OptXactLauncher: public Launcher
{
    CBDATA_CLASS(OptXactLauncher);

public:
    OptXactLauncher(Adaptation::ServicePointer aService);

protected:
    virtual Xaction *createXaction();
};

} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_ICAPOPTXACT_H */

