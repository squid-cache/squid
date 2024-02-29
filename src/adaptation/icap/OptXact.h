/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ADAPTATION_ICAP_OPTXACT_H
#define SQUID_SRC_ADAPTATION_ICAP_OPTXACT_H

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
    CBDATA_CHILD(OptXact);

public:
    OptXact(ServiceRep::Pointer &aService);

protected:
    /* Xaction API */
    void start() override;
    void startShoveling() override;
    void handleCommWrote(size_t size) override;
    void handleCommRead(size_t size) override;

    void makeRequest(MemBuf &buf);
    bool parseResponse();

    void startReading();
    bool doneReading() const override { return commEof || readAll; }

    void swanSong() override;

private:
    void finalizeLogInfo() override;

    bool readAll; ///< read the entire OPTIONS response
};

// An Launcher that stores OptXact construction info and
// creates OptXact when needed
class OptXactLauncher: public Launcher
{
    CBDATA_CHILD(OptXactLauncher);

public:
    OptXactLauncher(Adaptation::ServicePointer aService);

protected:
    Xaction *createXaction() override;
};

} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_SRC_ADAPTATION_ICAP_OPTXACT_H */

