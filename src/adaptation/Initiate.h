/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ADAPTATION_INITIATE_H
#define SQUID_SRC_ADAPTATION_INITIATE_H

#include "adaptation/forward.h"
#include "base/AsyncJob.h"
#include "base/CbcPointer.h"

namespace Adaptation
{

/*
 * The  Initiate is a common base for  queries or transactions
 * initiated by an Initiator. This interface exists to allow an
 * initiator to signal its "initiatees" that it is aborting and no longer
 * expecting an answer. The class is also handy for implementing common
 * initiate actions such as maintaining and notifying the initiator.
 *
 * Initiate implementations must cbdata-protect themselves.
 *
 * This class could have been named Initiatee.
 */
class Initiate: virtual public AsyncJob
{

public:
    Initiate(const char *aTypeName);
    ~Initiate() override;

    void initiator(const CbcPointer<Initiator> &i); ///< sets initiator

    // communication with the initiator
    virtual void noteInitiatorAborted() = 0;

protected:
    void sendAnswer(const Answer &answer); // send to the initiator
    void tellQueryAborted(bool final); // tell initiator
    void clearInitiator(); // used by noteInitiatorAborted; TODO: make private

    void swanSong() override; // internal cleanup

    const char *status() const override; // for debugging

    CbcPointer<Initiator> theInitiator;

private:
    Initiate(const Initiate &); // no definition
    Initiate &operator =(const Initiate &); // no definition
};

} // namespace Adaptation

#endif /* SQUID_SRC_ADAPTATION_INITIATE_H */

