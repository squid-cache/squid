#ifndef SQUID_ADAPTATION__INITIATE_H
#define SQUID_ADAPTATION__INITIATE_H

#include "base/AsyncCall.h"
#include "base/AsyncJob.h"
#include "adaptation/forward.h"

class HttpMsg;

namespace Adaptation
{

/* Initiator holder associtates an initiator with its cbdata. It is used as
 * a temporary hack to make cbdata work with multiple inheritance. We need
 * this hack because we cannot know whether the initiator pointer is still
 * valid without dereferencing it to call toCbdata()
 * TODO: JobDialer uses the same trick. Factor out or move this code. */
class InitiatorHolder
{
public:
    InitiatorHolder(Initiator *anInitiator);
    InitiatorHolder(const InitiatorHolder &anInitiator);
    ~InitiatorHolder();

    void clear();

    // to make comparison with NULL possible
    operator void*() { return prime; }
    bool operator == (void *) const { return prime == NULL; }
    bool operator != (void *) const { return prime != NULL; }
    bool operator !() const { return !prime; }

    bool isThere(); // we have a valid initiator pointer
    Initiator *ptr(); // asserts isThere()
    void *theCbdata() { return cbdata;}

private:
    InitiatorHolder &operator =(const InitiatorHolder &anInitiator);

    Initiator *prime;
    void *cbdata;
};

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
    Initiate(const char *aTypeName, Initiator *anInitiator);
    virtual ~Initiate();

    // communication with the initiator
    virtual void noteInitiatorAborted() = 0;

protected:
    void sendAnswer(HttpMsg *msg); // send to the initiator
    void tellQueryAborted(bool final); // tell initiator
    void clearInitiator(); // used by noteInitiatorAborted; TODO: make private

    virtual void swanSong(); // internal cleanup

    virtual const char *status() const; // for debugging

    InitiatorHolder theInitiator;

private:
    Initiate(const Initiate &); // no definition
    Initiate &operator =(const Initiate &); // no definition
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__INITIATE_H */
