#ifndef SQUID_COMMCALLS_H
#define SQUID_COMMCALLS_H

#include "base/AsyncCall.h"
#include "base/AsyncJobCalls.h"
#include "comm_err_t.h"
#include "comm/forward.h"

/* CommCalls implement AsyncCall interface for comm_* callbacks.
 * The classes cover two call dialer kinds:
 *     - A C-style call using a function pointer (depricated);
 *     - A C++-style call to an AsyncJob child.
 * and several comm_* callback kinds:
 *     - accept (IOACB)
 *     - connect (CNCB)
 *     - I/O (IOCB)
 *     - timeout (CTCB)
 *     - close (CLCB)
 * and a special callback kind for passing pipe FD, disk FD or fd_table index 'FD' to the handler:
 *     - FD passing callback (FDECB)
 */

class CommAcceptCbParams;
typedef void IOACB(const CommAcceptCbParams &params);

typedef void CNCB(const Comm::ConnectionPointer &conn, comm_err_t status, int xerrno, void *data);
typedef void IOCB(const Comm::ConnectionPointer &conn, char *, size_t size, comm_err_t flag, int xerrno, void *data);

class CommTimeoutCbParams;
typedef void CTCB(const CommTimeoutCbParams &params);

class CommCloseCbParams;
typedef void CLCB(const CommCloseCbParams &params);

class FdeCbParams;
typedef void FDECB(const FdeCbParams &params);

/*
 * TODO: When there are no function-pointer-based callbacks left, all
 * this complexity can be removed. Jobs that need comm services will just
 * implement CommReader, CommWriter, etc. interfaces and receive calls
 * using general (not comm-specific) AsyncCall code. For now, we have to
 * allow the caller to create a callback that comm can modify to set
 * parameters, which is not trivial when the caller type/kind is not
 * known to comm and there are many kinds of parameters.
 */

/* Comm*CbParams classes below handle callback parameters */

// Maintains parameters common to all comm callbacks
class CommCommonCbParams
{
public:
    CommCommonCbParams(void *aData);
    CommCommonCbParams(const CommCommonCbParams &params);
    ~CommCommonCbParams();

    /// adjust using the current Comm state; returns false to cancel the call
    // not virtual because callers know dialer type
    bool syncWithComm() { return true; }

    void print(std::ostream &os) const;

public:
    void *data; // cbdata-protected

    /** The connection which this call pertains to.
     * \itemize On accept() calls this is the new client connection.
     * \itemize On connect() finished calls this is the newely opened connection.
     * \itemize On write calls this is the connection just written to.
     * \itemize On read calls this is the connection just read from.
     * \itemize On close calls this describes the connection which is now closed.
     * \itemize On timeouts this is the connection whose operation timed out.
     *          NP: timeouts might also return to the connect/read/write handler with COMM_ERR_TIMEOUT.
     */
    Comm::ConnectionPointer conn;

    comm_err_t flag;  ///< comm layer result status.
    int xerrno;      ///< The last errno to occur. non-zero if flag is COMM_ERR.

    int fd; ///< FD which the call was about. Set by the async call creator.
private:
    // should not be needed and not yet implemented
    CommCommonCbParams &operator =(const CommCommonCbParams &params);
};

// accept parameters
class CommAcceptCbParams: public CommCommonCbParams
{
public:
    CommAcceptCbParams(void *aData);
};

// connect parameters
class CommConnectCbParams: public CommCommonCbParams
{
public:
    CommConnectCbParams(void *aData);

    bool syncWithComm(); // see CommCommonCbParams::syncWithComm
};

// read/write (I/O) parameters
class CommIoCbParams: public CommCommonCbParams
{
public:
    CommIoCbParams(void *aData);

    void print(std::ostream &os) const;
    bool syncWithComm(); // see CommCommonCbParams::syncWithComm

public:
    char *buf;
    size_t size;
};

// close parameters
class CommCloseCbParams: public CommCommonCbParams
{
public:
    CommCloseCbParams(void *aData);
};

class CommTimeoutCbParams: public  CommCommonCbParams
{
public:
    CommTimeoutCbParams(void *aData);
};

/// Special Calls parameter, for direct use of an FD without a controlling Comm::Connection
/// This is used for pipe() FD with helpers, and internally by Comm when handling some special FD actions.
class FdeCbParams: public CommCommonCbParams
{
public:
    FdeCbParams(void *aData);
    // TODO make this a standalone object with FD value and pointer to fde table entry.
    // that requires all the existing Comm handlers to be updated first though
};

// Interface to expose comm callback parameters of all comm dialers.
// GetCommParams() uses this interface to access comm parameters.
template <class Params_>
class CommDialerParamsT
{
public:
    typedef Params_ Params;
    CommDialerParamsT(const Params &io): params(io) {}

public:
    Params params;
};

// Get comm params of an async comm call
template <class Params>
Params &GetCommParams(AsyncCall::Pointer &call)
{
    typedef CommDialerParamsT<Params> DialerParams;
    DialerParams *dp = dynamic_cast<DialerParams*>(call->getDialer());
    assert(dp);
    return dp->params;
}

// All job dialers with comm parameters are merged into one since they
// all have exactly one callback argument and differ in Params type only
template <class C, class Params_>
class CommCbMemFunT: public JobDialer<C>, public CommDialerParamsT<Params_>
{
public:
    typedef Params_ Params;
    typedef void (C::*Method)(const Params &io);

    CommCbMemFunT(const CbcPointer<C> &job, Method meth): JobDialer<C>(job),
            CommDialerParamsT<Params_>(job.get()),
            method(meth) {}

    virtual bool canDial(AsyncCall &c) {
        return JobDialer<C>::canDial(c) &&
               this->params.syncWithComm();
    }

    virtual void print(std::ostream &os) const {
        os << '(';
        this->params.print(os);
        os << ')';
    }

public:
    Method method;

protected:
    virtual void doDial() { ((&(*this->job))->*method)(this->params); }
};

// accept (IOACB) dialer
class CommAcceptCbPtrFun: public CallDialer,
        public CommDialerParamsT<CommAcceptCbParams>
{
public:
    typedef CommAcceptCbParams Params;
    typedef RefCount<CommAcceptCbPtrFun> Pointer;

    CommAcceptCbPtrFun(IOACB *aHandler, const CommAcceptCbParams &aParams);
    CommAcceptCbPtrFun(const CommAcceptCbPtrFun &o);

    void dial();

    virtual void print(std::ostream &os) const;

public:
    IOACB *handler;
};

// connect (CNCB) dialer
class CommConnectCbPtrFun: public CallDialer,
        public CommDialerParamsT<CommConnectCbParams>
{
public:
    typedef CommConnectCbParams Params;

    CommConnectCbPtrFun(CNCB *aHandler, const Params &aParams);
    void dial();

    virtual void print(std::ostream &os) const;

public:
    CNCB *handler;
};

// read/write (IOCB) dialer
class CommIoCbPtrFun: public CallDialer,
        public CommDialerParamsT<CommIoCbParams>
{
public:
    typedef CommIoCbParams Params;

    CommIoCbPtrFun(IOCB *aHandler, const Params &aParams);
    void dial();

    virtual void print(std::ostream &os) const;

public:
    IOCB *handler;
};

// close (CLCB) dialer
class CommCloseCbPtrFun: public CallDialer,
        public CommDialerParamsT<CommCloseCbParams>
{
public:
    typedef CommCloseCbParams Params;

    CommCloseCbPtrFun(CLCB *aHandler, const Params &aParams);
    void dial();

    virtual void print(std::ostream &os) const;

public:
    CLCB *handler;
};

class CommTimeoutCbPtrFun:public CallDialer,
        public CommDialerParamsT<CommTimeoutCbParams>
{
public:
    typedef CommTimeoutCbParams Params;

    CommTimeoutCbPtrFun(CTCB *aHandler, const Params &aParams);
    void dial();

    virtual void print(std::ostream &os) const;

public:
    CTCB *handler;
};

/// FD event (FDECB) dialer
class FdeCbPtrFun: public CallDialer,
        public CommDialerParamsT<FdeCbParams>
{
public:
    typedef FdeCbParams Params;

    FdeCbPtrFun(FDECB *aHandler, const Params &aParams);
    void dial();
    virtual void print(std::ostream &os) const;

public:
    FDECB *handler;
};

// AsyncCall to comm handlers implemented as global functions.
// The dialer is one of the Comm*CbPtrFunT above
// TODO: Get rid of this class by moving canFire() to canDial() method
// of dialers.
template <class Dialer>
class CommCbFunPtrCallT: public AsyncCall
{
public:
    typedef RefCount<CommCbFunPtrCallT<Dialer> > Pointer;
    typedef typename Dialer::Params Params;

    inline CommCbFunPtrCallT(int debugSection, int debugLevel,
                             const char *callName, const Dialer &aDialer);

    inline CommCbFunPtrCallT(const CommCbFunPtrCallT &o) :
            AsyncCall(o.debugSection, o.debugLevel, o.name),
            dialer(o.dialer) {}

    ~CommCbFunPtrCallT() {}

    virtual CallDialer* getDialer() { return &dialer; }

public:
    Dialer dialer;

protected:
    inline virtual bool canFire();
    inline virtual void fire();

private:
    CommCbFunPtrCallT & operator=(const CommCbFunPtrCallT &); // not defined. not permitted.
};

// Conveninece wrapper: It is often easier to call a templated function than
// to create a templated class.
template <class Dialer>
inline
CommCbFunPtrCallT<Dialer> *commCbCall(int debugSection, int debugLevel,
                                      const char *callName, const Dialer &dialer)
{
    return new CommCbFunPtrCallT<Dialer>(debugSection, debugLevel, callName,
                                         dialer);
}

/* inlined implementation of templated methods */

/* CommCbFunPtrCallT */

template <class Dialer>
CommCbFunPtrCallT<Dialer>::CommCbFunPtrCallT(int aDebugSection, int aDebugLevel,
        const char *callName, const Dialer &aDialer):
        AsyncCall(aDebugSection, aDebugLevel, callName),
        dialer(aDialer)
{
}

template <class Dialer>
bool
CommCbFunPtrCallT<Dialer>::canFire()
{
    if (!AsyncCall::canFire())
        return false;

    if (!cbdataReferenceValid(dialer.params.data))
        return cancel("callee gone");

    if (!dialer.params.syncWithComm())
        return cancel("out of sync w/comm");

    if (!dialer.handler)
        return cancel("no callback requested");

    return true;
}

template <class Dialer>
void
CommCbFunPtrCallT<Dialer>::fire()
{
    dialer.dial();
}

#endif /* SQUID_COMMCALLS_H */
