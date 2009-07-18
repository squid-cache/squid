#include "squid.h"
#include "fde.h"
#include "CommCalls.h"

/* CommCommonCbParams */

CommCommonCbParams::CommCommonCbParams(void *aData):
        data(cbdataReference(aData)), fd(-1), xerrno(0), flag(COMM_OK)
{
}

CommCommonCbParams::CommCommonCbParams(const CommCommonCbParams &p):
        data(cbdataReference(p.data)), fd(p.fd), xerrno(p.xerrno), flag(p.flag)
{
}

CommCommonCbParams::~CommCommonCbParams()
{
    cbdataReferenceDone(data);
}

void
CommCommonCbParams::print(std::ostream &os) const
{
    os << "FD " << fd;
    if (xerrno)
        os << ", errno=" << xerrno;
    if (flag != COMM_OK)
        os << ", flag=" << flag;
    if (data)
        os << ", data=" << data;
}


/* CommAcceptCbParams */

CommAcceptCbParams::CommAcceptCbParams(void *aData): CommCommonCbParams(aData),
        nfd(-1)
{
}

void
CommAcceptCbParams::print(std::ostream &os) const
{
    CommCommonCbParams::print(os);
    if (nfd >= 0)
        os << ", newFD " << nfd;
}


/* CommConnectCbParams */

CommConnectCbParams::CommConnectCbParams(void *aData):
        CommCommonCbParams(aData)
{
}

bool
CommConnectCbParams::syncWithComm()
{
    // drop the call if the call was scheduled before comm_close but
    // is being fired after comm_close
    if (fd >= 0 && fd_table[fd].closing()) {
        debugs(5, 3, HERE << "droppin late connect call: FD " << fd);
        return false;
    }
    return true; // now we are in sync and can handle the call
}

void
CommConnectCbParams::print(std::ostream &os) const
{
    CommCommonCbParams::print(os);
    os << ", " << dns;
}

/* CommIoCbParams */

CommIoCbParams::CommIoCbParams(void *aData): CommCommonCbParams(aData),
        buf(NULL), size(0)
{
}

bool
CommIoCbParams::syncWithComm()
{
    // change parameters if the call was scheduled before comm_close but
    // is being fired after comm_close
    if (fd >= 0 && fd_table[fd].closing() && flag != COMM_ERR_CLOSING) {
        debugs(5, 3, HERE << "converting late call to COMM_ERR_CLOSING: FD " << fd);
        flag = COMM_ERR_CLOSING;
        size = 0;
    }
    return true; // now we are in sync and can handle the call
}


void
CommIoCbParams::print(std::ostream &os) const
{
    CommCommonCbParams::print(os);
    if (buf) {
        os << ", size=" << size;
        os << ", buf=" << (void*)buf;
    }
}


/* CommCloseCbParams */

CommCloseCbParams::CommCloseCbParams(void *aData):
        CommCommonCbParams(aData)
{
}

/* CommTimeoutCbParams */

CommTimeoutCbParams::CommTimeoutCbParams(void *aData):
        CommCommonCbParams(aData)
{
}


/* CommAcceptCbPtrFun */

CommAcceptCbPtrFun::CommAcceptCbPtrFun(IOACB *aHandler,
                                       const CommAcceptCbParams &aParams):
        CommDialerParamsT<CommAcceptCbParams>(aParams),
        handler(aHandler)
{
}

void
CommAcceptCbPtrFun::dial()
{
    handler(params.fd, params.nfd, &params.details, params.flag, params.xerrno, params.data);
}

void
CommAcceptCbPtrFun::print(std::ostream &os) const
{
    os << '(';
    params.print(os);
    os << ')';
}


/* CommConnectCbPtrFun */

CommConnectCbPtrFun::CommConnectCbPtrFun(CNCB *aHandler,
        const CommConnectCbParams &aParams):
        CommDialerParamsT<CommConnectCbParams>(aParams),
        handler(aHandler)
{
}

void
CommConnectCbPtrFun::dial()
{
    handler(params.fd, params.dns, params.flag, params.xerrno, params.data);
}

void
CommConnectCbPtrFun::print(std::ostream &os) const
{
    os << '(';
    params.print(os);
    os << ')';
}


/* CommIoCbPtrFun */

CommIoCbPtrFun::CommIoCbPtrFun(IOCB *aHandler, const CommIoCbParams &aParams):
        CommDialerParamsT<CommIoCbParams>(aParams),
        handler(aHandler)
{
}

void
CommIoCbPtrFun::dial()
{
    handler(params.fd, params.buf, params.size, params.flag, params.xerrno, params.data);
}

void
CommIoCbPtrFun::print(std::ostream &os) const
{
    os << '(';
    params.print(os);
    os << ')';
}


/* CommCloseCbPtrFun */

CommCloseCbPtrFun::CommCloseCbPtrFun(PF *aHandler,
                                     const CommCloseCbParams &aParams):
        CommDialerParamsT<CommCloseCbParams>(aParams),
        handler(aHandler)
{
}

void
CommCloseCbPtrFun::dial()
{
    handler(params.fd, params.data);
}

void
CommCloseCbPtrFun::print(std::ostream &os) const
{
    os << '(';
    params.print(os);
    os << ')';
}

/* CommTimeoutCbPtrFun */

CommTimeoutCbPtrFun::CommTimeoutCbPtrFun(PF *aHandler,
        const CommTimeoutCbParams &aParams):
        CommDialerParamsT<CommTimeoutCbParams>(aParams),
        handler(aHandler)
{
}

void
CommTimeoutCbPtrFun::dial()
{
    handler(params.fd, params.data);
}

void
CommTimeoutCbPtrFun::print(std::ostream &os) const
{
    os << '(';
    params.print(os);
    os << ')';
}
