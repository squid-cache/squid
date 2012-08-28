#include "squid.h"
#include "comm/Connection.h"
#include "CommCalls.h"
#include "fde.h"
#include "globals.h"

/* CommCommonCbParams */

CommCommonCbParams::CommCommonCbParams(void *aData):
        data(cbdataReference(aData)), conn(), flag(COMM_OK), xerrno(0), fd(-1)
{
}

CommCommonCbParams::CommCommonCbParams(const CommCommonCbParams &p):
        data(cbdataReference(p.data)), conn(p.conn), flag(p.flag), xerrno(p.xerrno), fd(p.fd)
{
}

CommCommonCbParams::~CommCommonCbParams()
{
    cbdataReferenceDone(data);
}

void
CommCommonCbParams::print(std::ostream &os) const
{
    if (conn != NULL)
        os << conn;
    else
        os << "FD " << fd;

    if (xerrno)
        os << ", errno=" << xerrno;
    if (flag != COMM_OK)
        os << ", flag=" << flag;
    if (data)
        os << ", data=" << data;
}

/* CommAcceptCbParams */

CommAcceptCbParams::CommAcceptCbParams(void *aData):
        CommCommonCbParams(aData)
{
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
        debugs(5, 3, HERE << "dropping late connect call: FD " << fd);
        return false;
    }
    return true; // now we are in sync and can handle the call
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
    if ((conn->fd < 0 || fd_table[conn->fd].closing()) && flag != COMM_ERR_CLOSING) {
        debugs(5, 3, HERE << "converting late call to COMM_ERR_CLOSING: " << conn);
        flag = COMM_ERR_CLOSING;
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

/* FdeCbParams */

FdeCbParams::FdeCbParams(void *aData):
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

CommAcceptCbPtrFun::CommAcceptCbPtrFun(const CommAcceptCbPtrFun &o):
        CommDialerParamsT<CommAcceptCbParams>(o.params),
        handler(o.handler)
{
}

void
CommAcceptCbPtrFun::dial()
{
    handler(params);
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
    handler(params.conn, params.flag, params.xerrno, params.data);
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
    handler(params.conn, params.buf, params.size, params.flag, params.xerrno, params.data);
}

void
CommIoCbPtrFun::print(std::ostream &os) const
{
    os << '(';
    params.print(os);
    os << ')';
}

/* CommCloseCbPtrFun */

CommCloseCbPtrFun::CommCloseCbPtrFun(CLCB *aHandler,
                                     const CommCloseCbParams &aParams):
        CommDialerParamsT<CommCloseCbParams>(aParams),
        handler(aHandler)
{
}

void
CommCloseCbPtrFun::dial()
{
    handler(params);
}

void
CommCloseCbPtrFun::print(std::ostream &os) const
{
    os << '(';
    params.print(os);
    os << ')';
}

/* CommTimeoutCbPtrFun */

CommTimeoutCbPtrFun::CommTimeoutCbPtrFun(CTCB *aHandler,
        const CommTimeoutCbParams &aParams):
        CommDialerParamsT<CommTimeoutCbParams>(aParams),
        handler(aHandler)
{
}

void
CommTimeoutCbPtrFun::dial()
{
    handler(params);
}

void
CommTimeoutCbPtrFun::print(std::ostream &os) const
{
    os << '(';
    params.print(os);
    os << ')';
}

/* FdeCbPtrFun */

FdeCbPtrFun::FdeCbPtrFun(FDECB *aHandler, const FdeCbParams &aParams) :
        CommDialerParamsT<FdeCbParams>(aParams),
        handler(aHandler)
{
}

void
FdeCbPtrFun::dial()
{
    handler(params);
}

void
FdeCbPtrFun::print(std::ostream &os) const
{
    os << '(';
    params.print(os);
    os << ')';
}
