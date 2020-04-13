#include "squid.h"
#include "err_detail_type.h"
#include "err_detail_type.cci"
#include "HttpRequest.h"

const ErrorDetail::Pointer ERR_DETAIL_NONE = nullptr;
const ErrorDetail::Pointer ERR_DETAIL_REDIRECTOR_TIMEDOUT = new ErrorDetail(ERROR_DETAIL_REDIRECTOR_TIMEDOUT);
const ErrorDetail::Pointer ERR_DETAIL_CLT_REQMOD_ABORT = new ErrorDetail(ERROR_DETAIL_CLT_REQMOD_ABORT);
const ErrorDetail::Pointer ERR_DETAIL_CLT_REQMOD_REQ_BODY = new ErrorDetail(ERROR_DETAIL_CLT_REQMOD_REQ_BODY);
const ErrorDetail::Pointer ERR_DETAIL_CLT_REQMOD_RESP_BODY = new ErrorDetail(ERROR_DETAIL_CLT_REQMOD_RESP_BODY);
const ErrorDetail::Pointer ERR_DETAIL_SRV_REQMOD_REQ_BODY = new ErrorDetail(ERROR_DETAIL_SRV_REQMOD_REQ_BODY);
const ErrorDetail::Pointer ERR_DETAIL_ICAP_RESPMOD_EARLY = new ErrorDetail(ERROR_DETAIL_ICAP_RESPMOD_EARLY);
const ErrorDetail::Pointer ERR_DETAIL_ICAP_RESPMOD_LATE = new ErrorDetail(ERROR_DETAIL_ICAP_RESPMOD_LATE);
const ErrorDetail::Pointer ERR_DETAIL_REQMOD_BLOCK = new ErrorDetail(ERROR_DETAIL_REQMOD_BLOCK);
const ErrorDetail::Pointer ERR_DETAIL_RESPMOD_BLOCK_EARLY = new ErrorDetail(ERROR_DETAIL_RESPMOD_BLOCK_EARLY);
const ErrorDetail::Pointer ERR_DETAIL_RESPMOD_BLOCK_LATE = new ErrorDetail(ERROR_DETAIL_RESPMOD_BLOCK_LATE);
const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_START = new ErrorDetail(ERROR_DETAIL_ICAP_XACT_START);
const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_SSL_START = new ErrorDetail(ERROR_DETAIL_ICAP_XACT_SSL_START);
const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_BODY_CONSUMER_ABORT = new ErrorDetail(ERROR_DETAIL_ICAP_XACT_BODY_CONSUMER_ABORT);
const ErrorDetail::Pointer ERR_DETAIL_ICAP_INIT_GONE = new ErrorDetail(ERROR_DETAIL_ICAP_INIT_GONE);
const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_CLOSE = new ErrorDetail(ERROR_DETAIL_ICAP_XACT_CLOSE);
const ErrorDetail::Pointer ERR_DETAIL_ICAP_XACT_OTHER = new ErrorDetail(ERROR_DETAIL_ICAP_XACT_OTHER);
const ErrorDetail::Pointer ERR_DETAIL_BUFFER = new ErrorDetail(ERROR_DETAIL_BUFFER);
const ErrorDetail::Pointer ERR_DETAIL_TUNNEL_ON_ERROR = new ErrorDetail(ERROR_DETAIL_TUNNEL_ON_ERROR);
const ErrorDetail::Pointer ERR_DETAIL_TLS_HELLO_PARSE_ERROR = new ErrorDetail(ERROR_DETAIL_TLS_HELLO_PARSE_ERROR);
const ErrorDetail::Pointer ERR_DETAIL_SSL_BUMP_SPLICE = new ErrorDetail(ERROR_DETAIL_SSL_BUMP_SPLICE);
const ErrorDetail::Pointer ERR_DETAIL_TLS_HANDSHAKE = new ErrorDetail(ERROR_DETAIL_TLS_HANDSHAKE);
const ErrorDetail::Pointer ERR_DETAIL_EXCEPTION_OTHER = new ErrorDetail(ERROR_DETAIL_EXCEPTION_OTHER);
const ErrorDetail::Pointer ERR_DETAIL_EXCEPTION = new ErrorDetail(ERROR_DETAIL_EXCEPTION);
const ErrorDetail::Pointer ERR_DETAIL_FTP_ERROR = new ErrorDetail(ERROR_DETAIL_FTP_ERROR);

const char *
ErrorDetail::logCode()
{
    if (errorDetailId >= ERR_DETAIL_START && errorDetailId < ERR_DETAIL_MAX)
        return err_detail_type_str[errorDetailId-ERR_DETAIL_START+2];

    return "UNKNOWN";
}

const char *
ErrorDetail::detailString(const HttpRequest::Pointer &)
{
    return logCode();
}

const char *
SysErrorDetail::logCode()
{
    static char sbuf[512];
    snprintf(sbuf, sizeof(sbuf), "SYSERR=%d", errorNo);
    return sbuf;
}

const char *
SysErrorDetail::detailString(const HttpRequest::Pointer &)
{
    return strerror(errorNo);
}

const char *
ExceptionErrorDetail::logCode()
{
    static char sbuf[512];
    snprintf(sbuf, sizeof(sbuf), "EXCEPTION=0x%X", exceptionId);
    return sbuf;
}

std::ostream &
operator <<(std::ostream &os, const ErrorDetail &detail)
{
    os << detail.logCode();
    return os;
}

std::ostream &
operator <<(std::ostream &os, const ErrorDetail::Pointer &detail)
{
    if (detail)
        os << *detail;
    else
        os << "[no details]";
    return os;
}
