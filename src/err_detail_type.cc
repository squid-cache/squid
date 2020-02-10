#include "squid.h"
#include "err_detail_type.h"
#include "err_detail_type.cci"
#include "HttpRequest.h"

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
