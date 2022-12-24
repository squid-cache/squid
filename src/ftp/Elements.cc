/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 09    File Transfer Protocol (FTP) */

#include "squid.h"
#include "ftp/Elements.h"
#include "HttpHdrCc.h"
#include "HttpReply.h"
#include "sbuf/SBuf.h"

// FTP does not have a notion of a "protocol version" but we need something for
// compatibility with the current Http::Message wrapping layer. We use version 1.1:
// * some ICAP services probably expect /1.0 or /1.1 when parsing HTTP headers;
// * FTP commands are sent on a "persistent by default" connection, just like
//   HTTP/1.1. Using 1.1 leads to fewer exceptions in current code shared by
//   HTTP and FTP.
AnyP::ProtocolVersion
Ftp::ProtocolVersion()
{
    return AnyP::ProtocolVersion(AnyP::PROTO_FTP, 1, 1);
}

HttpReply *
Ftp::HttpReplyWrapper(const int ftpStatus, const char *ftpReason, const Http::StatusCode httpStatus, const int64_t clen)
{
    HttpReply *const reply = new HttpReply;

    AnyP::ProtocolVersion httpVersion = Http::ProtocolVersion(
                                            Ftp::ProtocolVersion().major, Ftp::ProtocolVersion().minor);
    reply->sline.set(httpVersion, httpStatus);

    HttpHeader &header = reply->header;
    header.putTime(Http::HdrType::DATE, squid_curtime);
    {
        HttpHdrCc cc;
        cc.Private(String());
        header.putCc(&cc);
    }
    if (ftpStatus > 0)
        header.putInt(Http::HdrType::FTP_STATUS, ftpStatus);
    if (ftpReason)
        header.putStr(Http::HdrType::FTP_REASON, ftpReason);
    if (clen >= 0)
        header.putInt64(Http::HdrType::CONTENT_LENGTH, clen);
    reply->hdrCacheInit();
    return reply;
}

const SBuf &
Ftp::cmdAppe()
{
    static const SBuf cmd("APPE");
    return cmd;
}

const SBuf &
Ftp::cmdAuth()
{
    static const SBuf cmd("AUTH");
    return cmd;
}

const SBuf &
Ftp::cmdCwd()
{
    static const SBuf cmd("CWD");
    return cmd;
}

const SBuf &
Ftp::cmdDele()
{
    static const SBuf cmd("DELE");
    return cmd;
}

const SBuf &
Ftp::cmdEprt()
{
    static const SBuf cmd("EPRT");
    return cmd;
}

const SBuf &
Ftp::cmdEpsv()
{
    static const SBuf cmd("EPSV");
    return cmd;
}

const SBuf &
Ftp::cmdList()
{
    static const SBuf cmd("LIST");
    return cmd;
}

const SBuf &
Ftp::cmdMkd()
{
    static const SBuf cmd("MKD");
    return cmd;
}

const SBuf &
Ftp::cmdMlsd()
{
    static const SBuf cmd("MLSD");
    return cmd;
}

const SBuf &
Ftp::cmdMlst()
{
    static const SBuf cmd("MLST");
    return cmd;
}

const SBuf &
Ftp::cmdNlst()
{
    static const SBuf cmd("NLST");
    return cmd;
}

const SBuf &
Ftp::cmdRetr()
{
    static const SBuf cmd("RETR");
    return cmd;
}

const SBuf &
Ftp::cmdRmd()
{
    static const SBuf cmd("RMD");
    return cmd;
}

const SBuf &
Ftp::cmdRnfr()
{
    static const SBuf cmd("RNFR");
    return cmd;
}

const SBuf &
Ftp::cmdRnto()
{
    static const SBuf cmd("RNTO");
    return cmd;
}

const SBuf &
Ftp::cmdSmnt()
{
    static const SBuf cmd("SMNT");
    return cmd;
}

const SBuf &
Ftp::cmdStat()
{
    static const SBuf cmd("STAT");
    return cmd;
}

const SBuf &
Ftp::cmdStor()
{
    static const SBuf cmd("STOR");
    return cmd;
}

const SBuf &
Ftp::cmdStou()
{
    static const SBuf cmd("STOU");
    return cmd;
}

const SBuf &
Ftp::cmdUser()
{
    static const SBuf cmd("USER");
    return cmd;
}

