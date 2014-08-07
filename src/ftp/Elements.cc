/*
 * DEBUG: section 09    File Transfer Protocol (FTP)
 */

#include "squid.h"
#include "ftp/Elements.h"
#include "SBuf.h"

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
