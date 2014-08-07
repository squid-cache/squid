#ifndef SQUID_FTP_ELEMENTS_H
#define SQUID_FTP_ELEMENTS_H

class SBuf;

namespace Ftp {

/* FTP Commands used by Squid. ALLCAPS case. Safe for static initializaton. */
const SBuf &cmdAppe();
const SBuf &cmdAuth();
const SBuf &cmdCwd();
const SBuf &cmdDele();
const SBuf &cmdEprt();
const SBuf &cmdEpsv();
const SBuf &cmdList();
const SBuf &cmdMkd();
const SBuf &cmdMlsd();
const SBuf &cmdMlst();
const SBuf &cmdNlst();
const SBuf &cmdRetr();
const SBuf &cmdRmd();
const SBuf &cmdRnfr();
const SBuf &cmdRnto();
const SBuf &cmdSmnt();
const SBuf &cmdStat();
const SBuf &cmdStor();
const SBuf &cmdStou();
const SBuf &cmdUser();

} // namespace Ftp

#endif /* SQUID_FTP_ELEMENTS_H */
