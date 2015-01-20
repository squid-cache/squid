/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 50    Log file handling */

#ifndef _SQUID_SRC_LOG_MODSYSLOG_H
#define _SQUID_SRC_LOG_MODSYSLOG_H

class Logfile;

int logfile_mod_syslog_open(Logfile * lf, const char *path, size_t bufsz, int fatal_flag);

#endif /* _SQUID_SRC_LOG_MODSYSLOG_H */

