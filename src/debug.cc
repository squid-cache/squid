/*
 * $Id: debug.cc,v 1.18 1996/07/09 03:41:21 wessels Exp $
 *
 * DEBUG: section 0     Debug Routines
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "squid.h"

char *_db_file = __FILE__;
int _db_line = 0;

int syslog_enable = 0;
FILE *debug_log = NULL;
static char *debug_log_file = NULL;
static time_t last_squid_curtime = 0;
static char the_time[81];

#define MAX_DEBUG_SECTIONS 50
static int debugLevels[MAX_DEBUG_SECTIONS];

#if defined(__STRICT_ANSI__)
void _db_print(int section, int level, char *format,...)
{
    va_list args;
#else
void _db_print(va_alist)
     va_dcl
{
    va_list args;
    int section;
    int level;
    char *format = NULL;
#endif
    static char f[BUFSIZ];
    static char tmpbuf[BUFSIZ];
    char *s = NULL;

    if (debug_log == NULL)
	return;

#if defined(__STRICT_ANSI__)
    va_start(args, format);
#else
    va_start(args);
    section = va_arg(args, int);
    level = va_arg(args, int);
    format = va_arg(args, char *);
#endif

    if (level > debugLevels[section]) {
	va_end(args);
	return;
    }
    /* don't compute the curtime too much */
    if (last_squid_curtime != squid_curtime) {
	last_squid_curtime = squid_curtime;
	the_time[0] = '\0';
	s = mkhttpdlogtime(&squid_curtime);
	strcpy(the_time, s);
    }
    sprintf(f, "[%s] %s:%d:\t %s",
	the_time,
	_db_file,
	_db_line,
	format);

#if HAVE_SYSLOG
    /* level 0 go to syslog */
    if ((level == 0) && syslog_enable) {
	tmpbuf[0] = '\0';
	vsprintf(tmpbuf, f, args);
	syslog(LOG_ERR, tmpbuf);
    }
#endif /* HAVE_SYSLOG */

    /* write to log file */
    vfprintf(debug_log, f, args);
    if (unbuffered_logs)
	fflush(debug_log);

    va_end(args);
}

static void debugArg(arg)
     char *arg;
{
    int s = 0;
    int l = 0;
    int i;

    if (!strncasecmp(arg, "ALL", 3)) {
	s = -1;
	arg += 4;
    } else {
	s = atoi(arg);
	while (*arg && *arg++ != ',');
    }
    l = atoi(arg);

    if (s >= 0) {
	debugLevels[s] = l;
	return;
    }
    for (i = 0; i < MAX_DEBUG_SECTIONS; i++)
	debugLevels[i] = l;
}

static void debugOpenLog(logfile)
     char *logfile;
{
    if (logfile == NULL) {
	debug_log = stderr;
	return;
    }
    if (debug_log_file)
	xfree(debug_log_file);
    debug_log_file = xstrdup(logfile);	/* keep a static copy */
    if (debug_log && debug_log != stderr)
	fclose(debug_log);
    debug_log = fopen(logfile, "a+");
    if (!debug_log) {
	fprintf(stderr, "WARNING: Cannot write log file: %s\n", logfile);
	perror(logfile);
	fprintf(stderr, "         messages will be sent to 'stderr'.\n");
	fflush(stderr);
	debug_log = stderr;
    }
}

void _db_init(logfile, options)
     char *logfile;
     char *options;
{
    int i;
    char *p = NULL;
    char *s = NULL;

    for (i = 0; i < MAX_DEBUG_SECTIONS; i++)
	debugLevels[i] = -1;

    if (options) {
	p = xstrdup(options);
	for (s = strtok(p, w_space); s; s = strtok(NULL, w_space))
	    debugArg(s);
	xfree(p);
    }
    debugOpenLog(logfile);

#if HAVE_SYSLOG && defined(LOG_LOCAL4)
    if (syslog_enable)
	openlog(appname, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);
#endif /* HAVE_SYSLOG */

}

void _db_rotate_log()
{
    int i;
    static char from[MAXPATHLEN];
    static char to[MAXPATHLEN];

    if (debug_log_file == NULL)
	return;

    /* Rotate numbers 0 through N up one */
    for (i = getLogfileRotateNumber(); i > 1;) {
	i--;
	sprintf(from, "%s.%d", debug_log_file, i - 1);
	sprintf(to, "%s.%d", debug_log_file, i);
	rename(from, to);
    }
    /* Rotate the current log to .0 */
    if (getLogfileRotateNumber() > 0) {
	sprintf(to, "%s.%d", debug_log_file, 0);
	rename(debug_log_file, to);
    }
    /* Close and reopen the log.  It may have been renamed "manually"
     * before HUP'ing us. */
    if (debug_log != stderr)
	debugOpenLog(getCacheLogFile());
}
