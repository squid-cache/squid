static char rcsid[] = "$Id: debug.cc,v 1.1 1996/02/22 06:23:54 wessels Exp $";
/*
 *  File:         debug.c
 *  Description:  implementation of trace facility for debugging
 *  Author:       John Noll, USC
 *  Created:      Tue Jan  8 11:05:41 1991
 *  Language:     C
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *  
 */
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#if defined(__STRICT_ANSI__)
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <syslog.h>
#include <sys/param.h>		/* For  MAXPATHLEN. */

#include "debug.h"
#include "util.h"
#include "cache_cf.h"

static char *_db_modules = 0;	/* colon separated list of modules to debug. */
int _db_level = 0;
char *_db_file = __FILE__;
int _db_line = 0;

extern time_t cached_curtime;
extern char *mkrfc850();
extern int unbuffered_logs;	/* main.c */

int syslog_enable = 0;
int stderr_enable = 0;
FILE *debug_log = NULL;
static char *debug_log_file = NULL;
static time_t last_cached_curtime = 0;
static char the_time[81];

#if defined(__STRICT_ANSI__)
void _db_print(int level,...)
{
    char *format;
    va_list args;
#else
void _db_print(va_alist)
     va_dcl
{
    char *format;
    int level;
    va_list args;
#endif
    static char f[BUFSIZ];
    static char tmpbuf[BUFSIZ];
    char *module = NULL;
    char *s = NULL;

    if (debug_log == NULL)
	return;

#if defined(__STRICT_ANSI__)
    /* strict ANSI compliance requires the second arg to va_start - we don't */
    va_start(args, level);
    format = va_arg(args, char *);
#else
    va_start(args);
    level = va_arg(args, int);
    format = va_arg(args, char *);
#endif

    /* Obtain module name from filename. */
    if ((module = strrchr(_db_file, '/')) != NULL)
	module++;
    else
	module = _db_file;

    if (_db_level >= level) {
	if (!_db_modules || strstr(_db_modules, module)) {
	    /* don't compute the curtime too much */
	    if (last_cached_curtime != cached_curtime) {
		last_cached_curtime = cached_curtime;
		the_time[0] = '\0';
		s = mkhttpdlogtime(&cached_curtime);
		strcpy(the_time, s);
	    }
	    sprintf(f, "[%s] %s:%d:\t %s", the_time, module, _db_line, format);

	    /* level 0 go to syslog */
	    if ((level == 0) && syslog_enable) {
		tmpbuf[0] = '\0';
		vsprintf(tmpbuf, f, args);
		syslog(LOG_ERR, tmpbuf);
	    }
	    /* write to log file */
	    vfprintf(debug_log, f, args);
	    if (unbuffered_logs)
		fflush(debug_log);

	    /* if requested, dump it to stderr also */
	    if (stderr_enable) {
		vfprintf(stderr, f, args);
		fflush(stderr);
	    }
	}
    }
    va_end(args);
}

void _db_init(prefix, initial_level, logfile)
     char *prefix;
     int initial_level;
     char *logfile;
{
    char *db_level_str, db_buf[MAXPATHLEN];

    sprintf(db_buf, "%s_debug_level", prefix);
    if ((db_level_str = getenv(db_buf)) != NULL)
	_db_level = atoi(db_level_str);
    else
	_db_level = initial_level;

    _db_modules = getenv("DHT_DEBUG_MODULES");

    /* open error logging file */
    if (logfile != NULL) {
	if (debug_log_file)
	    free(debug_log_file);
	debug_log_file = strdup(logfile);	/* keep a static copy */
	debug_log = fopen(logfile, "a+");
	if (!debug_log) {
	    fprintf(stderr, "WARNING: Cannot write log file: %s\n", logfile);
	    perror(logfile);
	    fprintf(stderr, "         messages will be sent to 'stderr'.\n");
	    fflush(stderr);
	    debug_log = stderr;
	    /* avoid reduntancy */
	    stderr_enable = 0;
	}
    } else {
	fprintf(stderr, "WARNING: No log file specified?\n");
	fprintf(stderr, "         messages will be sent to 'stderr'.\n");
	fflush(stderr);
	debug_log = stderr;
	/* avoid reduntancy */
	stderr_enable = 0;
    }

    if (syslog_enable) {
	openlog("cached", LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);
    }
}

/* gack!  would be nice to use _db_init() instead */
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
    fclose(debug_log);
    debug_log = fopen(debug_log_file, "a+");
    if (debug_log == NULL) {
	fprintf(stderr, "WARNING: Cannot write log file: %s\n",
	    debug_log_file);
	perror(debug_log_file);
	fprintf(stderr, "         messages will be sent to 'stderr'.\n");
	fflush(stderr);
	debug_log = stderr;
	/* avoid redundancy */
	stderr_enable = 0;
    }
}
