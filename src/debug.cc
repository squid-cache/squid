
/*
 * $Id: debug.cc,v 1.60 1998/02/21 18:46:36 rousskov Exp $
 *
 * DEBUG: section 0     Debug Routines
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
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

static char *debug_log_file = NULL;
static int Ctx_Lock = 0;
static const char *debugLogTime(time_t);
static void ctx_print();

#ifdef __STDC__
void
_db_print(const char *format,...)
{
#if defined(__QNX__)
    va_list eargs;
#endif
    va_list args;
#else
void
_db_print(va_alist)
     va_dcl
{
    va_list args;
    const char *format = NULL;
#endif
    LOCAL_ARRAY(char, f, BUFSIZ);
#if HAVE_SYSLOG
    LOCAL_ARRAY(char, tmpbuf, BUFSIZ);
#endif

#ifdef __STDC__
    va_start(args, format);
#if defined(__QNX__)
    va_start(eargs, format);
#endif
#else
    va_start(args);
    format = va_arg(args, const char *);
#endif

    if (debug_log == NULL)
	return;
    /* give a chance to context-based debugging to print current context */
    if (!Ctx_Lock)
	ctx_print();
    snprintf(f, BUFSIZ, "%s| %s",
	debugLogTime(squid_curtime),
	format);
#if HAVE_SYSLOG
    /* level 0 go to syslog */
    if (_db_level == 0 && opt_syslog_enable) {
	tmpbuf[0] = '\0';
	vsnprintf(tmpbuf, BUFSIZ, format, args);
	tmpbuf[1023] = '\0';
	syslog(LOG_ERR, "%s", tmpbuf);
    }
#endif /* HAVE_SYSLOG */
    /* write to log file */
#if defined(__QNX__)
    vfprintf(debug_log, f, eargs);
#else
    vfprintf(debug_log, f, args);
#endif
    if (!Config.onoff.buffered_logs)
	fflush(debug_log);
    if (opt_debug_stderr >= _db_level && debug_log != stderr) {
#if defined(__QNX__)
	vfprintf(stderr, f, eargs);
#else
	vfprintf(stderr, f, args);
#endif
    }
#if defined(__QNX__)
    va_end(eargs);
#endif
    va_end(args);
}

static void
debugArg(const char *arg)
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

static void
debugOpenLog(const char *logfile)
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

void
_db_init(const char *logfile, const char *options)
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
    if (opt_syslog_enable)
	openlog(appname, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);
#endif /* HAVE_SYSLOG */

}

void
_db_rotate_log(void)
{
    int i;
    LOCAL_ARRAY(char, from, MAXPATHLEN);
    LOCAL_ARRAY(char, to, MAXPATHLEN);
#ifdef S_ISREG
    struct stat sb;
#endif

    if (debug_log_file == NULL)
	return;
#ifdef S_ISREG
    if (stat(debug_log_file, &sb) == 0)
	if (S_ISREG(sb.st_mode) == 0)
	    return;
#endif

    /* Rotate numbers 0 through N up one */
    for (i = Config.Log.rotateNumber; i > 1;) {
	i--;
	snprintf(from, MAXPATHLEN, "%s.%d", debug_log_file, i - 1);
	snprintf(to, MAXPATHLEN, "%s.%d", debug_log_file, i);
	rename(from, to);
    }
    /* Rotate the current log to .0 */
    if (Config.Log.rotateNumber > 0) {
	snprintf(to, MAXPATHLEN, "%s.%d", debug_log_file, 0);
	rename(debug_log_file, to);
    }
    /* Close and reopen the log.  It may have been renamed "manually"
     * before HUP'ing us. */
    if (debug_log != stderr)
	debugOpenLog(Config.Log.log);
}

static const char *
debugLogTime(time_t t)
{
    struct tm *tm;
    static char buf[128];
    static time_t last_t = 0;
    if (t != last_t) {
        tm = localtime(&t);
        strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);
        last_t = t;
    }
    return buf;
}

/*
 * Context-based Debugging
 */

#if 0

    Rationale
    ---------

    When you have a long nested processing sequence, it is often impossible
    for low level routines to know in what larger context they operate. If a
    routine coredumps, one can restore the context using debugger trace.
    However, in many case you do not want to coredump, but just want to report
    a potential problem. A report maybe useless out of problem context.

    To solve this potential problem, use the following approach:

    int top_level_foo(const char *url)
    {
	/* define current context */
	Ctx ctx = ctx_enter(url); /* note: we stack but do not dup ctx descriptions! */
	...
	/* go down; middle_level_bar will eventually call bottom_level_boo */
	middle_level_bar(method, protocol);
	...
	/* exit, clean after yourself */
	ctx_exit(ctx);
    }

    void bottom_level_boo(int status, void *data)
    {
	/*
	 * detect exceptional condition, and simply report it, the context
	 * information will be available somewhere close in the log file
	 */
	if (status == STRANGE_STATUS)
	    debug(13, 6) ("DOS attack detected, data: %p\n", data);
	...
    }

    Current implementation is extremely simple but still very handy. It has a
    negligible overhead (descriptions are not duplicated).

    When the _first_ debug message for a given context is printed, it is
    prepended with the current context description. Context is printed with
    the same debugging level as the original message.

    Note that we do not print context every type you do ctx_enter(). This
    approach would produce too many useless messages.  For the same reason, a
    context description is printed at most _once_ even if you have 10
    debugging messages within one context.

    Contexts can be nested, of course. You must use ctx_enter() to enter a
    context (push it onto stack).  It is probably safe to exit several nested
    contexts at _once_ by calling ctx_exit() at the top level (this will pop
    all context till current one). However, as in any stack, you cannot start
    in the middle.

    Analysis: 
	i)   locate debugging message,
	ii)  locate current context by going _upstream_ in your log file,
	iii) hack away.

#endif /* rationale */

/*
 * To-Do: 
 *       decide if we want to dup() descriptions (adds overhead) but allows to
 *       add printf()-style interface
 */


/* implementation */

/*
 * descriptions for contexts over CTX_MAX_LEVEL limit are ignored, you probably
 * have a bug if your nesting goes that deep.
 */
#define CTX_MAX_LEVEL 255
/* produce a warning when nesting reaches this level and then double the level */
static int Ctx_Warn_Level = 32;  /* set to -1 to disable this feature */
/* all descriptions has been printed up to this level */
static Ctx_Reported_Level = -1;
/* descriptions are still valid or active up to this level */
static Ctx_Valid_Level = -1;
/* current level, the number of nested ctx_enter() calls */
static Ctx_Current_Level = -1;
/* saved descriptions (stack) */
static const char *Ctx_Descrs[CTX_MAX_LEVEL+1];


Ctx
ctx_enter(const char *descr)
{
    Ctx_Current_Level++;

    if (Ctx_Current_Level <= CTX_MAX_LEVEL)
	Ctx_Descrs[Ctx_Current_Level] = descr;

    if (Ctx_Current_Level == Ctx_Warn_Level) {
	debug(0,0) ("# ctx: suspiciously deep (%d) nesting:\n", Ctx_Warn_Level);
	Ctx_Warn_Level *= 2;
    }

    return Ctx_Current_Level;
}

void
ctx_exit(Ctx ctx)
{
    assert(ctx >= 0);
    Ctx_Current_Level = (ctx >= 0) ? ctx-1 : -1;
    if (Ctx_Valid_Level > Ctx_Current_Level)
	Ctx_Valid_Level = Ctx_Current_Level;
}

/*
 * the idea id to print each context description at most once but provide enough
 * info for deducing the current execution stack
 */
static void
ctx_print()
{
    /* lock so _db_print will not call us recursively */
    Ctx_Lock++;
    /* ok, user saw [0,Ctx_Reported_Level] descriptions */
    /* first inform about entries popped since user saw them */
    if (Ctx_Valid_Level < Ctx_Reported_Level) {
	_db_print("ctx: exit: from %2d downto %2d\n", 
	    Ctx_Reported_Level, Ctx_Valid_Level+1);
	Ctx_Reported_Level = Ctx_Valid_Level;
    }
    /* report new contexts that were pushed since last report */
    while (Ctx_Reported_Level < Ctx_Current_Level) {
	Ctx_Reported_Level++;
	Ctx_Valid_Level++;
	_db_print("ctx: enter: %2d '%s'\n", Ctx_Reported_Level, 
	    Ctx_Descrs[Ctx_Reported_Level] ? Ctx_Descrs[Ctx_Reported_Level] : "<null>");
    }
    /* unlock */
    Ctx_Lock--;
}
