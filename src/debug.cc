
/* $Id: debug.cc,v 1.17 1996/04/17 17:14:43 wessels Exp $ */

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

void _db_init(logfile)
     char *logfile;
{
    int i;
    char *p = NULL;
    char *s = NULL;

    for (i = 0; i < MAX_DEBUG_SECTIONS; i++)
	debugLevels[i] = -1;

    if ((p = getDebugOptions())) {
	p = xstrdup(p);
	for (s = strtok(p, w_space); s; s = strtok(NULL, w_space)) {
	    debugArg(s);
	}
	xfree(p);
    }
    debugOpenLog(logfile);

#if HAVE_SYSLOG
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
	debugOpenLog(debug_log_file);
}
