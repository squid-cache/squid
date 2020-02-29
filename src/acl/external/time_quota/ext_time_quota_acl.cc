/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * ext_time_quota_acl: Squid external acl helper for quota on usage.
 *
 * Copyright (C) 2011 Dr. Tilmann Bubeck <t.bubeck@reinform.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 */

#include "squid.h"
#include "helper/protocol_defines.h"

#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#if HAVE_TDB_H
#include <tdb.h>
#endif

#ifndef DEFAULT_QUOTA_DB
#error "Please define DEFAULT_QUOTA_DB preprocessor constant."
#endif

const char *db_path = DEFAULT_QUOTA_DB;
const char *program_name;

TDB_CONTEXT *db = nullptr;

#define KEY_LAST_ACTIVITY            "last-activity"
#define KEY_PERIOD_START             "period-start"
#define KEY_PERIOD_LENGTH_CONFIGURED "period-length-configured"
#define KEY_TIME_BUDGET_LEFT         "time-budget-left"
#define KEY_TIME_BUDGET_CONFIGURED   "time-budget-configured"

/** Maximum size of buffers used to read or display lines. */
#define TQ_BUFFERSIZE                     1024

/** If there is more than this given number of seconds between two
 * sucessive requests, than the second request will be treated as a
 * new request and the time between first and seconds request will
 * be treated as a activity pause.
 *
 * Otherwise the following request will be treated as belonging to the
 * same activity and the quota will be reduced.
 */
static int pauseLength = 300;

static FILE *logfile = stderr;
static int tq_debug_enabled = false;

static void open_log(const char *logfilename)
{
    logfile = fopen(logfilename, "a");
    if ( logfile == NULL ) {
        perror(logfilename);
        logfile = stderr;
    }
}

static void vlog(const char *level, const char *format, va_list args)
{
    time_t now = time(NULL);

    fprintf(logfile, "%ld %s| %s: ", static_cast<long int>(now),
            program_name, level);
    vfprintf (logfile, format, args);
    fflush(logfile);
}

static void log_debug(const char *format, ...)
{
    va_list args;

    if ( tq_debug_enabled ) {
        va_start (args, format);
        vlog("DEBUG", format, args);
        va_end (args);
    }
}

static void log_info(const char *format, ...)
{
    va_list args;

    va_start (args, format);
    vlog("INFO", format, args);
    va_end (args);
}

static void log_error(const char *format, ...)
{
    va_list args;

    va_start (args, format);
    vlog("ERROR", format, args);
    va_end (args);
}

static void log_fatal(const char *format, ...)
{
    va_list args;

    va_start (args, format);
    vlog("FATAL", format, args);
    va_end (args);
}

static void init_db(void)
{
    log_info("opening time quota database \"%s\".\n", db_path);
    db = tdb_open(db_path, 0, TDB_CLEAR_IF_FIRST, O_CREAT | O_RDWR, 0666);
    if (!db) {
        log_fatal("Failed to open time_quota db '%s'\n", db_path);
        exit(EXIT_FAILURE);
    }
}

static void shutdown_db(void)
{
    tdb_close(db);
}

static char *KeyString(int &len, const char *user_key, const char *sub_key)
{
    static char keybuffer[TQ_BUFFERSIZE];
    *keybuffer = 0;

    len = snprintf(keybuffer, sizeof(keybuffer), "%s-%s", user_key, sub_key);
    if (len < 0) {
        log_error("Cannot add entry: %s-%s", user_key, sub_key);
        len = 0;

    } else if (static_cast<size_t>(len) >= sizeof(keybuffer)) {
        log_error("key too long (%s,%s)\n", user_key, sub_key);
        len = 0;
    }

    return keybuffer;
}

static void writeTime(const char *user_key, const char *sub_key, time_t t)
{
    int len = 0;
    if (/* const */ char *keybuffer = KeyString(len, user_key, sub_key)) {

        TDB_DATA key, data;

        key.dptr = reinterpret_cast<unsigned char *>(keybuffer);
        key.dsize = len;

        data.dptr = reinterpret_cast<unsigned char *>(&t);
        data.dsize = sizeof(t);

        tdb_store(db, key, data, TDB_REPLACE);
        log_debug("writeTime(\"%s\", %d)\n", keybuffer, t);
    }
}

static time_t readTime(const char *user_key, const char *sub_key)
{
    int len = 0;
    if (/* const */ char *keybuffer = KeyString(len, user_key, sub_key)) {

        TDB_DATA key;
        key.dptr = reinterpret_cast<unsigned char *>(keybuffer);
        key.dsize = len;

        auto data = tdb_fetch(db, key);

        time_t t = 0;
        if (data.dsize != sizeof(t)) {
            log_error("CORRUPTED DATABASE (%s)\n", keybuffer);
        } else {
            memcpy(&t, data.dptr, sizeof(t));
        }

        log_debug("readTime(\"%s\")=%d\n", keybuffer, t);
        return t;
    }

    return 0;
}

static void parseTime(const char *s, time_t *secs, time_t *start)
{
    double value;
    char unit;
    struct tm *ltime;
    int periodLength = 3600;

    *secs = 0;
    *start = time(NULL);
    ltime = localtime(start);

    sscanf(s, " %lf %c", &value, &unit);
    switch (unit) {
    case 's':
        periodLength = 1;
        break;
    case 'm':
        periodLength = 60;
        *start -= ltime->tm_sec;
        break;
    case 'h':
        periodLength = 3600;
        *start -= ltime->tm_min * 60 + ltime->tm_sec;
        break;
    case 'd':
        periodLength = 24 * 3600;
        *start -= ltime->tm_hour * 3600 + ltime->tm_min * 60 + ltime->tm_sec;
        break;
    case 'w':
        periodLength = 7 * 24 * 3600;
        *start -= ltime->tm_hour * 3600 + ltime->tm_min * 60 + ltime->tm_sec;
        *start -= ltime->tm_wday * 24 * 3600;
        *start += 24 * 3600;         // in europe, the week starts monday
        break;
    default:
        log_error("Wrong time unit \"%c\". Only \"m\", \"h\", \"d\", or \"w\" allowed.\n", unit);
        break;
    }

    *secs = (long)(periodLength * value);
}

/** This function parses the time quota file and stores it
 * in memory.
 */
static void readConfig(const char *filename)
{
    char line[TQ_BUFFERSIZE];        /* the buffer for the lines read
                   from the dict file */
    char *cp;           /* a char pointer used to parse
                   each line */
    char *username;     /* for the username */
    char *budget;
    char *period;
    FILE *FH;
    time_t t;
    time_t budgetSecs, periodSecs;
    time_t start;

    log_info("reading config file \"%s\".\n", filename);

    FH = fopen(filename, "r");
    if ( FH ) {
        /* the pointer to the first entry in the linked list */
        unsigned int lineCount = 0;
        while (fgets(line, sizeof(line), FH)) {
            ++lineCount;
            if (line[0] == '#') {
                continue;
            }
            if ((cp = strchr (line, '\n')) != NULL) {
                /* chop \n characters */
                *cp = '\0';
            }
            log_debug("read config line %u: \"%s\".\n", lineCount, line);
            if ((username = strtok(line, "\t ")) != NULL) {

                /* get the time budget */
                if ((budget = strtok(NULL, "/")) == NULL) {
                    fprintf(stderr, "ERROR: missing 'budget' field on line %u of '%s'.\n", lineCount, filename);
                    continue;
                }
                if ((period = strtok(NULL, "/")) == NULL) {
                    fprintf(stderr, "ERROR: missing 'period' field on line %u of '%s'.\n", lineCount, filename);
                    continue;
                }

                parseTime(budget, &budgetSecs, &start);
                parseTime(period, &periodSecs, &start);

                log_debug("read time quota for user \"%s\": %lds / %lds starting %lds\n",
                          username, budgetSecs, periodSecs, start);

                writeTime(username, KEY_PERIOD_START, start);
                writeTime(username, KEY_PERIOD_LENGTH_CONFIGURED, periodSecs);
                writeTime(username, KEY_TIME_BUDGET_CONFIGURED, budgetSecs);
                t = readTime(username, KEY_TIME_BUDGET_CONFIGURED);
                writeTime(username, KEY_TIME_BUDGET_LEFT, t);
            }
        }
        fclose(FH);
    } else {
        perror(filename);
    }
}

static void processActivity(const char *user_key)
{
    time_t now = time(NULL);
    time_t lastActivity;
    time_t activityLength;
    time_t periodStart;
    time_t periodLength;
    time_t userPeriodLength;
    time_t timeBudgetCurrent;
    time_t timeBudgetConfigured;
    char message[TQ_BUFFERSIZE];

    log_debug("processActivity(\"%s\")\n", user_key);

    // [1] Reset period if over
    periodStart = readTime(user_key, KEY_PERIOD_START);
    if ( periodStart == 0 ) {
        // This is the first period ever.
        periodStart = now;
        writeTime(user_key, KEY_PERIOD_START, periodStart);
    }

    periodLength = now - periodStart;
    userPeriodLength = readTime(user_key, KEY_PERIOD_LENGTH_CONFIGURED);
    if ( userPeriodLength == 0 ) {
        // This user is not configured. Allow anything.
        log_debug("No period length found for user \"%s\". Quota for this user disabled.\n", user_key);
        writeTime(user_key, KEY_TIME_BUDGET_LEFT, pauseLength);
    } else {
        if ( periodLength >= userPeriodLength ) {
            // a new period has started.
            log_debug("New time period started for user \"%s\".\n", user_key);
            while ( periodStart < now ) {
                periodStart += periodLength;
            }
            writeTime(user_key, KEY_PERIOD_START, periodStart);
            timeBudgetConfigured = readTime(user_key, KEY_TIME_BUDGET_CONFIGURED);
            if ( timeBudgetConfigured == 0 ) {
                log_debug("No time budget configured for user \"%s\". Quota for this user disabled.\n", user_key);
                writeTime(user_key, KEY_TIME_BUDGET_LEFT, pauseLength);
            } else {
                writeTime(user_key, KEY_TIME_BUDGET_LEFT, timeBudgetConfigured);
            }
        }
    }

    // [2] Decrease time budget iff activity
    lastActivity = readTime(user_key, KEY_LAST_ACTIVITY);
    if ( lastActivity == 0 ) {
        // This is the first request ever
        writeTime(user_key, KEY_LAST_ACTIVITY, now);
    } else {
        activityLength = now - lastActivity;
        if ( activityLength >= pauseLength ) {
            // This is an activity pause.
            log_debug("Activity pause detected for user \"%s\".\n", user_key);
            writeTime(user_key, KEY_LAST_ACTIVITY, now);
        } else {
            // This is real usage.
            writeTime(user_key, KEY_LAST_ACTIVITY, now);

            log_debug("Time budget reduced by %ld for user \"%s\".\n",
                      activityLength, user_key);
            timeBudgetCurrent = readTime(user_key, KEY_TIME_BUDGET_LEFT);
            timeBudgetCurrent -= activityLength;
            writeTime(user_key, KEY_TIME_BUDGET_LEFT, timeBudgetCurrent);
        }
    }

    timeBudgetCurrent = readTime(user_key, KEY_TIME_BUDGET_LEFT);
    snprintf(message, TQ_BUFFERSIZE, "message=\"Remaining quota for '%s' is %d seconds.\"", user_key, (int)timeBudgetCurrent);
    if ( timeBudgetCurrent > 0 ) {
        log_debug("OK %s.\n", message);
        SEND_OK(message);
    } else {
        log_debug("ERR %s\n", message);
        SEND_ERR("Time budget exceeded.");
    }
}

static void usage(void)
{
    log_error("Wrong usage. Please reconfigure in squid.conf.\n");

    fprintf(stderr, "Usage: %s [-d] [-l logfile] [-b dbpath] [-p pauselen] [-h] configfile\n", program_name);
    fprintf(stderr, "	-d            enable debugging output to logfile\n");
    fprintf(stderr, "	-l logfile    log messages to logfile\n");
    fprintf(stderr, "	-b dbpath     Path where persistent session database will be kept\n");
    fprintf(stderr, "	              If option is not used, then " DEFAULT_QUOTA_DB " will be used.\n");
    fprintf(stderr, "	-p pauselen   length in seconds to describe a pause between 2 requests.\n");
    fprintf(stderr, "	-h            show show command line help.\n");
    fprintf(stderr, "configfile is a file containing time quota definitions.\n");
}

int main(int argc, char **argv)
{
    char request[HELPER_INPUT_BUFFER];
    int opt;

    program_name = argv[0];

    while ((opt = getopt(argc, argv, "dp:l:b:h")) != -1) {
        switch (opt) {
        case 'd':
            tq_debug_enabled = true;
            break;
        case 'l':
            open_log(optarg);
            break;
        case 'b':
            db_path = optarg;
            break;
        case 'p':
            pauseLength = atoi(optarg);
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
            break;
        }
    }

    log_info("Starting %s\n", __FILE__);
    setbuf(stdout, NULL);

    init_db();

    if ( optind + 1 != argc ) {
        usage();
        exit(EXIT_FAILURE);
    } else {
        readConfig(argv[optind]);
    }

    log_info("Waiting for requests...\n");
    while (fgets(request, HELPER_INPUT_BUFFER, stdin)) {
        // we expect the following line syntax: %LOGIN
        const char *user_key = strtok(request, " \n");
        if (!user_key) {
            SEND_BH(HLP_MSG("User name missing"));
            continue;
        }
        processActivity(user_key);
    }
    log_info("Ending %s\n", __FILE__);
    shutdown_db();
    return EXIT_SUCCESS;
}

