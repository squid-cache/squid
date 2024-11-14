/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

/* DEBUG: section 82    External ACL Helpers */

#include "squid.h"
#include "debug/Stream.h"
#include "helper/protocol_defines.h"
#include "sbuf/Stream.h"

#include <ctime>
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#if HAVE_TDB_H
#include <tdb.h>
#endif

#ifndef DEFAULT_QUOTA_DB
#error "Please define DEFAULT_QUOTA_DB preprocessor constant."
#endif

static const auto MY_DEBUG_SECTION = 82;
const char *db_path = DEFAULT_QUOTA_DB;
const char *program_name;

TDB_CONTEXT *db = nullptr;

static const auto KeyLastActivity = "last-activity";
static const auto KeyPeriodStart = "period-start";
static const auto KeyPeriodLengthConfigured = "period-length-configured";
static const auto KeyTimeBudgetLeft = "time-budget-left";
static const auto KeyTimeBudgetConfigured = "time-budget-configured";

/** Maximum size of buffers used to read or display lines. */
static const size_t TQ_BUFFERSIZE = 1024;

/** If there is more than this given number of seconds between two
 * successive requests, than the second request will be treated as a
 * new request and the time between first and seconds request will
 * be treated as a activity pause.
 *
 * Otherwise the following request will be treated as belonging to the
 * same activity and the quota will be reduced.
 */
static int pauseLength = 300;

static void init_db(void)
{
    debugs(MY_DEBUG_SECTION, 2, "opening time quota database \"" << db_path << "\".");

    db = tdb_open(db_path, 0, TDB_CLEAR_IF_FIRST, O_CREAT | O_RDWR, 0666);
    if (!db) {
        debugs(MY_DEBUG_SECTION, DBG_CRITICAL, "FATAL: Failed to open time_quota db '" << db_path << '\'');
        exit(EXIT_FAILURE);
    }
    // count the number of entries in the database, only used for debugging
    debugs(MY_DEBUG_SECTION, 2, "Database contains " << tdb_traverse(db, nullptr, nullptr) << " entries");
}

static void shutdown_db(void)
{
    tdb_close(db);
}

static SBuf KeyString(const char *user_key, const char *sub_key)
{
    return ToSBuf(user_key, "-", sub_key);
}

static void writeTime(const char *user_key, const char *sub_key, time_t t)
{
    auto ks = KeyString(user_key, sub_key);
    const TDB_DATA key {
        reinterpret_cast<unsigned char *>(const_cast<char *>(ks.rawContent())),
        ks.length()
    };
    const TDB_DATA data {
        reinterpret_cast<unsigned char *>(&t),
        sizeof(t)
    };

    tdb_store(db, key, data, TDB_REPLACE);
    debugs(MY_DEBUG_SECTION, 3, "writeTime(\"" << ks << "\", " << t << ')');
}

static time_t readTime(const char *user_key, const char *sub_key)
{
    auto ks = KeyString(user_key, sub_key);
    const TDB_DATA key {
        reinterpret_cast<unsigned char *>(const_cast<char *>(ks.rawContent())),
        ks.length()
    };
    auto data = tdb_fetch(db, key);

    if (!data.dptr) {
        debugs(MY_DEBUG_SECTION, 3, "no data found for key \"" << ks << "\".");
        return 0;
    }

    time_t t = 0;
    if (data.dsize == sizeof(t)) {
        memcpy(&t, data.dptr, sizeof(t));
    } else {
        debugs(MY_DEBUG_SECTION, DBG_IMPORTANT, "ERROR: Incompatible or corrupted database. " <<
               "key: '" << ks <<
               "', expected time value size: " << sizeof(t) <<
               ", actual time value size: " << data.dsize);
    }

    debugs(MY_DEBUG_SECTION, 3, "readTime(\"" << ks << "\")=" << t);
    return t;
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
        debugs(MY_DEBUG_SECTION, DBG_IMPORTANT, "ERROR: Wrong time unit \"" << unit << "\". Only \"m\", \"h\", \"d\", or \"w\" allowed");
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

    debugs(MY_DEBUG_SECTION, 2, "reading config file \"" << filename << "\".");

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
            debugs(MY_DEBUG_SECTION, 3, "read config line " << lineCount << ": \"" << line << '\"');
            if ((username = strtok(line, "\t ")) != NULL) {

                /* get the time budget */
                if ((budget = strtok(nullptr, "/")) == NULL) {
                    debugs(MY_DEBUG_SECTION, DBG_IMPORTANT, "ERROR: missing 'budget' field on line " << lineCount << " of '" << filename << '\'');
                    continue;
                }
                if ((period = strtok(nullptr, "/")) == NULL) {
                    debugs(MY_DEBUG_SECTION, DBG_IMPORTANT, "ERROR: missing 'period' field on line " << lineCount << " of '" << filename << '\'');
                    continue;
                }

                parseTime(budget, &budgetSecs, &start);
                parseTime(period, &periodSecs, &start);

                debugs(MY_DEBUG_SECTION, 3, "read time quota for user \"" << username << "\": " <<
                       budgetSecs << "s / " << periodSecs << "s starting " << start);

                writeTime(username, KeyPeriodStart, start);
                writeTime(username, KeyPeriodLengthConfigured, periodSecs);
                writeTime(username, KeyTimeBudgetConfigured, budgetSecs);
                t = readTime(username, KeyTimeBudgetConfigured);
                writeTime(username, KeyTimeBudgetLeft, t);
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

    debugs(MY_DEBUG_SECTION, 3, "processActivity(\"" << user_key << "\")");

    // [1] Reset period if over
    periodStart = readTime(user_key, KeyPeriodStart);
    if ( periodStart == 0 ) {
        // This is the first period ever.
        periodStart = now;
        writeTime(user_key, KeyPeriodStart, periodStart);
    }

    periodLength = now - periodStart;
    userPeriodLength = readTime(user_key, KeyPeriodLengthConfigured);
    if ( userPeriodLength == 0 ) {
        // This user is not configured. Allow anything.
        debugs(MY_DEBUG_SECTION, 3, "disabling user quota for user '" <<
               user_key << "': no period length found");
        writeTime(user_key, KeyTimeBudgetLeft, pauseLength);
    } else {
        if ( periodLength >= userPeriodLength ) {
            // a new period has started.
            debugs(MY_DEBUG_SECTION, 3, "New time period started for user \"" << user_key << '\"');
            while ( periodStart < now ) {
                periodStart += periodLength;
            }
            writeTime(user_key, KeyPeriodStart, periodStart);
            timeBudgetConfigured = readTime(user_key, KeyTimeBudgetConfigured);
            if ( timeBudgetConfigured == 0 ) {
                debugs(MY_DEBUG_SECTION, 3, "No time budget configured for user \"" << user_key  <<
                       "\". Quota for this user disabled.");
                writeTime(user_key, KeyTimeBudgetLeft, pauseLength);
            } else {
                writeTime(user_key, KeyTimeBudgetLeft, timeBudgetConfigured);
            }
        }
    }

    // [2] Decrease time budget iff activity
    lastActivity = readTime(user_key, KeyLastActivity);
    if ( lastActivity == 0 ) {
        // This is the first request ever
        writeTime(user_key, KeyLastActivity, now);
    } else {
        activityLength = now - lastActivity;
        if ( activityLength >= pauseLength ) {
            // This is an activity pause.
            debugs(MY_DEBUG_SECTION, 3, "Activity pause detected for user \"" << user_key << "\".");
            writeTime(user_key, KeyLastActivity, now);
        } else {
            // This is real usage.
            writeTime(user_key, KeyLastActivity, now);

            debugs(MY_DEBUG_SECTION, 3, "Time budget reduced by " << activityLength <<
                   " for user \"" << user_key << "\".");
            timeBudgetCurrent = readTime(user_key, KeyTimeBudgetLeft);
            timeBudgetCurrent -= activityLength;
            writeTime(user_key, KeyTimeBudgetLeft, timeBudgetCurrent);
        }
    }

    timeBudgetCurrent = readTime(user_key, KeyTimeBudgetLeft);

    const auto message = ToSBuf(HLP_MSG("Remaining quota for '"), user_key, "' is ", timeBudgetCurrent, " seconds.");
    if ( timeBudgetCurrent > 0 ) {
        SEND_OK(message);
    } else {
        SEND_ERR("Time budget exceeded.");
    }
}

static void usage(void)
{
    debugs(MY_DEBUG_SECTION, DBG_CRITICAL, "Wrong usage. Please reconfigure in squid.conf.");

    std::cerr <<
              "Usage: " << program_name << " [-d level] [-b dbpath] [-p pauselen] [-h] configfile\n" <<
              "	-d level      set section " << MY_DEBUG_SECTION << " debugging to the specified level,\n"
              "               overwriting Squid's debug_options (default: 1)\n"
              "	-b dbpath     Path where persistent session database will be kept\n" <<
              "	              If option is not used, then " << DEFAULT_QUOTA_DB << " will be used.\n" <<
              "	-p pauselen   length in seconds to describe a pause between 2 requests.\n" <<
              "	-h            show show command line help.\n" <<
              "configfile is a file containing time quota definitions.\n";
}

int main(int argc, char **argv)
{
    char request[HELPER_INPUT_BUFFER];
    int opt;

    program_name = argv[0];
    Debug::NameThisHelper("ext_time_quota_acl");

    while ((opt = getopt(argc, argv, "d:p:b:h")) != -1) {
        switch (opt) {
        case 'd':
            Debug::parseOptions(ToSBuf(MY_DEBUG_SECTION, ",", optarg).c_str());
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
        default:
            // getopt() emits error message to stderr
            usage();
            exit(EXIT_FAILURE);
            break;
        }
    }

    debugs(MY_DEBUG_SECTION, DBG_IMPORTANT, "Starting " << program_name);
    setbuf(stdout, nullptr);

    init_db();

    if ( optind + 1 != argc ) {
        usage();
        exit(EXIT_FAILURE);
    } else {
        readConfig(argv[optind]);
    }

    debugs(MY_DEBUG_SECTION, 2, "Waiting for requests...");
    while (fgets(request, HELPER_INPUT_BUFFER, stdin)) {
        // we expect the following line syntax: %LOGIN
        const char *user_key = strtok(request, " \n");
        if (!user_key) {
            SEND_BH(HLP_MSG("User name missing"));
            continue;
        }
        processActivity(user_key);
    }
    debugs(MY_DEBUG_SECTION, DBG_IMPORTANT, "Ending " << program_name);
    shutdown_db();
    return EXIT_SUCCESS;
}

