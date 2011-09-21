/*
 * ext_session_acl: Squid external acl helper for tracking sessions
 *
 * Copyright (C) 2006 Henrik Nordstrom <henrik@henriknordstrom.net>
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

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include "helpers/defines.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <time.h>
#if HAVE_GETOPT_H
#include <getopt.h>
#endif

/* At this point all Bit Types are already defined, so we must
   protect from multiple type definition on platform where
   __BIT_TYPES_DEFINED__ is not defined.
 */
#ifndef        __BIT_TYPES_DEFINED__
#define        __BIT_TYPES_DEFINED__
#endif

#if HAVE_DB_185_H
#include <db_185.h>
#elif HAVE_DB_H
#include <db.h>
#endif

static int session_ttl = 3600;
static int fixed_timeout = 0;
char *db_path = NULL;
const char *program_name;

DB *db = NULL;

static void init_db(void)
{
    db = dbopen(db_path, O_CREAT | O_RDWR, 0666, DB_BTREE, NULL);
    if (!db) {
        fprintf(stderr, "FATAL: %s: Failed to open session db '%s'\n", program_name, db_path);
        exit(1);
    }
}

static void shutdown_db(void)
{
    db->close(db);
}

int session_is_active = 0;

static int session_active(const char *details, size_t len)
{
    DBT key, data;
    key.data = (void *)details;
    key.size = len;
    if (db->get(db, &key, &data, 0) == 0) {
        time_t timestamp;
        if (data.size != sizeof(timestamp)) {
            fprintf(stderr, "ERROR: %s: CORRUPTED DATABASE (%s)\n", program_name, details);
            db->del(db, &key, 0);
            return 0;
        }
        memcpy(&timestamp, data.data, sizeof(timestamp));
        if (timestamp + session_ttl >= time(NULL))
            return 1;
    }
    return 0;
}

static void session_login(const char *details, size_t len)
{
    DBT key, data;
    time_t now = time(NULL);
    key.data = (void *)details;
    key.size = len;
    data.data = &now;
    data.size = sizeof(now);
    db->put(db, &key, &data, 0);
    db->sync(db, 0);
}

static void session_logout(const char *details, size_t len)
{
    DBT key;
    key.data = (void *)details;
    key.size = len;
    db->del(db, &key, 0);
}

static void usage(void)
{
    fprintf(stderr, "Usage: %s [-t|-T session_timeout] [-b dbpath] [-a]\n", program_name);
    fprintf(stderr, "	-t sessiontimeout	Idle timeout after which sessions will be forgotten (user activity will reset)\n");
    fprintf(stderr, "	-T sessiontimeout	Fixed timeout after which sessions will be forgotten (regardless of user activity)\n");
    fprintf(stderr, "	-b dbpath		Path where persistent session database will be kept\n");
    fprintf(stderr, "	-a			Active mode requiring LOGIN argument to start a session\n");
}
int main(int argc, char **argv)
{
    char request[HELPER_INPUT_BUFFER];
    int opt;
    int default_action = 1;

    program_name = argv[0];

    while ((opt = getopt(argc, argv, "t:T:b:a?")) != -1) {
        switch (opt) {
        case 'T':
            fixed_timeout = 1;
        case 't':
            session_ttl = strtol(optarg, NULL, 0);
            break;
        case 'b':
            db_path = optarg;
            break;
        case 'a':
            default_action = 0;
            break;
        case '?':
            usage();
            exit(0);
            break;
        }
    }

    setbuf(stdout, NULL);

    init_db();

    while (fgets(request, HELPER_INPUT_BUFFER, stdin)) {
        int action = 0;
        const char *channel_id = strtok(request, " ");
        const char *detail = strtok(NULL, "\n");
        if (detail == NULL) {
            // Only 1 paramater supplied. We are expecting at least 2 (including the channel ID)
            fprintf(stderr, "FATAL: %s is concurrent and requires the concurrency option to be specified.\n", program_name);
            exit(1);
        }
        const char *lastdetail = strrchr(detail, ' ');
        size_t detail_len = strlen(detail);
        if (lastdetail) {
            if (strcmp(lastdetail, " LOGIN") == 0) {
                action = 1;
                detail_len = (size_t)(lastdetail-detail);
            } else if (strcmp(lastdetail, " LOGOUT") == 0) {
                action = -1;
                detail_len = (size_t)(lastdetail-detail);
            }
        }
        if (action == -1) {
            session_logout(detail, detail_len);
            printf("%s OK message=\"Bye\"\n", channel_id);
        } else if (action == 1) {
            session_login(detail, detail_len);
            printf("%s OK message=\"Welcome\"\n", channel_id);
        } else if (session_active(detail, detail_len)) {
            if (fixed_timeout == 0) {
                session_login(detail, detail_len);
            }
            printf("%s OK\n", channel_id);
        } else if (default_action == 1) {
            session_login(detail, detail_len);
            printf("%s ERR message=\"Welcome\"\n", channel_id);
        } else {
            printf("%s ERR message=\"No session available\"\n", channel_id);
        }
    }
    shutdown_db();
    return 0;
}
