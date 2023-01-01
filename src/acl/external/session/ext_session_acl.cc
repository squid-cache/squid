/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

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
#include "squid.h"
#endif
#include "helper/protocol_defines.h"

#include <cstdlib>
#include <cstring>
#include <ctime>
#if HAVE_DB_H
#include <db.h>
#endif
#include <fcntl.h>
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_TDB_H
#include <tdb.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

/* At this point all Bit Types are already defined, so we must
   protect from multiple type definition on platform where
   __BIT_TYPES_DEFINED__ is not defined.
 */
#ifndef        __BIT_TYPES_DEFINED__
#define        __BIT_TYPES_DEFINED__
#endif

static int session_ttl = 3600;
static int fixed_timeout = 0;
char *db_path = NULL;
const char *program_name;

#if USE_BERKLEYDB
DB *db = NULL;
DB_ENV *db_env = NULL;
typedef DBT DB_ENTRY;

#elif USE_TRIVIALDB
TDB_CONTEXT *db = nullptr;
typedef TDB_DATA DB_ENTRY;

#else
#error "Either Berkley DB or Trivial DB must be available"
#endif

static void
shutdown_db()
{
    if (db) {
#if USE_BERKLEYDB
        db->close(db, 0);
    }
    if (db_env) {
        db_env->close(db_env, 0);

#elif USE_TRIVIALDB
        if (tdb_close(db) != 0) {
            fprintf(stderr, "%s| WARNING: error closing session db '%s'\n", program_name, db_path);
            exit(EXIT_FAILURE);
        }
#endif
    }
    xfree(db_path);
}

static void init_db(void)
{
    struct stat st_buf;

    if (db_path) {
        if (!stat(db_path, &st_buf)) {
            if (S_ISDIR (st_buf.st_mode)) {
#if USE_BERKLEYDB
                /* If directory then open database environment. This prevents sync problems
                    between different processes. Otherwise fallback to single file */
                db_env_create(&db_env, 0);
                if (db_env->open(db_env, db_path, DB_CREATE | DB_INIT_MPOOL | DB_INIT_LOCK, 0666)) {
                    fprintf(stderr, "FATAL: %s: Failed to open database environment in '%s'\n", program_name, db_path);
                    db_env->close(db_env, 0);
                    exit(EXIT_FAILURE);
                }
                db_create(&db, db_env, 0);
#elif USE_TRIVIALDB
                std::string newPath(db_path);
                newPath.append("session", 7);
                db_path = xstrdup(newPath.c_str());
#endif
            }
        }
    }

#if USE_BERKLEYDB
    if (db_env) {
        if (db->open(db, NULL, "session", NULL, DB_BTREE, DB_CREATE, 0666)) {
            fprintf(stderr, "FATAL: %s: Failed to open db file '%s' in dir '%s'\n",
                    program_name, "session", db_path);
            db_env->close(db_env, 0);
            exit(EXIT_FAILURE);
        }
    } else {
        db_create(&db, NULL, 0);
        if (db->open(db, NULL, db_path, NULL, DB_BTREE, DB_CREATE, 0666)) {
            db = nullptr;
        }
    }
#elif USE_TRIVIALDB
#if _SQUID_FREEBSD_ && !defined(O_DSYNC)
    // FreeBSD lacks O_DSYNC, O_SYNC is closest to correct behaviour
#define O_DSYNC O_SYNC
#endif
    db = tdb_open(db_path, 0, TDB_CLEAR_IF_FIRST, O_CREAT|O_DSYNC, 0666);
#endif
    if (!db) {
        fprintf(stderr, "FATAL: %s: Failed to open session db '%s'\n", program_name, db_path);
        shutdown_db();
        exit(EXIT_FAILURE);
    }
}

int session_is_active = 0;

static size_t
dataSize(DB_ENTRY *data)
{
#if USE_BERKLEYDB
    return data->size;
#elif USE_TRIVIALDB
    return data->dsize;
#endif
}

static bool
fetchKey(/*const*/ DB_ENTRY &key, DB_ENTRY *data)
{
#if USE_BERKLEYDB
    return (db->get(db, nullptr, &key, data, 0) == 0);
#elif USE_TRIVIALDB
    // NP: API says returns NULL on errors, but return is a struct type WTF??
    *data = tdb_fetch(db, key);
    return (data->dptr != nullptr);
#endif
}

static void
deleteEntry(/*const*/ DB_ENTRY &key)
{
#if USE_BERKLEYDB
    db->del(db, nullptr, &key, 0);
#elif USE_TRIVIALDB
    tdb_delete(db, key);
#endif
}

static void
copyValue(void *dst, const DB_ENTRY *src, size_t sz)
{
#if USE_BERKLEYDB
    memcpy(dst, src->data, sz);
#elif USE_TRIVIALDB
    memcpy(dst, src->dptr, sz);
#endif
}

static int session_active(const char *details, size_t len)
{
#if USE_BERKLEYDB
    DBT key = {};
    key.data = const_cast<char*>(details);
    key.size = len;

    DBT data = {};
#elif USE_TRIVIALDB
    TDB_DATA key = {};
    key.dptr = reinterpret_cast<decltype(key.dptr)>(const_cast<char*>(details));
    key.dsize = len;

    TDB_DATA data = {};
#else
    (void)len;
#endif
    if (fetchKey(key, &data)) {
        time_t timestamp;
        if (dataSize(&data) != sizeof(timestamp)) {
            fprintf(stderr, "ERROR: %s: CORRUPTED DATABASE (%s)\n", program_name, details);
            deleteEntry(key);
            return 0;
        }
        copyValue(&timestamp, &data, sizeof(timestamp));
        if (timestamp + session_ttl >= time(NULL))
            return 1;
    }
    return 0;
}

static void
session_login(/*const*/ char *details, size_t len)
{
    DB_ENTRY key = {0};
    DB_ENTRY data = {0};
    time_t now = time(0);
#if USE_BERKLEYDB
    key.data = static_cast<decltype(key.data)>(details);
    key.size = len;
    data.data = &now;
    data.size = sizeof(now);
    db->put(db, NULL, &key, &data, 0);
#elif USE_TRIVIALDB
    key.dptr = reinterpret_cast<decltype(key.dptr)>(details);
    key.dsize = len;
    data.dptr = reinterpret_cast<decltype(data.dptr)>(&now);
    data.dsize = sizeof(now);
    tdb_store(db, key, data, 0);
#endif
}

static void
session_logout(/*const*/ char *details, size_t len)
{
    DB_ENTRY key = {0};
#if USE_BERKLEYDB
    key.data = static_cast<decltype(key.data)>(details);
    key.size = len;
#elif USE_TRIVIALDB
    key.dptr = reinterpret_cast<decltype(key.dptr)>(details);
    key.dsize = len;
#endif
    deleteEntry(key);
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
            db_path = xstrdup(optarg);
            break;
        case 'a':
            default_action = 0;
            break;
        case '?':
            usage();
            exit(EXIT_SUCCESS);
            break;
        }
    }

    setbuf(stdout, NULL);

    init_db();

    while (fgets(request, HELPER_INPUT_BUFFER, stdin)) {
        int action = 0;
        const char *channel_id = strtok(request, " ");
        char *detail = strtok(NULL, "\n");
        if (detail == NULL) {
            // Only 1 paramater supplied. We are expecting at least 2 (including the channel ID)
            fprintf(stderr, "FATAL: %s is concurrent and requires the concurrency option to be specified.\n", program_name);
            shutdown_db();
            exit(EXIT_FAILURE);
        }
        char *lastdetail = strrchr(detail, ' ');
        size_t detail_len = strlen(detail);
        if (lastdetail) {
            if (strcmp(lastdetail, " LOGIN") == 0) {
                action = 1;
                detail_len = (size_t)(lastdetail-detail);
                *lastdetail = '\0';
            } else if (strcmp(lastdetail, " LOGOUT") == 0) {
                action = -1;
                detail_len = (size_t)(lastdetail-detail);
                *lastdetail = '\0';
            } else if (!default_action && strcmp(lastdetail, " -") == 0) {
                // no action; LOGIN/LOGOUT not supplied
                // but truncate the '-' %DATA value given by Squid-4 and later
                detail_len = (size_t)(lastdetail-detail);
                *lastdetail = '\0';
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
    return EXIT_SUCCESS;
}

