/*
 * usersfile.c
 * (C) 2000 Antonino Iannella, Stellar-X Pty Ltd
 * Released under GPL, see COPYING-2.0 for details.
 *
 * These routines are to allow users attempting to use the proxy which
 * have been explicitly allowed by the system administrator.
 * The code originated from denyusers.c.
 */

#include "squid.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/param.h>
#include <fcntl.h>

#include "usersfile.h"

#define NAMELEN     50		/* Maximum username length */

static int
name_cmp(const void *a, const void *b)
{
    const char * const *A = static_cast<const char * const *>(a);
    const char * const *B = static_cast<const char * const *>(b);
    return strcasecmp(*A, *B);
}

static void
free_names(usersfile * uf)
{
    int i;
    for (i = 0; i < uf->Inuse; ++i) {
        if (uf->names[i])
            free(uf->names[i]);
        uf->names[i] = NULL;
    }
    uf->Inuse = 0;
}

/*
 * Reads a file of usernames and stuffs them into an array
 * of strings.
 * Returns 0 if the user list was successfully loaded,
 * and 1 in case of error.
 */

int
Read_usersfile(const char *path, usersfile * uf)
{
    FILE *fp;
    struct stat FileBuf;
    char buf[1024];

    free_names(uf);

    if (NULL == path) {
        path = uf->path;
    } else {
        if (uf->path)
            free(uf->path);
        uf->path = xstrdup(path);
    }

    /* Open the users file. Report any errors. */
    fp = fopen(path, "r");
    if (NULL == fp) {
        uf->LMT = 0;
        if (errno == ENOENT)
            return 0;
        syslog(LOG_ERR, "%s: %s", path, strerror(errno));
        return 1;
    }
    /* Stat the file. If it does not exist, save the size as zero.
     * Clear the allowed user string. Return. */
    if (fstat(fileno(fp), &FileBuf) < 0) {
        syslog(LOG_ERR, "%s: %s", path, strerror(errno));
        fclose(fp);
        return 1;
    }
    /* If it exists, save the modification time and size */
    uf->LMT = FileBuf.st_mtime;

    /* Handle the special case of a zero length file */
    if (FileBuf.st_size == 0) {
        fclose(fp);
        return 0;
    }

    /*
     * Read the file into memory
     * XXX assumes one username per input line
     */
    while (fgets(buf, 1024, fp) != NULL) {
        /* ensure no names longer than our limit */
        buf[NAMELEN] = '\0';
        /* skip bad input lines */
        if (NULL == strtok(buf, "\r\n"))
            continue;
        /* grow the list if necessary */
        if (0 == uf->Alloc) {
            uf->Alloc = 256;
            uf->names = static_cast<char**>(calloc(uf->Alloc, sizeof(*uf->names)));
        } else if (uf->Inuse == uf->Alloc) {
            uf->Alloc = uf->Alloc << 1;
            uf->names = static_cast<char**>(realloc(uf->names, uf->Alloc * sizeof(*uf->names)));
            /* zero out the newly allocated memory */
            memset(&uf->names[uf->Alloc >> 1],
                   '\0',
                   (uf->Alloc >> 1) * sizeof(*uf->names));
        }
        uf->names[uf->Inuse] = xstrdup(buf);
        ++uf->Inuse;
    }
    fclose(fp);
    fp = NULL;

    /* sort the names for searching */
    qsort(uf->names, uf->Inuse, sizeof(*uf->names), name_cmp);

    return 0;
}

/*
 * Check to see if the username provided by Squid appears in the
 * user list. Returns 0 if the user was not found, and 1 if they were.
 */

int
Check_userlist(usersfile * uf, char *User)
{
    void *p;

    /* Empty users are always in the list */
    if (User[0] == '\0')
        return 1;

    /* If allowed user list is empty, allow all users.
     * If no users are supposed to be using the proxy, stop squid instead. */
    if (0 == uf->Inuse)
        return 1;

    /* Check if username string is found in the allowed user list.
     * If so, allow. If not, deny. Reconstruct the username
     * to have whitespace, to avoid finding wrong string subsets. */

    p = bsearch(&User,
                uf->names,
                uf->Inuse,
                sizeof(*uf->names),
                name_cmp);
    if (NULL == p) {
        return 0;
    }
    return 1;
}

/*
 * Checks if there has been a change in a users file.
 * If the modification time has changed, then reload the user list.
 */
void
Check_forfilechange(usersfile * uf)
{
    struct stat ChkBuf;		/* Stat data buffer */

    /* Stat the allowed users file. If it cannot be accessed, return. */

    if (uf->path == NULL)
        return;

    if (stat(uf->path, &ChkBuf) < 0) {
        if (errno == ENOENT) {
            uf->LMT = 0;
            free_names(uf);
        } else {		/* Report error when accessing file */
            syslog(LOG_ERR, "%s: %s", uf->path, strerror(errno));
        }
        return;
    }
    /* return if no change */
    if (ChkBuf.st_mtime == uf->LMT)
        return;

    /*
     * The file changed, so re-read it.
     */
    syslog(LOG_INFO, "Check_forfilechange: Reloading user list '%s'.", uf->path);
    Read_usersfile(NULL, uf);
}
