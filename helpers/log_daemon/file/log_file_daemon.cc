#include "squid.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_PATHS_H
#include <paths.h>
#endif

#include "defines.h"

/* parse buffer - ie, length of longest expected line */
#define	LOGFILE_BUF_LEN		65536

static void
rotate(const char *path, int rotate_count)
{
#ifdef S_ISREG
    struct stat sb;
#endif
    int i;
    char from[MAXPATHLEN];
    char to[MAXPATHLEN];
    assert(path);
#ifdef S_ISREG
    if (stat(path, &sb) == 0)
        if (S_ISREG(sb.st_mode) == 0)
            return;
#endif
    /* Rotate numbers 0 through N up one */
    for (i = rotate_count; i > 1;) {
        --i;
        snprintf(from, MAXPATHLEN, "%s.%d", path, i - 1);
        snprintf(to, MAXPATHLEN, "%s.%d", path, i);
#if _SQUID_OS2_ || _SQUID_WINDOWS_
        if (remove(to) < 0) {
            fprintf(stderr, "WARNING: remove '%s' failure: %s\n", to, xstrerror());
        }
#endif
        if (rename(from, to) < 0 && errno != ENOENT) {
            fprintf(stderr, "WARNING: rename '%s' to '%s' failure: %s\n", from, to, xstrerror());
        }
    }
    if (rotate_count > 0) {
        snprintf(to, MAXPATHLEN, "%s.%d", path, 0);
#if _SQUID_OS2_ || _SQUID_WINDOWS_
        if (remove(to) < 0) {
            fprintf(stderr, "WARNING: remove '%s' failure: %s\n", to, xstrerror());
        }
#endif
        if (rename(path, to) < 0 && errno != ENOENT) {
            fprintf(stderr, "WARNING: rename %s to %s failure: %s\n", path, to, xstrerror());
        }
    }
}

/**
 * The commands:
 *
 * L<data>\n - logfile data
 * R\n - rotate file
 * T\n - truncate file
 * O\n - repoen file
 * F\n - flush file
 * r<n>\n - set rotate count to <n>
 * b<n>\n - 1 = buffer output, 0 = don't buffer output
 */
int
main(int argc, char *argv[])
{
    int t;
    FILE *fp;
    char buf[LOGFILE_BUF_LEN];
    int rotate_count = 10;
    int do_buffer = 1;

    if (argc < 2) {
        printf("Error: usage: %s <logfile>\n", argv[0]);
        exit(1);
    }
    fp = fopen(argv[1], "a");
    if (fp == NULL) {
        perror("fopen");
        exit(1);
    }
    setbuf(stdout, NULL);
    close(2);
    t = open(_PATH_DEVNULL, O_RDWR);
    assert(t > -1);
    dup2(t, 2);

    while (fgets(buf, LOGFILE_BUF_LEN, stdin)) {
        /* First byte indicates what we're logging! */
        switch (buf[0]) {
        case 'L':
            if (buf[1] != '\0') {
                fprintf(fp, "%s", buf + 1);
                /* try to detect the 32-bit file too big write error and rotate */
                int err = ferror(fp);
                clearerr(fp);
                if (err < 0) {
                    /* file too big - recover by rotating the logs and starting a new one.
                     * out of device space - recover by rotating and hoping that rotation count drops a big one.
                     */
                    if (err == EFBIG || err == ENOSPC) {
                        fprintf(stderr, "WARNING: %s writing %s. Attempting to recover via a log rotation.\n",xstrerr(err),argv[1]);
                        fclose(fp);
                        rotate(argv[1], rotate_count);
                        fp = fopen(argv[1], "a");
                        if (fp == NULL) {
                            perror("fopen");
                            exit(1);
                        }
                        fprintf(fp, "%s", buf + 1);
                    } else {
                        perror("fprintf");
                        exit(1);
                    }
                }
            }
            if (!do_buffer)
                fflush(fp);
            break;
        case 'R':
            fclose(fp);
            rotate(argv[1], rotate_count);
            fp = fopen(argv[1], "a");
            if (fp == NULL) {
                perror("fopen");
                exit(1);
            }
            break;
        case 'T':
            break;
        case 'O':
            break;
        case 'r':
            //fprintf(fp, "SET ROTATE: %s\n", buf + 1);
            rotate_count = atoi(buf + 1);
            break;
        case 'b':
            //fprintf(fp, "SET BUFFERED: %s\n", buf + 1);
            do_buffer = (buf[1] == '1');
            break;
        case 'F':
            fflush(fp);
            break;
        default:
            /* Just in case .. */
            fprintf(fp, "%s", buf);
            break;
        }
    }
    fclose(fp);
    fp = NULL;
    exit(0);
}
