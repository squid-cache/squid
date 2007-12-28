/*
 * Structures and types used to implement opendir/readdir/closedir
 * on Windows 95/NT.
*/

#include <io.h>
#include <stdlib.h>
#include <sys/types.h> 

/* To keep API definitions clear */
#ifdef __cplusplus
#define SQUIDCEXTERN extern "C"
#else
#define SQUIDCEXTERN extern
#endif

#ifdef _MSC_VER /* Microsoft C Compiler ONLY */
/* struct dirent - same as Unix */
struct dirent {
    ino_t d_ino;                    /* inode (always 1 in WIN32) */
    off_t d_off;                /* offset to this dirent */
    unsigned short d_reclen;    /* length of d_name */
    char d_name[_MAX_FNAME+1];    /* filename (null terminated) */
};

/* typedef DIR - not the same as Unix */
typedef struct {
    long handle;                /* _findfirst/_findnext handle */
    short offset;                /* offset into directory */
    short finished;             /* 1 if there are not more files */
    struct _finddata_t fileinfo;  /* from _findfirst/_findnext */
    char *dir;                  /* the dir we are reading */
    struct dirent dent;         /* the dirent to return */
} DIR;

/* Function prototypes */
SQUIDCEXTERN DIR * opendir(const char *);
SQUIDCEXTERN struct dirent * readdir(DIR *);
SQUIDCEXTERN int closedir(DIR *);
#endif
