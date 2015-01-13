/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// Author:  Jens-S. V?ckler <voeckler@rvs.uni-hannover.de>
//
// File:    purge.cc
//          Wed Jan 13 1999
//
// (c) 1999 Lehrgebiet Rechnernetze und Verteilte Systeme
//          Universit?t Hannover, Germany
//
// Permission to use, copy, modify, distribute, and sell this software
// and its documentation for any purpose is hereby granted without fee,
// provided that (i) the above copyright notices and this permission
// notice appear in all copies of the software and related documentation,
// and (ii) the names of the Lehrgebiet Rechnernetze und Verteilte
// Systeme and the University of Hannover may not be used in any
// advertising or publicity relating to the software without the
// specific, prior written permission of Lehrgebiet Rechnernetze und
// Verteilte Systeme and the University of Hannover.
//
// THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
// EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
//
// IN NO EVENT SHALL THE LEHRGEBIET RECHNERNETZE UND VERTEILTE SYSTEME OR
// THE UNIVERSITY OF HANNOVER BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
// INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT
// ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY,
// ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
// SOFTWARE.
//
// Revision 1.17  2000/09/21 10:59:53  cached
// *** empty log message ***
//
// Revision 1.16  2000/09/21 09:45:18  cached
// Fixed some small bugs.
//
// Revision 1.15  2000/09/21 09:05:56  cached
// added multi cache_dir support, thus changing -c cmdline option.
// modified file reading to support /dev/fd/0 reading for non-disclosed items.
//
// Revision 1.14  2000/06/20 09:43:01  voeckler
// added FreeBSD related fixes and support.
//
// Revision 1.13  2000/03/29 08:12:21  voeckler
// fixed wrong header file.
//
// Revision 1.12  2000/03/29 07:54:41  voeckler
// added mechanism to give a port specification precedence over a host
// specificiation with the -p option and not colon.
//
// Revision 1.11  1999/06/18 13:18:28  voeckler
// added refcount, fixed missing LF in -s output.
//
// Revision 1.10  1999/06/16 13:06:05  voeckler
// reversed meaning of -M flag.
//
// Revision 1.9  1999/06/15 21:11:53  voeckler
// added extended logging feature which extract the squid meta data available
// within the disk files. moved the content extraction and squid meta data
// handling parts into separate files. added options for copy-out and verbose.
//
// Revision 1.8  1999/06/14 20:14:46  voeckler
// intermediate version when adding understanding about the way
// Squid does log the metadata into the file.
//
// Revision 1.7  1999/01/23 21:01:10  root
// stumbled over libc5 header/lib inconsistency bug....
//
// Revision 1.6  1999/01/23 20:47:54  root
// added Linux specifics for psignal...
// Hope this helps.
//
// Revision 1.5  1999/01/20 09:48:12  voeckler
// added warning as first line of output.
//
// Revision 1.4  1999/01/19 11:53:49  voeckler
// added psignal() from <siginfo.h> handling.
//
// Revision 1.3  1999/01/19 11:00:50  voeckler
// added keyboard interrupt handling, exit handling, removed C++ strings and
// regular expression syntax in favour of less source code, added comments,
// added a reminder to remove swap.state in case of unlinks, added IAA flag,
// added a few assertions, changed policy to enforce the definition of at
// least one regular expression, and catch a few signals.
//
// Revision 1.2  1999/01/15 23:06:28  voeckler
// downgraded to simple C strings...
//
// Revision 1.1  1999/01/14 12:05:32  voeckler
// Initial revision
//
//
#include "squid.h"
#include "util.h"

#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#if HAVE_SIGINFO_H
#include <siginfo.h>
#endif

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "conffile.hh"
#include "convert.hh"
#include "copyout.hh"
#include "signal.hh"
#include "socket.hh"
#include "squid-tlv.hh"

#ifndef DEFAULTHOST
#define DEFAULTHOST "localhost"
#endif // DEFAULTHOST

#ifndef DEFAULTPORT
#define DEFAULTPORT 3128
#endif // DEFAULTPORT

volatile sig_atomic_t term_flag = 0; // 'terminate' is a gcc 2.8.x internal...
char*  linebuffer = 0;
size_t buffersize = 128*1024;
static char* copydir = 0;
static uint32_t debugFlag = 0;
static unsigned purgeMode = 0;
static bool iamalive = false;
static bool reminder = false;
static bool verbose  = false;
static bool envelope = false;
static bool no_fork  = false;
static const char* programname = 0;

// ----------------------------------------------------------------------

struct REList {
    REList( const char* what, bool doCase );
    ~REList();
    bool match( const char* check ) const;

    REList*     next;
    const char* data;
    regex_t     rexp;
};

REList::REList( const char* what, bool doCase )
    :next(0),data(xstrdup(what))
{
    int result = regcomp( &rexp, what,
                          REG_EXTENDED | REG_NOSUB | (doCase ? 0 : REG_ICASE) );
    if ( result != 0 ) {
        char buffer[256];
        regerror( result, &rexp, buffer, 256 );
        fprintf( stderr, "unable to compile re \"%s\": %s\n", what, buffer );
        exit(1);
    }
}

REList::~REList()
{
    if ( next ) delete next;
    if ( data ) xfree((void*) data);
    regfree(&rexp);
}

bool
REList::match( const char* check ) const
{
    int result = regexec( &rexp, check, 0, 0, 0 );
    if ( result != 0 && result != REG_NOMATCH ) {
        char buffer[256];
        regerror( result, &rexp, buffer, 256 );
        fprintf( stderr, "unable to execute re \"%s\"\n+ on line \"%s\": %s\n",
                 data, check, buffer );
        exit(1);
    }
    return ( result == 0 );
}

// ----------------------------------------------------------------------

char*
concat( const char* start, ... )
// purpose: concatinate an arbitrary number of C strings.
// paramtr: start (IN): first C string
//          ... (IN): further C strings, terminated with a NULL pointer
// returns: memory allocated via new(), containing the concatinated string.
{
    va_list ap;
    const char* s;

    // first run: determine size
    unsigned size = strlen(start)+1;
    va_start( ap, start );
    while ( (s=va_arg(ap,const char*)) != NULL )
        size += strlen(s);
    va_end(ap);

    // allocate
    char* result = new char[size];
    if ( result == 0 ) {
        perror( "string memory allocation" );
        exit(1);
    }

    // second run: copy content
    strcpy( result, start );
    va_start( ap, start );
    while ( (s=va_arg(ap,const char*)) != NULL ) strcat( result, s );
    va_end(ap);

    return result;
}

bool
isxstring( const char* s, size_t testlen )
// purpose: test a string for conforming to xdigit
// paramtr: s (IN): string to test
//          testlen (IN): length the string must have
// returns: true, iff strlen(s)==testlen && all_x_chars(s), false otherwise
{
    if ( strlen(s) != testlen ) return false;

    size_t i=0;
    while ( i<testlen && isxdigit(s[i]) )
        ++i;
    return (i==testlen);
}

inline
int
log_output( const char* fn, int code, long size, const char* url )
{
    return printf( "%s %3d %8ld %s\n", fn, code, size, url );
}

static
int
log_extended( const char* fn, int code, long size, const SquidMetaList* meta )
{
    static const char hexdigit[] = "0123456789ABCDEF";
    char md5[34];
    const SquidTLV* findings = 0;

    if ( meta && (findings = meta->search( STORE_META_KEY_MD5 )) ) {
        unsigned char* s = (unsigned char*) findings->data;
        for ( int j=0; j<16; ++j, ++s ) {
            md5[j*2+0] = hexdigit[ *s >> 4 ];
            md5[j*2+1] = hexdigit[ *s & 15 ];
        }
        md5[32] = '\0'; // terminate string
    } else {
        snprintf( md5, sizeof(md5), "%-32s", "(no_md5_data_available)" );
    }

    char timeb[64];
    if ( meta && (findings = meta->search( STORE_META_STD )) ) {
        StoreMetaStd temp;
        // make data aligned, avoid SIGBUS on RISC machines (ARGH!)
        memcpy( &temp, findings->data, sizeof(StoreMetaStd) );
        snprintf( timeb, sizeof(timeb), "%08lx %08lx %08lx %08lx %04x %5hu ",
                  (unsigned long)temp.timestamp, (unsigned long)temp.lastref,
                  (unsigned long)temp.expires, (unsigned long)temp.lastmod, temp.flags, temp.refcount );
    } else if ( meta && (findings = meta->search( STORE_META_STD_LFS )) ) {
        StoreMetaStdLFS temp;
        // make data aligned, avoid SIGBUS on RISC machines (ARGH!)
        memcpy( &temp, findings->data, sizeof(StoreMetaStd) );
        snprintf( timeb, sizeof(timeb), "%08lx %08lx %08lx %08lx %04x %5hu ",
                  (unsigned long)temp.timestamp, (unsigned long)temp.lastref,
                  (unsigned long)temp.expires, (unsigned long)temp.lastmod, temp.flags, temp.refcount );
    } else {
        unsigned long ul = ULONG_MAX;  // Match type of StoreMetaTLV fields
        unsigned short hu = 0;  // Match type of StoreMetaTLV refcount fields
        snprintf( timeb, sizeof(timeb), "%08lx %08lx %08lx %08lx %04x %5d ", ul, ul, ul, ul, 0, hu);
    }

    // make sure that there is just one printf()
    if ( meta && (findings = meta->search( STORE_META_URL )) ) {
        return printf( "%s %3d %8ld %s %s %s\n",
                       fn, code, size, md5, timeb, findings->data );
    } else {
        return printf( "%s %3d %8ld %s %s strange_file\n",
                       fn, code, size, md5, timeb );
    }
}

// o.k., this is pure lazyness...
static struct in_addr serverHost;
static unsigned short serverPort;

bool
action( int fd, size_t metasize,
        const char* fn, const char* url, const SquidMetaList& meta )
// purpose: if cmdline-requested, send the purge request to the cache
// paramtr: fd (IN): open FD for the object file
//        metasize (IN): offset into data portion of file (meta data size)
//          fn (IN): name of the object file
//          url (IN): URL string stored in the object file
//        meta (IN): list containing further meta data
// returns: true for a successful action, false otherwise. The action
//          may just print the file, send the purge request or even
//          remove unwanted files.
// globals: ::purgeMode (IN):  bit#0 set -> send purge request.
//                             bit#1 set -> remove 404 object files.
//          ::serverHost (IN): cache host address
//          ::serverPort (IN): cache port number
{
    static const char* schablone = "PURGE %s HTTP/1.0\r\nAccept: */*\r\n\r\n";
    struct stat st;
    long size = ( fstat(fd,&st) == -1 ? -1 : long(st.st_size - metasize) );

    // if we want to copy out the file, do that first of all.
    if ( ::copydir && *copydir && size > 0 )
        copy_out( st.st_size, metasize, ::debugFlag,
                  fn, url, ::copydir, ::envelope );

    // do we need to PURGE the file, yes, if purgemode bit#0 was set.
    int status = 0;
    if ( ::purgeMode & 0x01 ) {
        unsigned long bufsize = strlen(url) + strlen(schablone) + 4;
        char* buffer = new char[bufsize];

        snprintf( buffer, bufsize, schablone, url );
        int sockfd = connectTo( serverHost, serverPort, true );
        if ( sockfd == -1 ) {
            fprintf( stderr, "unable to connect to server: %s\n", strerror(errno) );
            delete[] buffer;
            return false;
        }

        int content_size = strlen(buffer);
        if ( write( sockfd, buffer, content_size ) != content_size ) {
            // error while talking to squid
            fprintf( stderr, "unable to talk to server: %s\n", strerror(errno) );
            close(sockfd);
            delete[] buffer;
            return false;
        }
        memset( buffer+8, 0, 4 );
        int readLen = read(sockfd, buffer, bufsize);
        if (readLen < 1) {
            // error while reading squid's answer
            fprintf( stderr, "unable to read answer: %s\n", strerror(errno) );
            close(sockfd);
            delete[] buffer;
            return false;
        }
        buffer[bufsize-1] = '\0';
        close(sockfd);
        int64_t s = strtol(buffer+8,0,10);
        if (s > 0 && s < 1000)
            status = s;
        else {
            // error while reading squid's answer
            fprintf( stderr, "invalid HTTP status in reply: %s\n", buffer+8);
        }
        delete[] buffer;
    }

    // log the output of our operation
    bool flag = true;
    if ( ::verbose ) flag = ( log_extended( fn, status, size, &meta ) >= 0 );
    else flag = ( log_output( fn, status, size, url ) >= 0 );

    // remove the file, if purgemode bit#1, and HTTP result status 404).
    if ( (::purgeMode & 0x02) && status == 404 ) {
        reminder = true;
        if ( unlink(fn) == -1 )
            // error while unlinking file, this may happen due to the cache
            // unlinking a file while it is still in the readdir() cache of purge.
            fprintf( stderr, "WARNING: unable to unlink %s: %s\n",
                     fn, strerror(errno) );
    }

    return flag;
}

bool
match( const char* fn, const REList* list )
// purpose: do something with the given cache content filename
// paramtr: fn (IN): filename of cache file
// returns: true for successful action, false otherwise.
// warning: only return false, if you want the loop to terminate!
{
    static const size_t addon = sizeof(unsigned char) + sizeof(unsigned int);
    bool flag = true;

    if ( debugFlag & 0x01 ) fprintf( stderr, "# [3] %s\n", fn );
    int fd = open( fn, O_RDONLY );
    if ( fd != -1 ) {
        memset(::linebuffer, 0, ::buffersize);
        size_t readLen = read(fd,::linebuffer,::buffersize-1);
        if ( readLen > 60 ) {
            ::linebuffer[ ::buffersize-1 ] = '\0'; // force-terminate string

            // check the offset into the start of object data. The offset is
            // stored in a host endianess after the first byte.
            unsigned int datastart;
            memcpy( &datastart, ::linebuffer + 1, sizeof(unsigned int) );
            if ( datastart > ::buffersize - addon - 1 ) {
                // check offset into server reply header (start of cache data).
                fputs( "WARNING: Using a truncated URL string.\n", stderr );
                datastart = ::buffersize - addon - 1;
            }

            // NEW: Parse squid meta data, which is a kind of linked list
            // flattened out into a file byte stream. Somewhere within is
            // the URL as part of the list. First, gobble all meta data.
            unsigned int offset = addon;
            SquidMetaList meta;
            while ( offset + addon <= datastart ) {
                unsigned int size = 0;
                memcpy( &size, linebuffer+offset+sizeof(char), sizeof(unsigned int) );
                if (size+offset < size) {
                    fputs("WARNING: file corruption detected. 32-bit overflow in size field.\n", stderr);
                    break;
                }
                if (size+offset > readLen) {
                    fputs( "WARNING: Partial meta data loaded.\n", stderr );
                    break;
                }
                meta.append( SquidMetaType(*(linebuffer+offset)),
                             size, linebuffer+offset+addon );
                offset += ( addon + size );
            }

            // Now extract the key URL from the meta data.
            const SquidTLV* urlmeta = meta.search( STORE_META_URL );
            if ( urlmeta ) {
                // found URL in meta data. Try to process the URL
                if ( list == 0 )
                    flag = action( fd, datastart, fn, (char*) urlmeta->data, meta );
                else {
                    REList* head = (REList*) list; // YUCK!
                    while ( head != 0 ) {
                        if ( head->match( (char*) urlmeta->data ) ) break;
                        head = head->next;
                    }
                    if ( head != 0 )
                        flag = action( fd, datastart, fn, (char*) urlmeta->data, meta );
                    else flag = true;
                }
            }

            // "meta" will be deleted when exiting from this block
        } else {
            // weird file, FIXME: stat() it!
            struct stat st;
            long size = ( fstat(fd,&st) == -1 ? -1 : st.st_size );
            if ( ::verbose ) flag = ( log_extended( fn, -1, size, 0 ) >= 0 );
            else flag = ( log_output( fn, -1, size, "strange file" ) >= 0 );

            if ( (::purgeMode & 0x04) ) {
                reminder = true;
                if ( unlink(fn) == -1 )
                    // error while unlinking file, this may happen due to the cache
                    // unlinking a file while it is in the readdir() cache of purge.
                    fprintf( stderr, "WARNING: unable to unlink %s: %s\n",
                             fn, strerror(errno) );
            }
        }
        close(fd);
    } else {
        // error while opening file, this may happen due to the cache
        // unlinking a file while it is still in the readdir() cache of purge.
        fprintf( stderr, "WARNING: open \"%s\": %s\n", fn, strerror(errno) );
    }

    return flag;
}

bool
filelevel( const char* directory, const REList* list )
// purpose: from given starting point, look for squid xxxxxxxx files.
// example: "/var/spool/cache/08/7F" as input, do action over files
// paramtr: directory (IN): starting point
//          list (IN): list of rexps to match URLs against
// returns: true, if every subdir && action was successful.
{
    dirent_t * entry;
    if ( debugFlag & 0x01 )
        fprintf( stderr, "# [2] %s\n", directory );

    DIR* dir = opendir( directory );
    if ( dir == NULL ) {
        fprintf( stderr, "unable to open directory \"%s\": %s\n",
                 directory, strerror(errno) );
        return false;
    }

    // display a rotating character as "i am alive" signal (slows purge).
    if ( ::iamalive ) {
        static char alivelist[4][3] = { "\\\b", "|\b", "/\b", "-\b" };
        static unsigned short alivecount = 0;
        const int write_success = write(STDOUT_FILENO, alivelist[alivecount++ & 3], 2);
        assert(write_success == 2);
    }

    bool flag = true;
    while ( (entry=readdir(dir)) && flag ) {
        if ( isxstring(entry->d_name,8) ) {
            char* name = concat( directory, "/", entry->d_name, 0 );
            flag = match( name, list );
            delete[] name;
        }
    }

    closedir(dir);
    return flag;
}

bool
dirlevel( const char* dirname, const REList* list, bool level=false )
// purpose: from given starting point, look for squid 00..FF directories.
// paramtr: dirname (IN): starting point
//          list (IN): list of rexps to match URLs against
//          level (IN): false==toplevel, true==1st level
// example: "/var/spool/cache", false as input, traverse subdirs w/ action.
// example: "/var/spool/cache/08", true as input, traverse subdirs w/ action.
// returns: true, if every subdir && action was successful.
// warning: this function is once-recursive, no deeper.
{
    dirent_t* entry;
    if ( debugFlag & 0x01 )
        fprintf( stderr, "# [%d] %s\n", (level ? 1 : 0), dirname );

    DIR* dir = opendir( dirname );
    if ( dir == NULL ) {
        fprintf( stderr, "unable to open directory \"%s\": %s\n",
                 dirname, strerror(errno) );
        return false;
    }

    bool flag = true;
    while ( (entry=readdir(dir)) && flag ) {
        if ( strlen(entry->d_name) == 2 &&
                isxdigit(entry->d_name[0]) &&
                isxdigit(entry->d_name[1]) ) {
            char* name = concat( dirname, "/", entry->d_name, 0 );
            flag = level ? filelevel( name, list ) : dirlevel( name, list, true );
            delete[] name;
        }
    }

    closedir(dir);
    return flag;
}

int
checkForPortOnly( const char* arg )
// purpose: see if somebody just put in a port instead of a hostname
// paramtr: optarg (IN): argument from commandline
// returns: 0..65535 is the valid port number in network byte order,
//          -1 if not a port
{
    // if there is a period in there, it must be a valid hostname
    if ( strchr( arg, '.' ) != 0 ) return -1;

    // if it is just a number between 0 and 65535, it must be a port
    char* errstr = 0;
    unsigned long result = strtoul( arg, &errstr, 0 );
    if ( result < 65536 && errstr != arg ) return htons(result);

#if 0
    // one last try, test for a symbolical service name
    struct servent* service = getservbyname( arg, "tcp" );
    return service ? service->s_port : -1;
#else
    return -1;
#endif
}

void
helpMe( void )
// purpuse: write help message and exit
{
    printf( "\nUsage:\t%s\t[-a] [-c cf] [-d l] [-(f|F) fn | -(e|E) re] "
            "[-p h[:p]]\n\t\t[-P #] [-s] [-v] [-C dir [-H]] [-n]\n\n",
            ::programname );
    printf(
        " -a\tdisplay a little rotating thingy to indicate that I am alive (tty only).\n"
        " -c c\tsquid.conf location, default \"%s\".\n"
        " -C dir\tbase directory for content extraction (copy-out mode).\n"
        " -d l\tdebug level, an OR mask of different debug options.\n"
        " -e re\tsingle regular expression per -e instance (use quotes!).\n"
        " -E re\tsingle case sensitive regular expression like -e.\n"
        " -f fn\tname of textfile containing one regular expression per line.\n"
        " -F fn\tname of textfile like -f containing case sensitive REs.\n"
        " -H\tprepend HTTP reply header to destination files in copy-out mode.\n"
        " -n\tdo not fork() when using more than one cache_dir.\n"
        " -p h:p\tcache runs on host h and optional port p, default is %s:%u.\n"
        " -P #\tif 0, just print matches; otherwise OR the following purge modes:\n"
        "\t   0x01 really send PURGE to the cache.\n"
        "\t   0x02 remove all caches files reported as 404 (not found).\n"
        "\t   0x04 remove all weird (inaccessible or too small) cache files.\n"
        "\t0 and 1 are recommended - slow rebuild your cache with other modes.\n"
        " -s\tshow all options after option parsing, but before really starting.\n"
        " -v\tshow more information about the file, e.g. MD5, timestamps and flags.\n"
        "\n", DEFAULT_SQUID_CONF, DEFAULTHOST, DEFAULTPORT );

}

void
parseCommandline( int argc, char* argv[], REList*& head,
                  char*& conffile, char*& copyDirPath,
                  struct in_addr& serverHostIp, unsigned short& serverHostPort )
// paramtr: argc: see ::main().
//          argv: see ::main().
// returns: Does terminate the program on errors!
// purpose: suck in any commandline options, and set the global vars.
{
    int option, port, showme = 0;
    char* ptr, *colon;
    FILE* rfile;

    // program basename
    if ( (ptr = strrchr(argv[0],'/')) == NULL )
        ptr=argv[0];
    else
        ++ptr;
    ::programname = ptr;

    // extract commandline parameters
    REList* tail = head = 0;
    opterr = 0;
    while ( (option = getopt( argc, argv, "ac:C:d:E:e:F:f:Hnp:P:sv" )) != -1 ) {
        switch ( option ) {
        case 'a':
            ::iamalive = ! ::iamalive;
            break;
        case 'C':
            if ( optarg && *optarg ) {
                if ( copyDirPath ) xfree( (void*) copyDirPath );
                copyDirPath = xstrdup(optarg);
                assert(copyDirPath);
            }
            break;
        case 'c':
            if ( !optarg || !*optarg ) {
                fprintf( stderr, "%c requires a regex pattern argument!\n", option );
                exit(1);
            }
            if ( *conffile ) xfree((void*) conffile);
            conffile = xstrdup(optarg);
            assert(conffile);
            break;

        case 'd':
            if ( !optarg || !*optarg ) {
                fprintf( stderr, "%c expects a mask parameter. Debug disabled.\n", option );
                ::debugFlag = 0;
            } else
                ::debugFlag = (strtoul(optarg, NULL, 0) & 0xFFFFFFFF);
            break;

        case 'E':
        case 'e':
            if ( !optarg || !*optarg ) {
                fprintf( stderr, "%c requires a regex pattern argument!\n", option );
                exit(1);
            }
            if ( head == 0 )
                tail = head = new REList( optarg, option=='E' );
            else {
                tail->next = new REList( optarg, option=='E' );
                tail = tail->next;
            }
            break;

        case 'f':
            if ( !optarg || !*optarg ) {
                fprintf( stderr, "%c requires a filename argument!\n", option );
                exit(1);
            }
            if ( (rfile = fopen( optarg, "r" )) != NULL ) {
                unsigned long lineno = 0;
#define LINESIZE 512
                char line[LINESIZE];
                while ( fgets( line, LINESIZE, rfile ) != NULL ) {
                    ++lineno;
                    int len = strlen(line)-1;
                    if ( len+2 >= LINESIZE ) {
                        fprintf( stderr, "%s:%lu: line too long, sorry.\n",
                                 optarg, lineno );
                        exit(1);
                    }

                    // remove trailing line breaks
                    while ( len > 0 && ( line[len] == '\n' || line[len] == '\r' ) ) {
                        line[len] = '\0';
                        --len;
                    }

                    // insert into list of expressions
                    if ( head == 0 ) tail = head = new REList(line,option=='F');
                    else {
                        tail->next = new REList(line,option=='F');
                        tail = tail->next;
                    }
                }
                fclose(rfile);
            } else
                fprintf( stderr, "unable to open %s: %s\n", optarg, strerror(errno));
            break;

        case 'H':
            ::envelope = ! ::envelope;
            break;
        case 'n':
            ::no_fork = ! ::no_fork;
            break;
        case 'p':
            if ( !optarg || !*optarg ) {
                fprintf( stderr, "%c requires a port argument!\n", option );
                exit(1);
            }
            colon = strchr( optarg, ':' );
            if ( colon == 0 ) {
                // no colon, only look at host

                // fix: see if somebody just put in there a port (no periods)
                // give port number precedence over host names
                port = checkForPortOnly( optarg );
                if ( port == -1 ) {
                    // assume that main() did set the default port
                    if ( convertHostname(optarg,serverHostIp) == -1 ) {
                        fprintf( stderr, "unable to resolve host %s!\n", optarg );
                        exit(1);
                    }
                } else {
                    // assume that main() did set the default host
                    serverHostPort = port;
                }
            } else {
                // colon used, port is extra
                *colon = 0;
                ++colon;
                if ( convertHostname(optarg,serverHostIp) == -1 ) {
                    fprintf( stderr, "unable to resolve host %s!\n", optarg );
                    exit(1);
                }
                if ( convertPortname(colon,serverHostPort) == -1 ) {
                    fprintf( stderr, "unable to resolve port %s!\n", colon );
                    exit(1);
                }
            }
            break;
        case 'P':
            if ( !optarg || !*optarg ) {
                fprintf( stderr, "%c requires a mode argument!\n", option );
                exit(1);
            }
            ::purgeMode = ( strtol( optarg, 0, 0 ) & 0x07 );
            break;
        case 's':
            showme=1;
            break;
        case 'v':
            ::verbose = ! ::verbose;
            break;
        case '?':
        default:
            helpMe();
            exit(1);
        }
    }

    // adjust
    if ( ! isatty(fileno(stdout)) || (::debugFlag & 0x01) ) ::iamalive = false;
    if ( head == 0 ) {
        fputs( "There was no regular expression defined. If you intend\n", stderr );
        fputs( "to match all possible URLs, use \"-e .\" instead.\n", stderr );
        exit(1);
    }

    // postcondition: head != 0
    assert( head != 0 );

    // make sure that the copy out directory is there and accessible
    if ( copyDirPath && *copyDirPath )
        if ( assert_copydir( copyDirPath ) != 0 ) exit(1);

    // show results
    if ( showme ) {
        printf( "#\n# Currently active values for %s:\n",
                ::programname);
        printf( "# Debug level       : " );
        if ( ::debugFlag ) printf( "%#6.4x", ::debugFlag );
        else printf( "production level" ); // printf omits 0x prefix for 0!
        printf( " + %s mode", ::no_fork ? "linear" : "parallel" );
        puts( ::verbose ? " + extra verbosity" : "" );

        printf( "# Copy-out directory: %s ",
                copyDirPath ? copyDirPath : "copy-out mode disabled" );
        if ( copyDirPath )
            printf( "(%s HTTP header)\n", ::envelope ? "prepend" : "no" );
        else
            puts("");

        printf( "# Squid config file : %s\n", conffile );
        printf( "# Cacheserveraddress: %s:%u\n",
                inet_ntoa( serverHostIp ), ntohs( serverHostPort ) );
        printf( "# purge mode        : 0x%02x\n", ::purgeMode );
        printf( "# Regular expression: " );

        unsigned count(0);
        for ( tail = head; tail != NULL; tail = tail->next ) {
            if ( count++ )
                printf( "#%22u", count );
#if defined(LINUX) && putc==_IO_putc
            // I HATE BROKEN LINUX HEADERS!
            // purge.o(.text+0x1040): undefined reference to `_IO_putc'
            // If your compilation breaks here, remove the undefinition
#undef putc
#endif
            else putchar('1');
            printf( " \"%s\"\n", tail->data );
        }
        puts( "#" );
    }
    fflush( stdout );
}

extern "C" {

    static
    void
    exiter( void ) {
        if ( ::term_flag ) psignal( ::term_flag, "received signal" );
        delete[] ::linebuffer;
        if ( ::reminder ) {
            fputs(
                "WARNING! Caches files were removed. Please shut down your cache, remove\n"
                "your swap.state files and restart your cache again, i.e. effictively do\n"
                "a slow rebuild your cache! Otherwise your squid *will* choke!\n", stderr );
        }
    }

    static
    void
    handler( int signo ) {
        ::term_flag = signo;
        if ( getpid() == getpgrp() ) kill( -getpgrp(), signo );
        exit(1);
    }

} // extern "C"

static
int
makelinebuffered( FILE* fp, const char* fn = 0 )
// purpose: make the given FILE line buffered
// paramtr: fp (IO): file pointer which to put into line buffer mode
//          fn (IN): name of file to print in case of error
// returns: 0 is ok, -1 to indicate an error
// warning: error messages will already be printed
{
    if ( setvbuf( fp, 0, _IOLBF, 0 ) == 0 ) {
        // ok
        return 0;
    } else {
        // error
        fprintf( stderr, "unable to make \"%s\" line buffered: %s\n",
                 fn ? fn : "", strerror(errno) );
        return -1;
    }
}

int
main( int argc, char* argv[] )
{
    // setup variables
    REList* list = 0;
    char* conffile = xstrdup( DEFAULT_SQUID_CONF );
    serverPort = htons(DEFAULTPORT);
    if ( convertHostname(DEFAULTHOST,serverHost) == -1 ) {
        fprintf( stderr, "unable to resolve host %s!\n", DEFAULTHOST );
        return 1;
    }

    // setup line buffer
    ::linebuffer = new char[ ::buffersize ];
    assert( ::linebuffer != 0 );

    // parse commandline
    puts( "### Use at your own risk! No guarantees whatsoever. You were warned. ###");
    parseCommandline( argc, argv, list, conffile, ::copydir,
                      serverHost, serverPort );

    // prepare execution
    if ( atexit( exiter ) != 0 ||
            Signal( SIGTERM, handler, true ) == SIG_ERR ||
            Signal( SIGINT, handler, true ) == SIG_ERR ||
            Signal( SIGHUP, handler, true ) == SIG_ERR ) {
        perror( "unable to install signal/exit function" );
        return 1;
    }

    // try to read squid.conf file to determine all cache_dir locations
    CacheDirVector cdv(0);
    if ( readConfigFile( cdv, conffile, debugFlag ? stderr : 0 ) > 0 ) {
        // there are some valid cache_dir entries.
        // unless forking was forbidden by cmdline option,
        // for a process for each cache_dir entry to remove files.

        if ( ::no_fork || cdv.size() == 1 ) {
            // linear mode, one cache_dir after the next
            for ( CacheDirVector::iterator i = cdv.begin(); i != cdv.end(); ++i ) {
                // execute OR complain
                if ( ! dirlevel(i->base,list) )
                    fprintf( stderr, "program terminated due to error: %s",
                             strerror(errno) );
                xfree((void*) i->base);
            }
        } else {
            // parallel mode, all cache_dir in parallel
            pid_t* child = new pid_t[ cdv.size() ];

            // make stdout/stderr line bufferd
            makelinebuffered( stdout, "stdout" );
            makelinebuffered( stderr, "stderr" );

            // make parent process group leader for easier killings
            if ( setpgid(getpid(), getpid()) != 0 ) {
                perror( "unable to set process group leader" );
                return 1;
            }

            // -a is mutually exclusive with fork mode
            if ( ::iamalive ) {
                puts( "# i-am-alive flag incompatible with fork mode, resetting" );
                ::iamalive = false;
            }

            for ( size_t i=0; i < cdv.size(); ++i ) {
                if ( getpid() == getpgrp() ) {
                    // only parent == group leader may fork off new processes
                    if ( (child[i]=fork()) < 0 ) {
                        // fork error, this is bad!
                        perror( "unable to fork" );
                        kill( -getpgrp(), SIGTERM );
                        return 1;
                    } else if ( child[i] == 0 ) {
                        // child mode
                        // execute OR complain
                        if ( ! dirlevel(cdv[i].base,list) )
                            fprintf( stderr, "program terminated due to error: %s\n",
                                     strerror(errno) );
                        xfree((void*) cdv[i].base);
                        return 0;
                    } else {
                        // parent mode
                        if ( ::debugFlag ) printf( "forked child %d\n", (int) child[i] );
                    }
                }
            }

            // collect the garbase
            pid_t temp;
            int status;
            for ( size_t i=0; i < cdv.size(); ++i ) {
                while ( (temp=waitpid( (pid_t)-1, &status, 0 )) == -1 )
                    if ( errno == EINTR ) continue;
                if ( ::debugFlag ) printf( "collected child %d\n", (int) temp );
            }
            delete[] child;
        }
    } else {
        fprintf( stderr, "no cache_dir or error accessing \"%s\"\n", conffile );
    }

    // clean up
    if ( copydir ) xfree( (void*) copydir );
    xfree((void*) conffile);
    delete list;
    return 0;
}

