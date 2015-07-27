/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// Author:  Jens-S. V?ckler <voeckler@rvs.uni-hannover.de>
//
// File:    conffile.cc
//          Fri Sep 15 2000
//
// (c) 2000 Lehrgebiet Rechnernetze und Verteilte Systeme
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
// Revision 1.1  2000/09/21 09:44:53  voeckler
// Initial revision
//

#include "squid.h"
#include "conffile.hh"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <regex>
#include <sys/types.h>
#include <memory.h>

int
readConfigFile( CacheDirVector& cachedir, const char* fn, FILE* debug )
// purpose: read squid.conf file and extract cache_dir entries
// paramtr: cachedir (OUT): vector with an entry for each cache_dir found
//          fn (IN): file name of squid.conf to use
// returns: number of entries, or negative to warn of errors
{
    // try to open file
    if ( debug ) fprintf( debug, "# trying to open %s\n", fn ? fn : "(null)" );
    std::ifstream cfgin(fn);
    if (!cfgin) {
        fprintf( stderr, "fopen %s: %s\n", fn, strerror(errno) );
        return -1;
    }

    // prepare regular expression for matching
    static const char * expression = "^[ \t]*cache_dir([ \t]+([[:alpha:]]+))?[ \t]+([[:graph:]]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)";
    if ( debug ) fprintf( debug, "# trying to compile \"%s\"\n", expression );

    static const std::regex rexp(expression, std::regex::extended);

    // read line by line
    if ( debug ) fputs( "# trying to read lines\n", debug );

    std::smatch subs; // set of std::string so we can use ==
    char *s, line[1024];
    CacheDir cd;
    while ( cfgin.getline( line, sizeof(line)) ) {
        // FIXME: overly long lines

        // terminate line at start of comment
        if ( (s = (char*) memchr( line, '#', sizeof(line) )) ) *s = '\0';

        // quick skip
        if ( *line == '\0' || *line == '\n' ) continue;

        // test line
        std::string tmpLine(line);
        if (!std::regex_search(tmpLine, subs, rexp))
            continue;

        // match, please record
        memset( &cd, 0, sizeof(cd) );
        if ( debug ) fprintf( debug, "# match '%s' on line %s", subs[0].str().c_str(), line);

        // extract information. If 6th parenthesis is filled, this is
        // a new squid with disk types, otherwise it is an older version
        int offset = 2;
        if (subs[6].str().empty()) {
            // old version, disk type at position 2 is always UFS
            cd.type = CacheDir::CDT_UFS;
        } else {
            // new version, disk type at position 2
            if ( debug ) fprintf( debug, "# match '%s' in \"%s\"\n", subs[offset].str().c_str(), subs[0].str().c_str());
            static const std::string ufsDir("ufs",3);
            static const std::string aufsDir("aufs",4);
            static const std::string asyncUfsDir("asyncufs",8);
            static const std::string diskdDir("diskd",5);
            if (subs[offset] == ufsDir)
                cd.type = CacheDir::CDT_UFS;
            else if (subs[offset] == aufsDir || subs[offset] == asyncUfsDir)
                cd.type = CacheDir::CDT_AUFS;
            else if (subs[offset] == diskdDir)
                cd.type = CacheDir::CDT_DISKD;
            else
                cd.type = CacheDir::CDT_OTHER;
            ++offset;
        }

        // extract base directory
        if ( debug ) fprintf( debug, "# match '%s' in \"%s\"\n", subs[offset].str().c_str(), subs[0].str().c_str());
        cd.base = xstrdup(subs[offset].str().c_str());
        ++offset;

        // extract size information
        if ( debug ) fprintf( debug, "# match '%s' in \"%s\"\n", subs[offset].str().c_str(), subs[0].str().c_str());
        cd.size = strtoul(subs[offset].str().c_str(), 0, 10);
        ++offset;

        // extract 1st level directories
        if ( debug ) fprintf( debug, "# match '%s' in \"%s\"\n", subs[offset].str().c_str(), subs[0].str().c_str());
        cd.level[0] = strtoul(subs[offset].str().c_str(), 0, 10);
        ++offset;

        // extract 2nd level directories
        if ( debug ) fprintf( debug, "# match '%s' in \"%s\"\n", subs[offset].str().c_str(), subs[0].str().c_str());
        cd.level[1] = strtoul(subs[offset].str().c_str(), 0, 10);
        ++offset;

        cachedir.push_back( cd );
    }

    cfgin.close();
    return cachedir.size();
}

