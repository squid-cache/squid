
/*
 * $Id: SquidString.h,v 1.9 2007/05/18 06:41:23 amosjeffries Exp $
 *
 * DEBUG: section 67    String
 * AUTHOR: Duane Wessels, Amos Jeffries
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

/**
 *
 *  To allow for easy future updates to the string handling within squid
 *  We adopt the std::string API as the basis for string operations.
 *  Then we typedef string (due to namespacing actually ::Squid::string)
 *  as the preferred string handling class.
 *  For Release 3.0 it is intended that the old String (no SquidString)
 *  Will be the default string type.
 *  For Release 3.1 it is expected that either std::string of another
 *  custom managed type will be defined as default.
 *
 *  NP: checkout http://johnpanzer.com/tsc_cuj/ToolboxOfStrings.html
 *      for possibly better and faster strings.
 *
 *  This has been done for several reasons:
 * 
 *  The initial String implementation was incomplete and non-standard
 *  std::string provides a better known API for string handling
 *  std::string or a derivative may be used in future within squid
 *  String is a defined alternative to std::string in some systems
 *  
 *  These changes:
 *    - move the old String class to SquidString making the
 *      internal definition explicit.
 *    - provide the well-known type of 'string' for general use
 *    - migrate custom functions to well-known API:
 *        buf()           -> c_str()
 *        clean()         -> clear()
 *    - remove redundant functions:
 *        buf(char*)      -> operator=(char*)
 *        initBuf(char*)  -> operator=(char*)
 *        reset(char*)    -> operator=(char*)
 *    - make init(char*) private for use by various assignment/costructor
 *    - define standard string operators
 *    - define debugs stream operator
 *
 */

#ifndef SQUID_STRING_H
#define SQUID_STRING_H

    /* Provide standard 'string' type                                                */
    /* class defined by the #include file MUST present the basic std::string API     */
    /* at least partially as not all operatios are used by squid.                    */
    /* API Ref:  http://www.sgi.com/tech/stl/basic_string.html                       */

#include "SqString.h"
typedef SqString string;


    /* Overload standard C functions using the basic string API */

inline int strncasecmp(const string &lhs, const string &rhs, size_t len) { return strncasecmp(lhs.c_str(), rhs.c_str(), len); }
inline int strcasecmp(const string &lhs, const string &rhs) { return strcasecmp(lhs.c_str(), rhs.c_str()); }

inline int strncmp(const string &lhs, const string &rhs, size_t len) { return strncmp(lhs.c_str(), rhs.c_str(), len); }
inline int strcmp(const string &lhs, const string &rhs) { return strcmp(lhs.c_str(), rhs.c_str()); }

inline const char * strpbrk(const string &lhs, const string &rhs) { return strpbrk(lhs.c_str(), rhs.c_str()); }

inline const char * strstr(const string &lhs, const string &rhs) { return strstr(lhs.c_str(), rhs.c_str()); }

inline std::ostream& operator <<(std::ostream &os, const string &s) { os << s.c_str(); return os; }

#endif /* SQUID_STRING_H */
