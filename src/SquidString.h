
/*
 * $Id: SquidString.h,v 1.1 2003/02/02 13:27:43 robertc Exp $
 *
 * DEBUG: section 67    String
 * AUTHOR: Duane Wessels
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

#ifndef SQUID_STRING_H
#define SQUID_STRING_H

class String {
public:
    static const String Null;
    _SQUID_INLINE_ String();
    String (char const *);
    String (String const &);
    ~String();
    
    String &operator =(char const *);
    String &operator =(String const &);
    
    _SQUID_INLINE_ int size() const;
    _SQUID_INLINE_ char const * buf() const;
    void init (char const *);
    void initBuf(size_t sz);
    void limitInit(const char *str, int len);
    void clean();
    void reset(char const *str);
    void append(char const *buf, int len);
    void append(char const *buf);
    void append (String const &);
    void absorb(String &old);
    _SQUID_INLINE_ int nCaseCmp (char const *aString, int aLen) const;
private:
    /* never reference these directly! */
    unsigned short int size_;	/* buffer size; 64K limit */
public:
    unsigned short int len_;	/* current length  */
    char *buf_;
};

#define StringNull String::Null;
/* String */
#define strChr(s,ch)  ((const char*)strchr((s).buf(), (ch)))
#define strRChr(s,ch) ((const char*)strrchr((s).buf(), (ch)))
#define strStr(s,str) ((const char*)strstr((s).buf(), (str)))
#define strCmp(s,str)     strcmp((s).buf(), (str))
#define strNCmp(s,str,n)     strncmp((s).buf(), (str), (n))
#define strCaseCmp(s,str) strcasecmp((s).buf(), (str))
#define strSet(s,ptr,ch) (s).buf_[ptr-(s).buf_] = (ch)
#define strCut(s,pos) (((s).len_ = pos) , ((s).buf_[pos] = '\0'))
#define strCutPtr(s,ptr) (((s).len_ = (ptr)-(s).buf_) , ((s).buf_[(s).len_] = '\0'))

#ifdef _USE_INLINE_
#include "String.cci"
#endif

#endif /* SQUID_STRING_H */

