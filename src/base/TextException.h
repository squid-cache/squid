/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__TEXTEXCEPTION_H
#define SQUID__TEXTEXCEPTION_H

// Origin: xstd/TextException

#include <exception>

static unsigned int FileNameHashCached(const char *fname);

// simple exception to report custom errors
// we may want to change the interface to be able to report system errors

class TextException: public std::exception
{

public:
    TextException();
    TextException(const char *aMessage, const char *aFileName = 0, int aLineNo = -1, unsigned int anId =0);
    TextException(const TextException& right);
    virtual ~TextException() throw();

    // unique exception ID for transaction error detail logging
    unsigned int id() const { return theId; }

    virtual const char *what() const throw();

    TextException& operator=(const TextException &right);

public:
    char *message; // read-only

protected:
    /// a small integer hash value to semi-uniquely identify the source file
    static unsigned int FileNameHash(const char *fname);

    // optional location information
    const char *theFileName;
    int theLineNo;
    unsigned int theId;

    friend unsigned int FileNameHashCached(const char *fname);
};

//inline
//ostream &operator <<(ostream &os, const TextException &exx) {
//    return exx.print(os);
//}

/// caches the result of FileNameHash() for each translation unit
static unsigned int
FileNameHashCached(const char *fname)
{
    static const char *lastFname = 0;
    static int lastHash = 0;
    // __FILE__ changes when we #include files
    if (lastFname != fname) { // cheap pointer comparison
        lastFname = fname;
        lastHash = TextException::FileNameHash(fname);
    }
    return lastHash;
}

///  Avoids "defined but not used" warnings for FileNameHashCached
class FileNameHashCacheUser
{
    bool use(void *ptr=NULL) { return ptr != (void*)&FileNameHashCached; }
};

#if !defined(TexcHere)
#    define TexcHere(msg) TextException((msg), __FILE__, __LINE__, \
                                         (FileNameHashCached(__FILE__)<<14) | (__LINE__ & 0x3FFF))
#endif

void Throw(const char *message, const char *fileName, int lineNo, unsigned int id);

// Must(condition) is like assert(condition) but throws an exception instead
#if !defined(Must)
#   define Must(cond) ((cond) ? \
        (void)0 : \
                      (void)Throw(#cond, __FILE__, __LINE__, \
                                  (FileNameHashCached(__FILE__)<<14) | (__LINE__ & 0x3FFF)))
#endif

#endif /* SQUID__TEXTEXCEPTION_H */

