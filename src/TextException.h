#ifndef SQUID__TEXTEXCEPTION_H
#define SQUID__TEXTEXCEPTION_H

// Origin: xstd/TextException


// simple exception to report custom errors
// we may want to change the interface to be able to report system errors

class TextException
{

public:
    TextException(const char *aMessage, const char *aFileName = 0, int aLineNo = -1);
    ~TextException();

    // ostream &print(ostream &os) const;

public:
    char *message; // read-only

protected:
    // optional location information
    const char *theFileName;
    int theLineNo;
};

//inline
//ostream &operator <<(ostream &os, const TextException &exx) {
//    return exx.print(os);
//}

#if !defined(TexcHere)
#    define TexcHere(msg) TextException((msg), __FILE__, __LINE__)
#endif

extern void Throw(const char *message, const char *fileName, int lineNo);

// Must(condition) is like assert(condition) but throws an exception instead
#if !defined(Must)
#   define Must(cond) ((cond) ? \
        (void)0 : \
        (void)Throw(#cond, __FILE__, __LINE__))
#endif

#endif /* SQUID__TEXTEXCEPTION_H */
