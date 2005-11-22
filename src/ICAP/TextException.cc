#include "squid.h"
#include "TextException.h"

TextException::TextException(const char *aMsg, const char *aFileName, int aLineNo):
        message(xstrdup(aMsg)), theFileName(aFileName), theLineNo(aLineNo)
{}

TextException::~TextException()
{
    xfree(message);
}

void Throw(const char *message, const char *fileName, int lineNo)
{

    // or should we let the exception recepient print the exception instead?

    if (fileName) {
        debugs(0, 3, fileName << ':' << lineNo << ": exception" <<
               (message ? ": " : ".") << (message ? message : ""));
    } else {
        debugs(0, 3, "exception" <<
               (message ? ": " : ".") << (message ? message : ""));
    }

    throw TextException(message, fileName, lineNo);
}
