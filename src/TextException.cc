#include "squid.h"
#include "TextException.h"

TextException::TextException()
{
	message=NULL;
	theFileName=NULL;
	theLineNo=0;
}

TextException::TextException(const TextException& right) :
	message((right.message?xstrdup(right.message):NULL)), theFileName(right.theFileName), theLineNo(right.theLineNo)
{
}

TextException::TextException(const char *aMsg, const char *aFileName, int aLineNo):
        message(xstrdup(aMsg)), theFileName(aFileName), theLineNo(aLineNo)
{}

TextException::~TextException() throw()
{
    if(message) xfree(message);
}

TextException& TextException::operator=(const TextException &right)
{
	if(this==&right) return *this;
	if(message) xfree(message);
    message=(right.message?xstrdup(right.message):NULL);
    theFileName=right.theFileName;
    theLineNo=right.theLineNo;

	return *this;	
}

const char *TextException::what() const throw()
{
    /// \todo add file:lineno
    return message ? message : "TextException without a message";
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
