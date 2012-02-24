#include "squid.h"
#include "wordlist.h"

#define STUB_API "wordlist.cc"
#include "tests/STUB.h"

const char *wordlistAdd(wordlist **, const char *) STUB_RETVAL(NULL)
void wordlistAddWl(wordlist **, wordlist *) STUB
void wordlistJoin(wordlist **, wordlist **) STUB
wordlist *wordlistDup(const wordlist *) STUB_RETVAL(NULL)
void wordlistDestroy(wordlist **) STUB
