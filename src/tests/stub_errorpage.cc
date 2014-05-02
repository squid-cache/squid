#include "squid.h"
#include "errorpage.h"

#define STUB_API "errorpage.cc"
#include "tests/STUB.h"

err_type errorReservePageId(const char *page_name) STUB_RETVAL(err_type())
void errorAppendEntry(StoreEntry * entry, ErrorState * err) STUB
bool strHdrAcptLangGetItem(const String &hdr, char *lang, int langLen, size_t &pos) STUB_RETVAL(false)
bool TemplateFile::loadDefault() STUB_RETVAL(false)
TemplateFile::TemplateFile(char const*, err_type) STUB
bool TemplateFile::loadFor(const HttpRequest *) STUB_RETVAL(false)
