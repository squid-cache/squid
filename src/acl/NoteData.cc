#include "squid.h"
#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/NoteData.h"
#include "acl/StringData.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "HttpRequest.h"
#include "Notes.h"
#include "wordlist.h"

ACLNoteData::ACLNoteData() : values(new ACLStringData)
{}

ACLNoteData::~ACLNoteData()
{
    delete values;
}

bool
ACLNoteData::matchNotes(NotePairs *note)
{
    if (note == NULL)
        return false;

    debugs(28, 3, "Checking " << name);

    if (values->empty())
        return (note->findFirst(name.termedBuf()) != NULL);

    for (Vector<NotePairs::Entry *>::iterator i = note->entries.begin(); i!= note->entries.end(); ++i) {
        if ((*i)->name.cmp(name.termedBuf()) == 0) {
            if (values->match((*i)->value.termedBuf()))
                return true;
        }
    }
    return false;
}

bool
ACLNoteData::match(HttpRequest *request)
{
    if (request->notes != NULL && matchNotes(request->notes.getRaw()))
        return true;
#if USE_ADAPTATION
    const Adaptation::History::Pointer ah = request->adaptLogHistory();
    if (ah != NULL && ah->metaHeaders != NULL && matchNotes(ah->metaHeaders.getRaw()))
        return true;
#endif
    return false;
}

wordlist *
ACLNoteData::dump()
{
    wordlist *W = NULL;
    wordlistAdd(&W, name.termedBuf());
    wordlist * dumpR = values->dump();
    wordlistAddWl(&W, dumpR);
    wordlistDestroy(&dumpR);
    return W;
}

void
ACLNoteData::parse()
{
    char* t = strtokFile();
    assert (t != NULL);
    name = t;
    values->parse();
}

bool
ACLNoteData::empty() const
{
    return name.undefined();
}

ACLData<HttpRequest *> *
ACLNoteData::clone() const
{
    ACLNoteData * result = new ACLNoteData;
    result->values = values->clone();
    result->name = name;
    return result;
}
