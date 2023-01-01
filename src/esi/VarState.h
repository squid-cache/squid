/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ESIVARSTATE_H
#define SQUID_ESIVARSTATE_H

#include "esi/Segment.h"
#include "HttpHeader.h"
#include "libTrie/Trie.h"

#include <vector>

class HttpReply;

/* esi variable replacement logic */

typedef enum {
    ESI_BROWSER_MSIE,
    ESI_BROWSER_MOZILLA,
    ESI_BROWSER_OTHER
} esiBrowser_t;

extern char const * esiBrowsers[];

/* Recursive uses are not supported by design */

struct _query_elem {char *var, *val;};

class ESIVarState
{
    CBDATA_CLASS(ESIVarState);

public:
    ESIVarState(HttpHeader const *hdr, char const *uri);
    ~ESIVarState();

    ESISegment::Pointer extractList();
    char *extractChar();
    void feedData (const char *buf, size_t len);
    void buildVary (HttpReply *rep);

    class Variable;
    void addVariable (char const *, size_t, Variable *);
    void removeVariable (String const &);

    /* For Variables */
    void cookieUsed();
    void hostUsed();
    void languageUsed();
    void refererUsed();
    void useragentUsed();
    ESISegment::Pointer &getOutput();
    HttpHeader &header();

private:
    ESISegment::Pointer input;
    ESISegment::Pointer output;
    HttpHeader hdr;

    struct {
        int language:1;
        int cookie:1;
        int host:1;
        int referer:1;
        int useragent:1;
    } flags;

public:

    class Variable
    {

    public:
        Variable () {}

        virtual ~Variable() {}

        /* prevent synthetics */
        Variable (Variable const &) {}

        Variable &operator= (Variable const &);
        virtual void eval (ESIVarState &state, char const *, char const *) const;
    };

    Variable* GetVar(char const *s, int len);

private:
    void doIt ();
    void setupUserAgent();
    Trie variables;
    std::vector<Variable*> variablesForCleanup;
    Variable *defaultVariable;
};

class ESIVariableCookie : public ESIVarState::Variable
{

public:
    virtual void eval (ESIVarState &state, char const *, char const *) const;
};

class ESIVariableHost : public ESIVarState::Variable
{

public:
    virtual void eval (ESIVarState &state, char const *, char const *) const;
};

class ESIVariableLanguage : public ESIVarState::Variable
{

public:
    virtual void eval (ESIVarState &state, char const *, char const *) const;
};

class ESIVariableQuery : public ESIVarState::Variable
{

public:
    ESIVariableQuery(char const *uri);
    ~ESIVariableQuery();
    virtual void eval (ESIVarState &state, char const *, char const *) const;
    char const *queryString() const;

    struct _query_elem const *queryVector() const;
    size_t const &queryElements() const;

    struct _query_elem *query;
    size_t query_sz;
    size_t query_elements;
    char *query_string;
};

class ESIVariableReferer : public ESIVarState::Variable
{

public:
    virtual void eval (ESIVarState &state, char const *, char const *) const;
};

class ESIVariableUserAgent : public ESIVarState::Variable
{

public:
    ~ESIVariableUserAgent();
    ESIVariableUserAgent (ESIVarState &state);
    virtual void eval (ESIVarState &state, char const *, char const *) const;

private:
    static char const * esiUserOs[];
    enum esiUserOs_t {
        ESI_OS_WIN,
        ESI_OS_MAC,
        ESI_OS_UNIX,
        ESI_OS_OTHER
    };
    esiUserOs_t identifyOs(char const *) const;
    char const *browserVersion() const {return browserversion;}

    char *getProductVersion (char const *s);
    esiUserOs_t UserOs;
    esiBrowser_t browser;
    char *browserversion;
};

#endif /* SQUID_ESIVARSTATE_H */

