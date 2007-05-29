
/*
 * $Id: ESIVarState.h,v 1.4 2007/05/29 13:31:37 amosjeffries Exp $
 *
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

#ifndef SQUID_ESIVARSTATE_H
#define SQUID_ESIVARSTATE_H

#include "ESISegment.h"
#include "Trie.h"
#include "Array.h"
#include "HttpHeader.h"

/* esi variable replacement logic */

typedef enum {
    ESI_BROWSER_MSIE,
    ESI_BROWSER_MOZILLA,
    ESI_BROWSER_OTHER
} esiBrowser_t;

extern char const * esiBrowsers[];

/* Recursive uses are not supported by design */

struct _query_elem{char *var, *val;};

class ESIVarState
{

public:
    ESISegment::Pointer extractList();
    char *extractChar();
    void feedData (const char *buf, size_t len);
    void buildVary (HttpReply *rep);

    class Variable;
    void addVariable (char const *, size_t, Variable *);
    void removeVariable (String const &);

    void *operator new (size_t byteCount);
    void operator delete (void *address);
    void freeResources();
    ESIVarState (HttpHeader const *hdr, char const *uri);
    ~ESIVarState();

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

    struct
    {

int language:
        1;

int cookie:
        1;

int host:
        1;

int referer:
        1;

int useragent:
        1;
    }

    flags;

public:

    class Variable
    {

    public:
        Variable () {}

        virtual ~Variable(){}

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
    Vector<Variable*> variablesForCleanup;
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
    enum esiUserOs_t{
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
