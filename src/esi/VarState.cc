/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#include "squid.h"
#include "esi/VarState.h"
#include "fatal.h"
#include "HttpReply.h"

char const *ESIVariableUserAgent::esiUserOs[]= {
    "WIN",
    "MAC",
    "UNIX",
    "OTHER"
};

char const * esiBrowsers[]= {"MSIE",
                             "MOZILLA",
                             "OTHER"
                            };

CBDATA_CLASS_INIT(ESIVarState);

void
ESIVarState::Variable::eval (ESIVarState &state, char const *subref, char const *found_default) const
{
    /* No-op. We swallow it */

    if (found_default)
        ESISegment::ListAppend (state.getOutput(), found_default, strlen (found_default));
}

void
ESIVarState::hostUsed()
{
    flags.host = 1;
}

void
ESIVarState::cookieUsed()
{
    flags.cookie = 1;
}

void
ESIVarState::languageUsed()
{
    flags.language = 1;
}

void
ESIVarState::refererUsed()
{
    flags.referer = 1;
}

void
ESIVarState::useragentUsed()
{
    flags.useragent = 1;
}

HttpHeader &
ESIVarState::header()
{
    return hdr;
}

ESISegment::Pointer &
ESIVarState::getOutput()
{
    return output;
}

char const *
ESIVariableQuery::queryString() const
{
    return query_string;
}

struct _query_elem const *
ESIVariableQuery::queryVector() const {
    return query;
}

size_t const &
ESIVariableQuery::queryElements() const
{
    return query_elements;
}

void
ESIVarState::feedData (const char *buf, size_t len)
{
    /* TODO: if needed - tune to skip segment iteration */
    debugs (86,6, "esiVarState::feedData: accepting " << len << " bytes");
    ESISegment::ListAppend (input, buf, len);
}

ESISegment::Pointer
ESIVarState::extractList()
{
    doIt();
    ESISegment::Pointer rv = output;
    output = NULL;
    debugs(86, 6, "ESIVarStateExtractList: Extracted list");
    return rv;
}

char *
ESIVarState::extractChar ()
{
    if (!input.getRaw())
        fatal ("Attempt to extract variable state with no data fed in \n");

    doIt();

    char *rv = output->listToChar();

    ESISegmentFreeList (output);

    debugs(86, 6, "ESIVarStateExtractList: Extracted char");

    return rv;
}

ESIVarState::~ESIVarState()
{
    // freeResources
    input = NULL;
    ESISegmentFreeList(output);
    hdr.clean();

    while (!variablesForCleanup.empty()) {
        delete variablesForCleanup.back();
        variablesForCleanup.pop_back();
    }

    delete defaultVariable;
}

char *
ESIVariableUserAgent::getProductVersion (char const *s)
{
    char const *t;
    int len;
    t = index(s,'/');

    if (!t || !*(++t))
        return xstrdup("");

    len = strcspn(t, " \r\n()<>@,;:\\\"/[]?={}");

    return xstrndup(t, len + 1);
}

ESIVariableQuery::ESIVariableQuery(char const *uri) : query (NULL), query_sz (0), query_elements (0), query_string (NULL)
{
    /* Count off the query elements */
    char const *query_start = strchr (uri, '?');

    if (query_start && query_start[1] != '\0' ) {
        unsigned int n;
        query_string = xstrdup(query_start + 1);
        query_elements = 1;
        char const *query_pos = query_start + 1;

        while ((query_pos = strchr(query_pos, '&'))) {
            ++query_elements;
            ++query_pos;
        }

        query = (_query_elem *)memReallocBuf(query, query_elements * sizeof (struct _query_elem),
                                             &query_sz);
        query_pos = query_start + 1;
        n = 0;

        while (query_pos) {
            char const *next = strchr(query_pos, '&');
            char const *div = strchr(query_pos, '=');

            if (next)
                ++next;

            assert (n < query_elements);

            if (!div)
                div = next;

            if (!(div - query_pos + 1))
                /* zero length between & and = or & and & */
                continue;

            query[n].var = xstrndup(query_pos, div - query_pos + 1) ;

            if (div == next) {
                query[n].val = xstrdup("");
            } else {
                query[n].val = xstrndup(div + 1, next - div - 1);
            }

            query_pos = next;
            ++n;
        }
    } else {
        query_string = xstrdup("");
    }

    if (query) {
        unsigned int n = 0;
        debugs(86, 6, "esiVarStateNew: Parsed Query string: '" << uri << "'");

        while (n < query_elements) {
            debugs(86, 6, "esiVarStateNew: Parsed Query element " << n + 1 << " '" << query[n].var << "'='" << query[n].val << "'");
            ++n;
        }
    }
}

ESIVariableQuery::~ESIVariableQuery()
{
    if (query) {
        unsigned int i;

        for (i = 0; i < query_elements; ++i) {
            safe_free(query[i].var);
            safe_free(query[i].val);
        }

        memFreeBuf (query_sz, query);
    }

    safe_free (query_string);
}

ESIVarState::ESIVarState(HttpHeader const *aHeader, char const *uri) :
    output(NULL),
    hdr(hoReply)
{
    memset(&flags, 0, sizeof(flags));

    /* TODO: only grab the needed headers */
    /* Note that as we pass these through to included requests, we
     * cannot trim them */
    hdr.append(aHeader);

    /* populate our variables trie with the available variables.
     * Additional ones can be added during the parsing.
     * If there is a lazy evaluation approach to this, consider it!
     */
    defaultVariable = new Variable;
    addVariable ("HTTP_ACCEPT_LANGUAGE", 20, new ESIVariableLanguage);
    addVariable ("HTTP_COOKIE", 11, new ESIVariableCookie);
    addVariable ("HTTP_HOST", 9, new ESIVariableHost);
    addVariable ("HTTP_REFERER", 12, new ESIVariableReferer);
    addVariable ("HTTP_USER_AGENT", 15, new ESIVariableUserAgent(*this));
    addVariable ("QUERY_STRING", 12, new ESIVariableQuery(uri));
}

void
ESIVarState::removeVariable (String const &name)
{
    Variable *candidate = static_cast <Variable *>(variables.find (name.rawBuf(), name.size()));

    if (candidate) {
        /* XXX: remove me */
        /* Note - this involves:
         * extend libTrie to have a remove() call.
         * delete from the vector.
         * delete the object.
         */
    }
}

void
ESIVarState::addVariable(char const *name, size_t len, Variable *aVariable)
{
    String temp;
    temp.assign(name, len);
    removeVariable (temp);
    variables.add(name, len, aVariable);
    variablesForCleanup.push_back(aVariable);
}

ESIVariableUserAgent::~ESIVariableUserAgent()
{
    safe_free (browserversion);
}

ESIVariableUserAgent::ESIVariableUserAgent(ESIVarState &state)
{
    /* An example:
     *    User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.0.3705) */
    /* Grr this Node is painful - RFC 2616 specifies that 'by convention' the tokens are in order of importance
     * in identifying the product. According to the RFC the above should be interpreted as:
     * Product - Mozilla version 4.0
     * in comments - compatible; .... 3705
     *
     * Useing the RFC a more appropriate header would be
     *    User-Agent: MSIE/6.0 Mozilla/4.0 Windows-NT/5.1 .NET-CLR/1.0.3705
     *    or something similar.
     *
     * Because we can't parse under those rules and get real-world useful answers, we follow the following
     * algorithm:
     * if the string Windows appears in the header, the OS is WIN.
     * If the string Mac appears in the header, the OS is MAC.
     * If the string nix, or BSD appears in the header, the OS is UNIX.
     * If the string MSIE appears in the header, the BROWSER is MSIE, and the version is the string from
     * MSIE<sp> to the first ;, or end of string.
     * If the String MSIE does not appear in the header, and MOZILLA does, we use the version from the
     * /version field.
     * if MOZILLA doesn't appear, the browser is set to OTHER.
     * In future, this may be better implemented as a regexp.
     */

    if (state.header().has(Http::HdrType::USER_AGENT)) {
        char const *s = state.header().getStr(Http::HdrType::USER_AGENT);
        UserOs = identifyOs(s);
        char const *t, *t1;

        /* Now the browser and version */

        if ((t = strstr (s, "MSIE"))) {
            browser = ESI_BROWSER_MSIE;
            t = index (t, ' ');

            if (!t)
                browserversion = xstrdup("");
            else {
                t1 = index(t, ';');

                if (!t1)
                    browserversion = xstrdup(t + 1);
                else
                    browserversion = xstrndup(t + 1, t1-t);
            }
        } else if (strstr (s, "Mozilla")) {
            browser = ESI_BROWSER_MOZILLA;
            browserversion = getProductVersion(s);
        } else {
            browser = ESI_BROWSER_OTHER;
            browserversion = getProductVersion(s);
        }
    } else {
        UserOs = ESI_OS_OTHER;
        browser = ESI_BROWSER_OTHER;
        browserversion = xstrdup("");
    }
}

ESIVariableUserAgent::esiUserOs_t
ESIVariableUserAgent::identifyOs(char const *s) const
{
    if (!s)
        return ESI_OS_OTHER;

    if (strstr (s, "Windows"))
        return ESI_OS_WIN;
    else if (strstr (s, "Mac"))
        return ESI_OS_MAC;
    else if (strstr (s, "nix") || strstr (s, "BSD"))
        return ESI_OS_UNIX;
    else
        return ESI_OS_OTHER;
}

void
ESIVariableCookie::eval (ESIVarState &state, char const *subref, char const *found_default) const
{
    const char *s = NULL;
    state.cookieUsed();

    if (state.header().has(Http::HdrType::COOKIE)) {
        if (!subref)
            s = state.header().getStr (Http::HdrType::COOKIE);
        else {
            const auto subCookie = state.header().getListMember(Http::HdrType::COOKIE, subref, ';');

            if (subCookie.length())
                ESISegment::ListAppend(state.getOutput(), subCookie.rawContent(), subCookie.length());
            else if (found_default)
                ESISegment::ListAppend (state.getOutput(), found_default, strlen (found_default));
        }
    } else
        s = found_default;

    if (s)
        ESISegment::ListAppend (state.getOutput(), s, strlen (s));
}

void
ESIVariableHost::eval (ESIVarState &state, char const *subref, char const *found_default) const
{
    const char *s = NULL;
    state.hostUsed();

    if (!subref && state.header().has(Http::HdrType::HOST)) {
        s = state.header().getStr (Http::HdrType::HOST);
    } else
        s = found_default;

    ESISegment::ListAppend (state.getOutput(), s, strlen (s));
}

void
ESIVariableLanguage::eval (ESIVarState &state, char const *subref, char const *found_default) const
{
    char const *s = NULL;
    state.languageUsed();

    if (state.header().has(Http::HdrType::ACCEPT_LANGUAGE)) {
        if (!subref) {
            String S (state.header().getList (Http::HdrType::ACCEPT_LANGUAGE));
            ESISegment::ListAppend (state.getOutput(), S.rawBuf(), S.size());
        } else {
            if (state.header().hasListMember (Http::HdrType::ACCEPT_LANGUAGE, subref, ',')) {
                s = "true";
            } else {
                s = "false";
            }

            ESISegment::ListAppend (state.getOutput(), s, strlen (s));
        }
    } else {
        s = found_default;
        ESISegment::ListAppend (state.getOutput(), s, strlen (s));
    }
}

void
ESIVariableQuery::eval (ESIVarState &state, char const *subref, char const *found_default) const
{
    char const *s = NULL;

    if (!subref)
        s = queryString();
    else {
        unsigned int i = 0;

        while (i < queryElements() && !s) {
            if (!strcmp (subref, queryVector()[i].var))
                s = queryVector()[i].val;

            ++i;
        }

        if (!s)
            s = found_default;
    }

    ESISegment::ListAppend (state.getOutput(), s, strlen (s));
}

void
ESIVariableReferer::eval (ESIVarState &state, char const *subref, char const *found_default) const
{
    const char *s = NULL;
    state.refererUsed();

    if (!subref && state.header().has(Http::HdrType::REFERER))
        s = state.header().getStr (Http::HdrType::REFERER);
    else
        s = found_default;

    ESISegment::ListAppend (state.getOutput(), s, strlen (s));
}

void
ESIVariableUserAgent::eval (ESIVarState &state, char const *subref, char const *found_default) const
{
    char const *s = NULL;
    state.useragentUsed();

    if (state.header().has(Http::HdrType::USER_AGENT)) {
        if (!subref)
            s = state.header().getStr (Http::HdrType::USER_AGENT);
        else {
            if (!strcmp (subref, "os")) {
                s = esiUserOs[UserOs];
            } else if (!strcmp (subref, "browser")) {
                s = esiBrowsers[browser];
            } else if (!strcmp (subref, "version")) {
                s = browserVersion();
            } else
                s = "";
        }
    } else
        s = found_default;

    ESISegment::ListAppend (state.getOutput(), s, strlen (s));
}

/* thoughts on long term:
 * get $
 * get () handler
 * hand off to handler.
 * one handler for variables.
 * one handler for each function.
 */

class ESIVariableProcessor;

class ESIFunction
{

public:
    static ESIFunction *GetFunction (char const *symbol, ESIVariableProcessor &);
    ESIFunction(ESIVariableProcessor &);
    void doIt();

private:
    ESIVariableProcessor &processor;

};

ESIFunction::ESIFunction(ESIVariableProcessor &aProcessor) : processor(aProcessor)
{}

ESIFunction *
ESIFunction::GetFunction(char const *symbol, ESIVariableProcessor &aProcessor)
{
    if (*symbol == '(')
        return new ESIFunction(aProcessor);

    return NULL;
}

class ESIVariableProcessor
{

public:
    ESIVariableProcessor(char *, ESISegment::Pointer &, Trie &, ESIVarState *);
    ~ESIVariableProcessor();
    void doIt();

private:
    bool validChar (char c);
    void eval (ESIVarState::Variable *var, char const *subref, char const *foundDefault );
    void doFunction();
    void identifyFunction();
    char *string;
    ESISegment::Pointer &output;
    Trie &variables;
    ESIVarState *varState;
    int state;
    size_t len;
    size_t pos;
    size_t var_pos;
    size_t done_pos;
    char * found_subref;
    char *found_default;
    ESIVarState::Variable *vartype;
    ESIFunction *currentFunction;
};

void
ESIVariableProcessor::eval (ESIVarState::Variable *var, char const *subref, char const *foundDefault )
{
    assert (var);

    if (!foundDefault)
        foundDefault = "";

    var->eval (*varState, subref, foundDefault);
}

bool
ESIVariableProcessor::validChar (char c)
{
    if (('A' <= c && c <= 'Z') ||
            ('a' <= c && c <= 'z') ||
            '_' == c || '-' == c)
        return true;

    return false;
}

ESIVarState::Variable *
ESIVarState::GetVar(char const *symbol, int len)
{
    assert (symbol);

    void *result = variables.find (symbol, len);

    if (result)
        return static_cast<Variable *>(result);

    return defaultVariable;
}

void
ESIVarState::doIt ()
{
    char *string = input->listToChar();
    ESISegmentFreeList (input);
    ESIVariableProcessor theProcessor(string, output, variables, this);
    theProcessor.doIt();
    safe_free(string);
}

#define LOOKFORSTART 0
ESIVariableProcessor::ESIVariableProcessor(char *aString, ESISegment::Pointer &aSegment, Trie &aTrie, ESIVarState *aState) :
    string(aString), output (aSegment), variables(aTrie), varState (aState),
    state(LOOKFORSTART), pos(0), var_pos(0), done_pos(0), found_subref (NULL),
    found_default (NULL), currentFunction(NULL)
{
    len = strlen (string);
    vartype = varState->GetVar("",0);
}

void
ESIFunction::doIt()
{}

/* because we are only used to process:
 * - include URL's
 * - non-esi elements
 * - choose clauses
 * buffering is ok - we won't delay the start of async activity, or
 * of output data preparation
 */
/* Should make these an enum or something...
 */
void
ESIVariableProcessor::doFunction()
{
    if (!currentFunction)
        return;

    /* stay in here whilst operating */
    while (pos < len && state)
        switch (state) {

        case 2: /* looking for variable name */

            if (!validChar(string[pos])) {
                /* not a variable name char */

                if (pos - var_pos) {
                    vartype = varState->GetVar (string + var_pos, pos - var_pos);
                }

                state = 3;
            } else {
                ++pos;
            }

            break;

        case 3: /* looking for variable subref, end bracket or default indicator */

            if (string[pos] == ')') {
                /* end of string */
                eval(vartype, found_subref, found_default);
                done_pos = ++pos;
                safe_free(found_subref);
                safe_free(found_default);
                state = LOOKFORSTART;
            } else if (!found_subref && !found_default && string[pos] == '{') {
                debugs(86, 6, "ESIVarStateDoIt: Subref of some sort");
                /* subreference of some sort */
                /* look for the entry name */
                var_pos = ++pos;
                state = 4;
            } else if (!found_default && string[pos] == '|') {
                debugs(86, 6, "esiVarStateDoIt: Default present");
                /* extract default value */
                state = 5;
                var_pos = ++pos;
            } else {
                /* unexpected char, not a variable after all */
                debugs(86, 6, "esiVarStateDoIt: unexpected char after varname");
                state = LOOKFORSTART;
                pos = done_pos + 2;
            }

            break;

        case 4: /* looking for variable subref */

            if (string[pos] == '}') {
                /* end of subref */
                found_subref = xstrndup (&string[var_pos], pos - var_pos + 1);
                debugs(86, 6, "esiVarStateDoIt: found end of variable subref '" << found_subref << "'");
                state = 3;
                ++pos;
            } else if (!validChar (string[pos])) {
                debugs(86, 6, "esiVarStateDoIt: found invalid char in variable subref");
                /* not a valid subref */
                safe_free(found_subref);
                state = LOOKFORSTART;
                pos = done_pos + 2;
            } else {
                ++pos;
            }

            break;

        case 5: /* looking for a default value */

            if (string[pos] == '\'') {
                /* begins with a quote */
                debugs(86, 6, "esiVarStateDoIt: found quoted default");
                state = 6;
                var_pos = ++pos;
            } else {
                /* doesn't */
                debugs(86, 6, "esiVarStateDoIt: found unquoted default");
                state = 7;
                ++pos;
            }

            break;

        case 6: /* looking for a quote terminate default value */

            if (string[pos] == '\'') {
                /* end of default */
                found_default = xstrndup (&string[var_pos], pos - var_pos + 1);
                debugs(86, 6, "esiVarStateDoIt: found end of quoted default '" << found_default << "'");
                state = 3;
            }

            ++pos;
            break;

        case 7: /* looking for } terminate default value */

            if (string[pos] == ')') {
                /* end of default - end of variable*/
                found_default = xstrndup (&string[var_pos], pos - var_pos + 1);
                debugs(86, 6, "esiVarStateDoIt: found end of variable (w/ unquoted default) '" << found_default << "'");
                eval(vartype,found_subref, found_default);
                done_pos = ++pos;
                safe_free(found_default);
                safe_free(found_subref);
                state = LOOKFORSTART;
            }

            ++pos;
            break;

        default:
            fatal("esiVarStateDoIt: unexpected state\n");
        }
}

void
ESIVariableProcessor::identifyFunction()
{
    delete currentFunction;
    currentFunction = ESIFunction::GetFunction (&string[pos], *this);

    if (!currentFunction) {
        state = LOOKFORSTART;
    } else {
        state = 2; /* process a function */
        /* advance past function name */
        var_pos = ++pos;
    }
}

void
ESIVariableProcessor::doIt()
{
    assert (output == NULL);

    while (pos < len) {
        /* skipping pre-variables */

        if (string[pos] != '$') {
            ++pos;
        } else {
            if (pos - done_pos)
                /* extract known plain text */
                ESISegment::ListAppend (output, string + done_pos, pos - done_pos);

            done_pos = pos;

            ++pos;

            identifyFunction();

            doFunction();
        }
    }

    /* pos-done_pos chars are ready to copy */
    if (pos-done_pos)
        ESISegment::ListAppend (output, string+done_pos, pos - done_pos);

    safe_free (found_default);

    safe_free (found_subref);
}

ESIVariableProcessor::~ESIVariableProcessor()
{
    delete currentFunction;
}

/* XXX FIXME: this should be comma delimited, no? */
void
ESIVarState::buildVary (HttpReply *rep)
{
    char tempstr[1024];
    tempstr[0]='\0';

    if (flags.language)
        strcat (tempstr, "Accept-Language ");

    if (flags.cookie)
        strcat (tempstr, "Cookie ");

    if (flags.host)
        strcat (tempstr, "Host ");

    if (flags.referer)
        strcat (tempstr, "Referer ");

    if (flags.useragent)
        strcat (tempstr, "User-Agent ");

    if (!tempstr[0])
        return;

    String strVary (rep->header.getList (Http::HdrType::VARY));

    if (!strVary.size() || strVary[0] != '*') {
        rep->header.putStr (Http::HdrType::VARY, tempstr);
    }
}

