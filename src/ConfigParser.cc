
/*
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "fatal.h"
#include "globals.h"

int ConfigParser::RecognizeQuotedValues = true;
std::stack<ConfigParser::CfgFile *> ConfigParser::CfgFiles;
ConfigParser::TokenType ConfigParser::LastTokenType = ConfigParser::SimpleToken;
char *ConfigParser::LastToken = NULL;
char *ConfigParser::CfgLine = NULL;
char *ConfigParser::CfgPos = NULL;
std::queue<std::string> ConfigParser::Undo_;
bool ConfigParser::AllowMacros_ = false;

void
ConfigParser::destruct()
{
    shutting_down = 1;
    if (!CfgFiles.empty()) {
        std::ostringstream message;
        CfgFile *f = CfgFiles.top();
        message << "Bungled " << f->filePath << " line " << f->lineNo <<
        ": " << f->currentLine << std::endl;
        CfgFiles.pop();
        delete f;
        while (!CfgFiles.empty()) {
            f = CfgFiles.top();
            message << " included from " << f->filePath << " line " <<
            f->lineNo << ": " << f->currentLine << std::endl;
            CfgFiles.pop();
            delete f;
        }
        message << " included from " <<  cfg_filename << " line " <<
        config_lineno << ": " << config_input_line << std::endl;
        std::string msg = message.str();
        fatalf("%s", msg.c_str());
    } else
        fatalf("Bungled %s line %d: %s",
               cfg_filename, config_lineno, config_input_line);
}

void
ConfigParser::TokenUndo()
{
    assert(LastToken);
    Undo_.push(LastToken);
}

void
ConfigParser::TokenPutBack(const char *tok)
{
    assert(tok);
    Undo_.push(tok);
}

char *
ConfigParser::Undo()
{
    LOCAL_ARRAY(char, undoToken, CONFIG_LINE_LIMIT);
    if (!Undo_.empty()) {
        strncpy(undoToken, Undo_.front().c_str(), sizeof(undoToken));
        undoToken[sizeof(undoToken) - 1] = '\0';
        Undo_.pop();
        return undoToken;
    }
    return NULL;
}

char *
ConfigParser::strtokFile()
{
    if (RecognizeQuotedValues)
        return ConfigParser::NextToken();

    static int fromFile = 0;
    static FILE *wordFile = NULL;

    char *t;
    LOCAL_ARRAY(char, buf, CONFIG_LINE_LIMIT);

    if ((LastToken = ConfigParser::Undo()))
        return LastToken;

    do {

        if (!fromFile) {
            ConfigParser::TokenType tokenType;
            t = ConfigParser::NextElement(tokenType, true);
            if (!t) {
                return NULL;
            } else if (tokenType == ConfigParser::QuotedToken) {
                /* quote found, start reading from file */
                debugs(3, 8,"Quoted token found : " << t);

                if ((wordFile = fopen(t, "r")) == NULL) {
                    debugs(3, DBG_CRITICAL, "Can not open file " << t << " for reading");
                    return NULL;
                }

#if _SQUID_WINDOWS_
                setmode(fileno(wordFile), O_TEXT);
#endif

                fromFile = 1;
            } else {
                return LastToken = t;
            }
        }

        /* fromFile */
        if (fgets(buf, CONFIG_LINE_LIMIT, wordFile) == NULL) {
            /* stop reading from file */
            fclose(wordFile);
            wordFile = NULL;
            fromFile = 0;
            return NULL;
        } else {
            char *t2, *t3;
            t = buf;
            /* skip leading and trailing white space */
            t += strspn(buf, w_space);
            t2 = t + strcspn(t, w_space);
            t3 = t2 + strspn(t2, w_space);

            while (*t3 && *t3 != '#') {
                t2 = t3 + strcspn(t3, w_space);
                t3 = t2 + strspn(t2, w_space);
            }

            *t2 = '\0';
        }

        /* skip comments */
        /* skip blank lines */
    } while ( *t == '#' || !*t );

    return LastToken = t;
}

char *
ConfigParser::UnQuote(char *token, char **end)
{
    char quoteChar = *token;
    assert(quoteChar == '"' || quoteChar == '\'');
    char  *s = token + 1;
    /* scan until the end of the quoted string, unescaping " and \  */
    while (*s && *s != quoteChar) {
        if (*s == '\\' && isalnum(*( s + 1))) {
            debugs(3, DBG_CRITICAL, "Unsupported escape sequence: " << s);
            self_destruct();
        } else if (*s == '$' && quoteChar == '"') {
            debugs(3, DBG_CRITICAL, "Unsupported cfg macro: " << s);
            self_destruct();
        } else if (*s == '%' && quoteChar == '"' && (!AllowMacros_ )) {
            debugs(3, DBG_CRITICAL, "Macros are not supported here: " << s);
            self_destruct();
        } else if (*s == '\\') {
            const char * next = s+1; // may point to 0
            memmove(s, next, strlen(next) + 1);
        }
        ++s;
    }

    if (*s != quoteChar) {
        debugs(3, DBG_CRITICAL, "missing '" << quoteChar << "' at the end of quoted string: " << (s-1));
        self_destruct();
    }
    *end = s;
    return (token+1);
}

void
ConfigParser::SetCfgLine(char *line)
{
    CfgLine = line;
    CfgPos = line;
}

char *
ConfigParser::TokenParse(char * &nextToken, ConfigParser::TokenType &type, bool legacy)
{
    if (!nextToken || *nextToken == '\0')
        return NULL;
    type = ConfigParser::SimpleToken;
    nextToken += strspn(nextToken, w_space);
    if (*nextToken == '"' || *nextToken == '\'') {
        type = ConfigParser::QuotedToken;
        char *token = UnQuote(nextToken, &nextToken);
        *nextToken = '\0';
        ++nextToken;
        return token;
    }

    char *token = nextToken;
    if (char *t = strchr(nextToken, '#'))
        *t = '\0';
    const char *sep;
    if (legacy)
        sep = w_space;
    else
        sep = w_space "(";
    nextToken += strcspn(nextToken, sep);

    if (!legacy && *nextToken == '(')
        type = ConfigParser::FunctionNameToken;
    else
        type = ConfigParser::SimpleToken;

    if (*nextToken != '\0') {
        *nextToken = '\0';
        ++nextToken;
    }

    if (*token == '\0')
        return NULL;

    return token;
}

char *
ConfigParser::NextElement(ConfigParser::TokenType &type, bool legacy)
{
    char *token = TokenParse(CfgPos, type, legacy);
    return token;
}

char *
ConfigParser::NextToken()
{
    if ((LastToken = ConfigParser::Undo()))
        return LastToken;

    char *token = NULL;
    do {
        while (token == NULL && !CfgFiles.empty()) {
            ConfigParser::CfgFile *wordfile = CfgFiles.top();
            token = wordfile->parse(LastTokenType);
            if (!token) {
                assert(!wordfile->isOpen());
                CfgFiles.pop();
                delete wordfile;
            }
        }

        if (!token)
            token = NextElement(LastTokenType);

        if (token &&  LastTokenType == ConfigParser::FunctionNameToken && strcmp("parameters", token) == 0) {
            char *path = NextToken();
            if (LastTokenType != ConfigParser::QuotedToken) {
                debugs(3, DBG_CRITICAL, "Quoted filename missing: " << token);
                self_destruct();
                return NULL;
            }

            // The next token in current cfg file line must be a ")"
            char *end = NextToken();
            if (LastTokenType != ConfigParser::SimpleToken || strcmp(end, ")") != 0) {
                debugs(3, DBG_CRITICAL, "missing ')' after " << token << "(\"" << path << "\"");
                self_destruct();
                return NULL;
            }

            if (CfgFiles.size() > 16) {
                debugs(3, DBG_CRITICAL, "WARNING: can't open %s for reading parameters: includes are nested too deeply (>16)!\n" << path);
                self_destruct();
                return NULL;
            }

            ConfigParser::CfgFile *wordfile = new ConfigParser::CfgFile();
            if (!path || !wordfile->startParse(path)) {
                debugs(3, DBG_CRITICAL, "Error opening config file: " << token);
                delete wordfile;
                self_destruct();
                return NULL;
            }
            CfgFiles.push(wordfile);
            token = NULL;
        } else if (token &&  LastTokenType == ConfigParser::FunctionNameToken) {
            debugs(3, DBG_CRITICAL, "Unknown cfg function: " << token);
            self_destruct();
            return NULL;
        }
    } while (token == NULL && !CfgFiles.empty());

    return (LastToken = token);
}

char *
ConfigParser::NextQuotedOrToEol()
{
    char *token;

    if ((token = CfgPos) == NULL) {
        debugs(3, DBG_CRITICAL, "token is missing");
        self_destruct();
        return NULL;
    }
    token += strspn(token, w_space);

    if (*token == '\"' || *token == '\'') {
        //TODO: eat the spaces at the end and check if it is untill the end of file.
        char *end;
        token = UnQuote(token, &end);
        *end = '\0';
        CfgPos = end + 1;
        LastTokenType = ConfigParser::QuotedToken;
    } else
        LastTokenType = ConfigParser::SimpleToken;

    CfgPos = NULL;
    return (LastToken = token);
}

const char *
ConfigParser::QuoteString(const String &var)
{
    static String quotedStr;
    const char *s = var.termedBuf();
    bool  needQuote = false;

    for (const char *l = s; !needQuote &&  *l != '\0'; ++l  )
        needQuote = !isalnum(*l);

    if (!needQuote)
        return s;

    quotedStr.clean();
    quotedStr.append('"');
    for (; *s != '\0'; ++s) {
        if (*s == '"' || *s == '\\')
            quotedStr.append('\\');
        quotedStr.append(*s);
    }
    quotedStr.append('"');
    return quotedStr.termedBuf();
}

bool
ConfigParser::CfgFile::startParse(char *path)
{
    assert(wordFile == NULL);
    if ((wordFile = fopen(path, "r")) == NULL) {
        debugs(3, DBG_CRITICAL, "file :" << path << " not found");
        return false;
    }

#if _SQUID_WINDOWS_
    setmode(fileno(wordFile), O_TEXT);
#endif

    filePath = path;
    return getFileLine();
}

bool
ConfigParser::CfgFile::getFileLine()
{
    // Else get the next line
    if (fgets(parseBuffer, CONFIG_LINE_LIMIT, wordFile) == NULL) {
        /* stop reading from file */
        fclose(wordFile);
        wordFile = NULL;
        parseBuffer[0] = '\0';
        return false;
    }
    parsePos = parseBuffer;
    currentLine = parseBuffer;
    lineNo++;
    return true;
}

char *
ConfigParser::CfgFile::parse(ConfigParser::TokenType &type)
{
    if (!wordFile)
        return NULL;

    if (!*parseBuffer)
        return NULL;

    char *token;
    while (!(token = nextElement(type))) {
        if (!getFileLine())
            return NULL;
    }
    return token;
}

char *
ConfigParser::CfgFile::nextElement(ConfigParser::TokenType &type)
{
    return TokenParse(parsePos, type);
}

ConfigParser::CfgFile::~CfgFile()
{
    if (wordFile)
        fclose(wordFile);
}
