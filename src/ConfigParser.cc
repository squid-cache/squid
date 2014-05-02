
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

bool ConfigParser::RecognizeQuotedValues = true;
bool ConfigParser::StrictMode = true;
std::stack<ConfigParser::CfgFile *> ConfigParser::CfgFiles;
ConfigParser::TokenType ConfigParser::LastTokenType = ConfigParser::SimpleToken;
const char *ConfigParser::CfgLine = NULL;
const char *ConfigParser::CfgPos = NULL;
std::queue<char *> ConfigParser::CfgLineTokens_;
std::queue<std::string> ConfigParser::Undo_;
bool ConfigParser::AllowMacros_ = false;
bool ConfigParser::ParseQuotedOrToEol_ = false;
bool ConfigParser::PreviewMode_ = false;

static const char *SQUID_ERROR_TOKEN = "[invalid token]";

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
        if (!PreviewMode_)
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

    if ((t = ConfigParser::Undo()))
        return t;

    do {

        if (!fromFile) {
            ConfigParser::TokenType tokenType;
            t = ConfigParser::NextElement(tokenType);
            if (!t) {
                return NULL;
            } else if (*t == '\"' || *t == '\'') {
                /* quote found, start reading from file */
                debugs(3, 8,"Quoted token found : " << t);
                char *fn = ++t;

                while (*t && *t != '\"' && *t != '\'')
                    ++t;

                *t = '\0';

                if ((wordFile = fopen(fn, "r")) == NULL) {
                    debugs(3, DBG_CRITICAL, "Can not open file " << t << " for reading");
                    return NULL;
                }

#if _SQUID_WINDOWS_
                setmode(fileno(wordFile), O_TEXT);
#endif

                fromFile = 1;
            } else {
                return t;
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

    return t;
}

char *
ConfigParser::UnQuote(const char *token, const char **next)
{
    const char *errorStr = NULL;
    const char *errorPos = NULL;
    char quoteChar = *token;
    assert(quoteChar == '"' || quoteChar == '\'');
    LOCAL_ARRAY(char, UnQuoted, CONFIG_LINE_LIMIT);
    const char  *s = token + 1;
    char *d = UnQuoted;
    /* scan until the end of the quoted string, handling escape sequences*/
    while (*s && *s != quoteChar && !errorStr && (size_t)(d - UnQuoted) < sizeof(UnQuoted)) {
        if (*s == '\\') {
            s++;
            switch (*s) {
            case 'r':
                *d = '\r';
                break;
            case 'n':
                *d = '\n';
                break;
            case 't':
                *d = '\t';
                break;
            default:
                if (isalnum(*s)) {
                    errorStr = "Unsupported escape sequence";
                    errorPos = s;
                }
                *d = *s;
                break;
            }
#if 0
        } else if (*s == '$' && quoteChar == '"') {
            errorStr = "Unsupported cfg macro";
            errorPos = s;
#endif
#if 0
        } else if (*s == '%' && quoteChar == '"' && (!AllowMacros_ )) {
            errorStr = "Macros are not supported here";
            errorPos = s;
#endif
        } else
            *d = *s;
        ++s;
        ++d;
    }

    if (*s != quoteChar && !errorStr) {
        errorStr = "missing quote char at the end of quoted string";
        errorPos = s - 1;
    }
    // The end of token
    *d = '\0';

    // We are expecting a separator after quoted string, space or one of "()#"
    if (*(s + 1) != '\0' && !strchr(w_space "()#", *(s + 1)) && !errorStr) {
        errorStr = "Expecting space after the end of quoted token";
        errorPos = token;
    }

    if (errorStr) {
        if (PreviewMode_)
            strncpy(UnQuoted, SQUID_ERROR_TOKEN, sizeof(UnQuoted));
        else {
            debugs(3, DBG_CRITICAL, errorStr << ": " << errorPos);
            self_destruct();
        }
    }

    if (next)
        *next = s + 1;
    return UnQuoted;
}

void
ConfigParser::SetCfgLine(char *line)
{
    CfgLine = line;
    CfgPos = line;
    while (!CfgLineTokens_.empty()) {
        char *token = CfgLineTokens_.front();
        CfgLineTokens_.pop();
        free(token);
    }
}

char *
ConfigParser::TokenParse(const char * &nextToken, ConfigParser::TokenType &type)
{
    if (!nextToken || *nextToken == '\0')
        return NULL;
    type = ConfigParser::SimpleToken;
    nextToken += strspn(nextToken, w_space);

    if (*nextToken == '#')
        return NULL;

    if (ConfigParser::RecognizeQuotedValues && (*nextToken == '"' || *nextToken == '\'')) {
        type = ConfigParser::QuotedToken;
        char *token = xstrdup(UnQuote(nextToken, &nextToken));
        CfgLineTokens_.push(token);
        return token;
    }

    const char *tokenStart = nextToken;
    const char *sep;
    if (ConfigParser::ParseQuotedOrToEol_)
        sep = "\n";
    else if (!ConfigParser::RecognizeQuotedValues || *nextToken == '(')
        sep = w_space;
    else
        sep = w_space "(";
    nextToken += strcspn(nextToken, sep);

    if (ConfigParser::RecognizeQuotedValues && *nextToken == '(') {
        if (strncmp(tokenStart, "parameters", nextToken - tokenStart) == 0)
            type = ConfigParser::FunctionParameters;
        else {
            if (PreviewMode_) {
                char *err = xstrdup(SQUID_ERROR_TOKEN);
                CfgLineTokens_.push(err);
                return err;
            } else {
                debugs(3, DBG_CRITICAL, "Unknown cfg function: " << tokenStart);
                self_destruct();
            }
        }
    } else
        type = ConfigParser::SimpleToken;

    char *token = NULL;
    if (nextToken - tokenStart) {
        if (ConfigParser::StrictMode && type == ConfigParser::SimpleToken) {
            bool tokenIsNumber = true;
            for (const char *s = tokenStart; s != nextToken; ++s) {
                const bool isValidChar = isalnum(*s) || strchr(".,()-=_/:", *s) ||
                                         (tokenIsNumber && *s == '%' && (s + 1 == nextToken));

                if (!isdigit(*s))
                    tokenIsNumber = false;

                if (!isValidChar) {
                    if (PreviewMode_) {
                        char *err = xstrdup(SQUID_ERROR_TOKEN);
                        CfgLineTokens_.push(err);
                        return err;
                    } else {
                        debugs(3, DBG_CRITICAL, "Not alphanumeric character '"<< *s << "' in unquoted token " << tokenStart);
                        self_destruct();
                    }
                }
            }
        }
        token = xstrndup(tokenStart, nextToken - tokenStart + 1);
        CfgLineTokens_.push(token);
    }

    if (*nextToken != '\0' && *nextToken != '#') {
        ++nextToken;
    }

    return token;
}

char *
ConfigParser::NextElement(ConfigParser::TokenType &type)
{
    const char *pos = CfgPos;
    char *token = TokenParse(pos, type);
    // If not in preview mode the next call of this method should start
    // parsing after the end of current token.
    // For function "parameters(...)" we need always to update current parsing
    // position to allow parser read the arguments of "parameters(..)"
    if (!PreviewMode_ || type == FunctionParameters)
        CfgPos = pos;
    // else next call will read the same token
    return token;
}

char *
ConfigParser::NextToken()
{
    char *token = NULL;
    if ((token = ConfigParser::Undo())) {
        debugs(3, 6, "TOKEN (undone): " << token);
        return token;
    }

    do {
        while (token == NULL && !CfgFiles.empty()) {
            ConfigParser::CfgFile *wordfile = CfgFiles.top();
            token = wordfile->parse(LastTokenType);
            if (!token) {
                assert(!wordfile->isOpen());
                CfgFiles.pop();
                debugs(3, 4, "CfgFiles.pop " << wordfile->filePath);
                delete wordfile;
            }
        }

        if (!token)
            token = NextElement(LastTokenType);

        if (token &&  LastTokenType == ConfigParser::FunctionParameters) {
            //Disable temporary preview mode, we need to parse function parameters
            const bool savePreview = ConfigParser::PreviewMode_;
            ConfigParser::PreviewMode_ = false;

            char *path = NextToken();
            if (LastTokenType != ConfigParser::QuotedToken) {
                debugs(3, DBG_CRITICAL, "Quoted filename missing: " << token);
                self_destruct();
                return NULL;
            }

            // The next token in current cfg file line must be a ")"
            char *end = NextToken();
            ConfigParser::PreviewMode_ = savePreview;
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
        }
    } while (token == NULL && !CfgFiles.empty());

    return token;
}

char *
ConfigParser::PeekAtToken()
{
    PreviewMode_ = true;
    char *token = NextToken();
    PreviewMode_ = false;
    return token;
}

char *
ConfigParser::NextQuotedOrToEol()
{
    ParseQuotedOrToEol_ = true;
    char *token = NextToken();
    ParseQuotedOrToEol_ = false;

    // Assume end of current config line
    // Close all open configuration files for this config line
    while (!CfgFiles.empty()) {
        ConfigParser::CfgFile *wordfile = CfgFiles.top();
        CfgFiles.pop();
        delete wordfile;
    }

    return token;
}

char *
ConfigParser::RegexStrtokFile()
{
    if (ConfigParser::RecognizeQuotedValues) {
        debugs(3, DBG_CRITICAL, "Can not read regex expresion while configuration_includes_quoted_values is enabled");
        self_destruct();
    }
    char * token = strtokFile();
    return token;
}

char *
ConfigParser::RegexPattern()
{
    if (ConfigParser::RecognizeQuotedValues) {
        debugs(3, DBG_CRITICAL, "Can not read regex expresion while configuration_includes_quoted_values is enabled");
        self_destruct();
    }

    char * token = NextToken();
    return token;
}

char *
ConfigParser::NextQuotedToken()
{
    const bool saveRecognizeQuotedValues = ConfigParser::RecognizeQuotedValues;
    ConfigParser::RecognizeQuotedValues = true;
    char *token = NextToken();
    ConfigParser::RecognizeQuotedValues = saveRecognizeQuotedValues;
    return token;
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
    debugs(3, 3, "Parsing from " << path);
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
    const char *pos = parsePos;
    char *token = TokenParse(pos, type);
    if (!PreviewMode_ || type == FunctionParameters)
        parsePos = pos;
    // else next call will read the same token;
    return token;
}

ConfigParser::CfgFile::~CfgFile()
{
    if (wordFile)
        fclose(wordFile);
}
