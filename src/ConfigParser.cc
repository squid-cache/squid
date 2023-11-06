/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "base/Here.h"
#include "base/RegexPattern.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "fatal.h"
#include "globals.h"
#include "neighbors.h"
#include "sbuf/Stream.h"

bool ConfigParser::RecognizeQuotedValues = true;
bool ConfigParser::StrictMode = true;
std::stack<ConfigParser::CfgFile *> ConfigParser::CfgFiles;
ConfigParser::TokenType ConfigParser::LastTokenType = ConfigParser::SimpleToken;
const char *ConfigParser::CfgLine = nullptr;
const char *ConfigParser::CfgPos = nullptr;
std::queue<char *> ConfigParser::CfgLineTokens_;
bool ConfigParser::AllowMacros_ = false;
bool ConfigParser::ParseQuotedOrToEol_ = false;
bool ConfigParser::ParseKvPair_ = false;
ConfigParser::ParsingStates ConfigParser::KvPairState_ = ConfigParser::atParseKey;
bool ConfigParser::RecognizeQuotedPair_ = false;
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

char *
ConfigParser::strtokFile()
{
    if (RecognizeQuotedValues)
        return ConfigParser::NextToken();

    static int fromFile = 0;
    static FILE *wordFile = nullptr;

    char *t;
    static char buf[CONFIG_LINE_LIMIT];

    do {

        if (!fromFile) {
            ConfigParser::TokenType tokenType;
            t = ConfigParser::NextElement(tokenType);
            if (!t) {
                return nullptr;
            } else if (*t == '\"' || *t == '\'') {
                /* quote found, start reading from file */
                debugs(3, 8,"Quoted token found : " << t);
                char *fn = ++t;

                while (*t && *t != '\"' && *t != '\'')
                    ++t;

                *t = '\0';

                if ((wordFile = fopen(fn, "r")) == nullptr) {
                    debugs(3, DBG_CRITICAL, "ERROR: Can not open file " << fn << " for reading");
                    return nullptr;
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
        if (fgets(buf, sizeof(buf), wordFile) == nullptr) {
            /* stop reading from file */
            fclose(wordFile);
            wordFile = nullptr;
            fromFile = 0;
            return nullptr;
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
    const char *errorStr = nullptr;
    const char *errorPos = nullptr;
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
            xstrncpy(UnQuoted, SQUID_ERROR_TOKEN, sizeof(UnQuoted));
        else {
            debugs(3, DBG_CRITICAL, "FATAL: " << errorStr << ": " << errorPos);
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

SBuf
ConfigParser::CurrentLocation()
{
    return ToSBuf(SourceLocation(cfg_directive, cfg_filename, config_lineno));
}

char *
ConfigParser::TokenParse(const char * &nextToken, ConfigParser::TokenType &type)
{
    if (!nextToken || *nextToken == '\0')
        return nullptr;
    type = ConfigParser::SimpleToken;
    nextToken += strspn(nextToken, w_space);

    if (*nextToken == '#')
        return nullptr;

    if (ConfigParser::RecognizeQuotedValues && (*nextToken == '"' || *nextToken == '\'')) {
        type = ConfigParser::QuotedToken;
        char *token = xstrdup(UnQuote(nextToken, &nextToken));
        CfgLineTokens_.push(token);
        return token;
    }

    const char *tokenStart = nextToken;
    const char *sep;
    if (ConfigParser::ParseKvPair_) {
        if (ConfigParser::KvPairState_ == ConfigParser::atParseKey)
            sep = "=";
        else
            sep = w_space;
    } else if (ConfigParser::ParseQuotedOrToEol_)
        sep = "\n";
    else if (ConfigParser::RecognizeQuotedPair_)
        sep = w_space "\\";
    else if (!ConfigParser::RecognizeQuotedValues || *nextToken == '(')
        sep = w_space;
    else
        sep = w_space "(";
    nextToken += strcspn(nextToken, sep);

    while (ConfigParser::RecognizeQuotedPair_ && *nextToken == '\\') {
        // NP: do not permit \0 terminator to be escaped.
        if (*(nextToken+1) && *(nextToken+1) != '\r' && *(nextToken+1) != '\n') {
            nextToken += 2; // skip the quoted-pair (\-escaped) character
            nextToken += strcspn(nextToken, sep);
        } else {
            debugs(3, DBG_CRITICAL, "FATAL: Unescaped '\' character in regex pattern: " << tokenStart);
            self_destruct();
        }
    }

    if (ConfigParser::RecognizeQuotedValues && *nextToken == '(') {
        if (strncmp(tokenStart, "parameters", nextToken - tokenStart) == 0)
            type = ConfigParser::FunctionParameters;
        else {
            if (PreviewMode_) {
                char *err = xstrdup(SQUID_ERROR_TOKEN);
                CfgLineTokens_.push(err);
                return err;
            } else {
                debugs(3, DBG_CRITICAL, "FATAL: Unknown cfg function: " << tokenStart);
                self_destruct();
            }
        }
    } else
        type = ConfigParser::SimpleToken;

    char *token = nullptr;
    if (nextToken - tokenStart) {
        if (ConfigParser::StrictMode && type == ConfigParser::SimpleToken) {
            bool tokenIsNumber = true;
            for (const char *s = tokenStart; s != nextToken; ++s) {
                const bool isValidChar = isalnum(*s) || strchr(".,()-=_/:+", *s) ||
                                         (tokenIsNumber && *s == '%' && (s + 1 == nextToken));

                if (!isdigit(*s))
                    tokenIsNumber = false;

                if (!isValidChar) {
                    if (PreviewMode_) {
                        char *err = xstrdup(SQUID_ERROR_TOKEN);
                        CfgLineTokens_.push(err);
                        return err;
                    } else {
                        debugs(3, DBG_CRITICAL, "FATAL: Not alphanumeric character '"<< *s << "' in unquoted token " << tokenStart);
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
    char *token = nullptr;

    do {
        while (token == nullptr && !CfgFiles.empty()) {
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
                debugs(3, DBG_CRITICAL, "FATAL: Quoted filename missing: " << token);
                self_destruct();
                return nullptr;
            }

            // The next token in current cfg file line must be a ")"
            char *end = NextToken();
            ConfigParser::PreviewMode_ = savePreview;
            if (LastTokenType != ConfigParser::SimpleToken || strcmp(end, ")") != 0) {
                debugs(3, DBG_CRITICAL, "FATAL: missing ')' after " << token << "(\"" << path << "\"");
                self_destruct();
                return nullptr;
            }

            if (CfgFiles.size() > 16) {
                debugs(3, DBG_CRITICAL, "FATAL: can't open %s for reading parameters: includes are nested too deeply (>16)!\n" << path);
                self_destruct();
                return nullptr;
            }

            ConfigParser::CfgFile *wordfile = new ConfigParser::CfgFile();
            if (!path || !wordfile->startParse(path)) {
                debugs(3, DBG_CRITICAL, "FATAL: Error opening config file: " << token);
                delete wordfile;
                self_destruct();
                return nullptr;
            }
            CfgFiles.push(wordfile);
            token = nullptr;
        }
    } while (token == nullptr && !CfgFiles.empty());

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

bool
ConfigParser::optionalKvPair(char * &key, char * &value)
{
    key = nullptr;
    value = nullptr;

    if (const char *currentToken = PeekAtToken()) {
        // NextKvPair() accepts "a = b" and skips "=" or "a=". To avoid
        // misinterpreting the admin intent, we use strict checks.
        if (const auto middle = strchr(currentToken, '=')) {
            if (middle == currentToken)
                throw TextException(ToSBuf("missing key in a key=value option: ", currentToken), Here());
            if (middle + 1 == currentToken + strlen(currentToken))
                throw TextException(ToSBuf("missing value in a key=value option: ", currentToken), Here());
        } else
            return false; // not a key=value token

        if (!NextKvPair(key, value)) // may still fail (e.g., bad value quoting)
            throw TextException(ToSBuf("invalid key=value option: ", currentToken), Here());

        return true;
    }

    return false; // end of directive or input
}

bool
ConfigParser::NextKvPair(char * &key, char * &value)
{
    key = value = nullptr;
    ParseKvPair_ = true;
    KvPairState_ = ConfigParser::atParseKey;
    if ((key = NextToken()) != nullptr) {
        KvPairState_ = ConfigParser::atParseValue;
        value = NextQuotedToken();
    }
    ParseKvPair_ = false;

    if (!key)
        return false;
    if (!value) {
        debugs(3, DBG_CRITICAL, "ERROR: Failure while parsing key=value token. Value missing after: " << key);
        return false;
    }

    return true;
}

char *
ConfigParser::RegexStrtokFile()
{
    if (ConfigParser::RecognizeQuotedValues) {
        debugs(3, DBG_CRITICAL, "FATAL: Can not read regex expression while configuration_includes_quoted_values is enabled");
        self_destruct();
    }
    ConfigParser::RecognizeQuotedPair_ = true;
    char * token = strtokFile();
    ConfigParser::RecognizeQuotedPair_ = false;
    return token;
}

std::unique_ptr<RegexPattern>
ConfigParser::regex(const char *expectedRegexDescription)
{
    if (RecognizeQuotedValues)
        throw TextException("Cannot read regex expression while configuration_includes_quoted_values is enabled", Here());

    SBuf pattern;
    int flags = REG_EXTENDED | REG_NOSUB;

    ConfigParser::RecognizeQuotedPair_ = true;
    const auto flagOrPattern = token(expectedRegexDescription);
    if (flagOrPattern.cmp("-i") == 0) {
        flags |= REG_ICASE;
        pattern = token(expectedRegexDescription);
    } else if (flagOrPattern.cmp("+i") == 0) {
        flags &= ~REG_ICASE;
        pattern = token(expectedRegexDescription);
    } else {
        pattern = flagOrPattern;
    }
    ConfigParser::RecognizeQuotedPair_ = false;

    return std::unique_ptr<RegexPattern>(new RegexPattern(pattern, flags));
}

CachePeer &
ConfigParser::cachePeer(const char *peerNameTokenDescription)
{
    if (const auto name = NextToken()) {
        debugs(3, 5, CurrentLocation() << ' ' << peerNameTokenDescription << ": " << name);

        if (const auto p = findCachePeerByName(name))
            return *p;

        throw TextException(ToSBuf("Cannot find a previously declared cache_peer referred to by ",
                                   peerNameTokenDescription, " as ", name), Here());
    }

    throw TextException(ToSBuf("Missing ", peerNameTokenDescription), Here());
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

void
ConfigParser::rejectDuplicateDirective()
{
    assert(cfg_directive);
    throw TextException("duplicate configuration directive", Here());
}

void
ConfigParser::closeDirective()
{
    assert(cfg_directive);
    if (const auto garbage = PeekAtToken())
        throw TextException(ToSBuf("trailing garbage at the end of a configuration directive: ", garbage), Here());
    // TODO: cfg_directive = nullptr; // currently in generated code
}

SBuf
ConfigParser::token(const char *expectedTokenDescription)
{
    if (const auto extractedToken = NextToken()) {
        debugs(3, 5, CurrentLocation() << ' ' << expectedTokenDescription << ": " << extractedToken);
        return SBuf(extractedToken);
    }
    throw TextException(ToSBuf("missing ", expectedTokenDescription), Here());
}

bool
ConfigParser::skipOptional(const char *keyword)
{
    assert(keyword);
    if (const auto nextToken = PeekAtToken()) {
        if (strcmp(nextToken, keyword) == 0) {
            (void)NextToken();
            return true;
        }
        return false; // the next token on the line is not the optional keyword
    }
    return false; // no more tokens (i.e. we are at the end of the line)
}

Acl::Tree *
ConfigParser::optionalAclList()
{
    if (!skipOptional("if"))
        return nullptr; // OK: the directive has no ACLs

    Acl::Tree *acls = nullptr;
    const auto aclCount = aclParseAclList(*this, &acls, cfg_directive);
    assert(acls);
    if (aclCount <= 0)
        throw TextException("missing ACL name(s) after 'if' keyword", Here());
    return acls;
}

bool
ConfigParser::CfgFile::startParse(char *path)
{
    assert(wordFile == nullptr);
    debugs(3, 3, "Parsing from " << path);
    if ((wordFile = fopen(path, "r")) == nullptr) {
        debugs(3, DBG_CRITICAL, "WARNING: file :" << path << " not found");
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
    if (fgets(parseBuffer, CONFIG_LINE_LIMIT, wordFile) == nullptr) {
        /* stop reading from file */
        fclose(wordFile);
        wordFile = nullptr;
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
        return nullptr;

    if (!*parseBuffer)
        return nullptr;

    char *token;
    while (!(token = nextElement(type))) {
        if (!getFileLine())
            return nullptr;
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

