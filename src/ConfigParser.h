/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CONFIGPARSER_H
#define SQUID_SRC_CONFIGPARSER_H

#include "acl/forward.h"
#include "base/forward.h"
#include "sbuf/forward.h"
#include "SquidString.h"

#include <memory>
#include <queue>
#include <stack>
#include <string>

class CachePeer;
class wordlist;

/**
 * Limit to how long any given config line may be.
 * This affects squid.conf and all included files.
 *
 * Behaviour when setting larger than 2KB is unknown.
 * The config parser read mechanism can cope, but the other systems
 * receiving the data from its buffers on such lines may not.
 */
#define CONFIG_LINE_LIMIT   2048

/**
 * A configuration file Parser. Instances of this class track
 * parsing state and perform tokenisation. Syntax is currently
 * taken care of outside this class.
 *
 * One reason for this class is to allow testing of configuration
 * using modules without linking cache_cf.o in - because that drags
 * in all of squid by reference. Instead the tokeniser only is
 * brought in.
 */
class ConfigParser
{

public:
    /**
     * Parsed tokens type: simple tokens, quoted tokens or function
     * like parameters.
     */
    enum TokenType {SimpleToken, QuotedToken, FunctionParameters};

    void destruct();

    /// stops parsing the current configuration directive
    void closeDirective();

    /// rejects configuration due to a repeated directive
    void rejectDuplicateDirective();

    /// extracts and returns a required token
    SBuf token(const char *expectedTokenDescription);

    /// extracts an optional key=value token or returns false
    /// rejects configurations with empty keys or empty values
    /// key and value have lifetime of the current line/directive
    bool optionalKvPair(char * &key, char * &value);

    /// either extracts the given (optional) token or returns false
    bool skipOptional(const char *keyword);

    /// parses an [if [!]<acl>...] construct
    Acl::Tree *optionalAclList();

    /// extracts and returns a regex (including any optional flags)
    std::unique_ptr<RegexPattern> regex(const char *expectedRegexDescription);

    /// extracts a cache_peer name token and returns the corresponding CachePeer
    CachePeer &cachePeer(const char *peerNameTokenDescription);

    static void ParseUShort(unsigned short *var);
    static void ParseBool(bool *var);
    static const char *QuoteString(const String &var);
    static void ParseWordList(wordlist **list);

    /**
     * Backward compatibility wrapper for the ConfigParser::NextToken method.
     * If the configuration_includes_quoted_values configuration parameter is
     * set to 'off' this interprets the quoted tokens as filenames.
     */
    static char * strtokFile();

    /**
     * Returns the body of the next element. The element is either a token or
     * a quoted string with optional escape sequences and/or macros. The body
     * of a quoted string element does not include quotes or escape sequences.
     * Future code will want to see Elements and not just their bodies.
     */
    static char *NextToken();

    /**
     * Backward compatibility wrapper for ConfigParser::RegexPattern method.
     * If the configuration_includes_quoted_values configuration parameter is
     * set to 'off' this interprets the quoted tokens as filenames.
     */
    static char *RegexStrtokFile();

    /**
     * Parse the next token with support for quoted values enabled even if
     * the configuration_includes_quoted_values is set to off
     */
    static char *NextQuotedToken();

    /// \return true if the last parsed token was quoted
    static bool LastTokenWasQuoted() {return (LastTokenType == ConfigParser::QuotedToken);}

    /**
     * \return the next quoted string or the raw string data until the end of line.
     * This method allows %macros in unquoted strings to keep compatibility
     * for the logformat option.
     */
    static char *NextQuotedOrToEol();

    /**
     * the next key value pair which must be separated by "="
     * \return true on success, false otherwise
     */
    static bool NextKvPair(char * &key, char * &value);

    /**
     * Preview the next token. The next NextToken() and strtokFile() call
     * will return the same token.
     * On parse error (eg invalid characters in token) will return an
     * error message as token.
     */
    static char *PeekAtToken();

    /// Set the configuration file line to parse.
    static void SetCfgLine(char *line);

    /// Allow %macros inside quoted strings
    static void EnableMacros() {AllowMacros_ = true;}

    /// Do not allow %macros inside quoted strings
    static void DisableMacros() {AllowMacros_ = false;}

    static SBuf CurrentLocation();

    /// configuration_includes_quoted_values in squid.conf
    static bool RecognizeQuotedValues;

    /**
     * Strict syntax mode. Does not allow not alphanumeric characters in unquoted tokens.
     * Controlled by the  configuration_includes_quoted_values in squid.conf but remains
     * false when the the legacy ConfigParser::NextQuotedToken() call forces
     * RecognizeQuotedValues to be temporary true.
     */
    static bool StrictMode;

protected:
    /**
     * Class used to store required information for the current
     * configuration file.
     */
    class CfgFile
    {
    public:
        CfgFile(): wordFile(nullptr), parsePos(nullptr), lineNo(0) { parseBuffer[0] = '\0';}
        ~CfgFile();
        /// True if the configuration file is open
        bool isOpen() {return wordFile != nullptr;}

        /**
         * Open the file given by 'path' and initializes the CfgFile object
         * to start parsing
         */
        bool startParse(char *path);

        /**
         * Do the next parsing step:
         * reads the next line from file if required.
         * \return the body of next element or a NULL pointer if there are no more token elements in the file.
         * \param type will be filled with the ConfigParse::TokenType for any element found, or left unchanged if NULL is returned.
         */
        char *parse(TokenType &type);

    private:
        bool getFileLine();   ///< Read the next line from the file
        /**
         * Return the body of the next element. If the wasQuoted is given
         * set to true if the element was quoted.
         */
        char *nextElement(TokenType &type);
        FILE *wordFile; ///< Pointer to the file.
        char parseBuffer[CONFIG_LINE_LIMIT]; ///< Temporary buffer to store data to parse
        const char *parsePos; ///< The next element position in parseBuffer string
    public:
        std::string filePath; ///< The file path
        std::string currentLine; ///< The current line to parse
        int lineNo; ///< Current line number
    };

    /**
     * Unquotes the token, which must be quoted.
     * \param next if it is not NULL, it is set after the end of token.
     */
    static char *UnQuote(const char *token, const char **next = nullptr);

    /**
     * Does the real tokens parsing job: Ignore comments, unquote an
     * element if required.
     * \return the next token, or NULL if there are no available tokens in the nextToken string.
     * \param nextToken updated to point to the pos after parsed token.
     * \param type      The token type
     */
    static char *TokenParse(const char * &nextToken, TokenType &type);

    /// Wrapper method for TokenParse.
    static char *NextElement(TokenType &type);
    static std::stack<CfgFile *> CfgFiles; ///< The stack of open cfg files
    static TokenType LastTokenType; ///< The type of last parsed element
    static const char *CfgLine; ///< The current line to parse
    static const char *CfgPos; ///< Pointer to the next element in cfgLine string
    static std::queue<char *> CfgLineTokens_; ///< Store the list of tokens for current configuration line
    static bool AllowMacros_;
    static bool ParseQuotedOrToEol_; ///< The next tokens will be handled as quoted or to_eol token
    static bool RecognizeQuotedPair_; ///< The next tokens may contain quoted-pair (\-escaped) characters
    static bool PreviewMode_; ///< The next token will not popped from cfg files, will just previewd.
    static bool ParseKvPair_; ///<The next token will be handled as kv-pair token
    static enum ParsingStates {atParseKey, atParseValue} KvPairState_; ///< Parsing state while parsing kv-pair tokens
};

int parseConfigFile(const char *file_name);

#endif /* SQUID_SRC_CONFIGPARSER_H */

