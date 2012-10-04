#ifndef SQUID_SSL_CRTD_MESSAGE_H
#define SQUID_SSL_CRTD_MESSAGE_H

#if HAVE_STRING
#include <string>
#endif
#if HAVE_MAP
#include <map>
#endif

namespace Ssl
{
class CertificateProperties;

/**
 * This class is responsible for composing and parsing messages destined to, or comming
 * from an ssl_crtd server. Format of these mesages is:
 *   <response/request code> <whitespace> <body length> <whitespace> <body>
 */
class CrtdMessage
{
public:
    typedef std::map<std::string, std::string> BodyParams;
    /// Parse result codes.
    enum ParseResult {
        OK,
        INCOMPLETE,
        ERROR
    };
    CrtdMessage();
    /**Parse buffer of length len
     \retval OK          if parsing completes
     \retval INCOMPLETE  if more data required
     \retval ERROR       if there is an error.
     */
    ParseResult parse(const char * buffer, size_t len);
    /// Current  body. If parsing is not finished the method returns incompleted body.
    std::string const & getBody() const;
    /// Current response/request code. If parsing is not finished the method may return incompleted code.
    std::string const & getCode() const;
    void setBody(std::string const & aBody); ///< Set new body to encode.
    void setCode(std::string const & aCode); ///< Set new request/reply code to compose.
    std::string compose() const; ///< Compose current (request) code and body to string.
    /// Reset the class.
    void clear();
    /**
     *Parse body data which has the form: \verbatim
         param1=value1
         param2=value2
         The other multistring part of body.  \endverbatim
     * The parameters of the body stored to map and the remaining part to other_part
     */
    void parseBody(BodyParams & map, std::string & other_part) const;
    /**
     *Compose parameters given by map with their values and the other part given by
     * other_part to body data. The constructed body will have the form:  \verbatim
         param1=value1
         param2=value2
         The other multistring part of body.  \endverbatim
    */
    void composeBody(BodyParams const & map, std::string const & other_part);

    /// orchestrates entire request parsing
    bool parseRequest(Ssl::CertificateProperties &, std::string &error);
    void composeRequest(Ssl::CertificateProperties const &); // throws

    /// String code for "new_certificate" messages
    static const std::string code_new_certificate;
    /// Parameter name for passing hostname
    static const std::string param_host;
    /// Parameter name for passing SetValidAfter cert adaptation variable
    static const std::string param_SetValidAfter;
    /// Parameter name for passing SetValidBefore cert adaptation variable
    static const std::string param_SetValidBefore;
    /// Parameter name for passing SetCommonName cert adaptation variable
    static const std::string param_SetCommonName;
    /// Parameter name for passing signing algorithm
    static const std::string param_Sign;
private:
    enum ParseState {
        BEFORE_CODE,
        CODE,
        BEFORE_LENGTH,
        LENGTH,
        BEFORE_BODY,
        BODY,
        END
    };
    size_t body_size; ///< The body size if exist or 0.
    ParseState state; ///< Parsing state.
    std::string body; ///< Current body.
    std::string code; ///< Current response/request code.
    std::string current_block; ///< Current block buffer.
};

} //namespace Ssl
#endif // SQUID_SSL_CRTD_MESSAGE_H
