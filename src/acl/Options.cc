/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Options.h"
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "sbuf/Stream.h"

#include <iostream>
#include <utility>
#include <vector>

namespace Acl {

/// low-level parser that extracts but does not interpret ACL options
class OptionExtractor
{
public:
    /// parses the next option and fills public members with its details
    /// \returns whether option extraction was successful
    bool extractOne();

    /* extracted option details (after successful extraction */
    SBuf name; ///< extracted option name, including dash(es)
    bool hasValue = false; ///< whether the option has a value (-x=value)
    const SBuf &value() const; ///< extracted option value (requires hasValue)

protected:
    bool advance();
    void extractWhole();
    void extractShort();

private:
    SBuf prefix_; ///< option name(s), including leading dash(es)
    SBuf value_; ///< the last seen value of some option
    SBuf::size_type letterPos_ = 0; ///< letter position inside an -xyz sequence
    bool sawValue_ = false; ///< the current option sequence had a value
};

/// parses/validates/stores ACL options; skips/preserves parameter flags
class OptionsParser
{
public:
    explicit OptionsParser(const Options &options);

    // fill previously supplied options container, throwing on errors
    void parse();

private:
    using SupportedOption = std::pair<const Option *, bool /* enable */ >;
    SupportedOption supportedOption(const SBuf &name) const;

    const Options &options_; ///< caller-supported, linked options
};

} // namespace Acl

/* Acl::Option */

Acl::Option::Option(const char * const nameThatEnables, const char * const nameThatDisables, const ValueExpectation vex):
    onName(nameThatEnables),
    offName(nameThatDisables),
    valueExpectation(vex)
{
    assert(onName);
}

/* Acl::OptionExtractor */

const SBuf &
Acl::OptionExtractor::value() const
{
    Must(hasValue);
    return value_;
}

bool
Acl::OptionExtractor::extractOne()
{
    if (!prefix_.isEmpty()) {
        extractShort(); // continue with the previously extracted flags
        return true;
    }

    if (!advance())
        return false; // end of options (and, possibly, the whole "acl" directive)

    if (prefix_.length() < 2)
        throw TexcHere(ToSBuf("truncated(?) ACL flag: ", prefix_)); // single - or +

    if (prefix_[0] == '-' && prefix_[1] == '-') {
        if (prefix_.length() == 2)
            return false; // skipped "--", an explicit end-of-options marker
        extractWhole();
        return true;
    }

    if (prefix_.length() == 2) { // common trivial case: -x or +y
        extractWhole();
        return true;
    }

    // -xyz or +xyz
    letterPos_ = 1;
    extractShort();
    return true;
}

/// extracts a token with the next option/flag(s) or returns false
bool
Acl::OptionExtractor::advance()
{
    const char *next = ConfigParser::PeekAtToken();
    if (!next)
        return false; // end of the "acl" line

    const char nextChar = *next;
    if (!(nextChar == '-' || nextChar == '+'))
        return false; // start of ACL parameters

    sawValue_ = strchr(next, '='); // TODO: Make ConfigParser reject '^=.*' tokens
    if (sawValue_) {
        char *rawPrefix = nullptr;
        char *rawValue = nullptr;
        if (!ConfigParser::NextKvPair(rawPrefix, rawValue))
            throw TexcHere(ToSBuf("Malformed acl option=value: ", next));
        prefix_.assign(rawPrefix);
        value_.assign(rawValue);
    } else {
        prefix_.assign(next);
        ConfigParser::NextToken(); // consume what we have peeked at
    }
    return true;
}

/// handles -x[=option] or --foo[=option]
void
Acl::OptionExtractor::extractWhole()
{
    debugs(28, 8, "from " << prefix_ << " value: " << sawValue_);
    hasValue = sawValue_;
    name = prefix_;
    prefix_.clear();
}

/// handles one flag letter inside an -xyx[=option] or +xyz[=option] sequence
void
Acl::OptionExtractor::extractShort()
{
    debugs(28, 8, "from " << prefix_ << " at " << letterPos_ << " value: " << sawValue_);
    name.assign(prefix_.rawContent(), 1); // leading - or +
    name.append(prefix_.at(letterPos_++));
    if (letterPos_ >= prefix_.length()) { // got last flag in the sequence
        hasValue = sawValue_;
        prefix_.clear();
    } else {
        hasValue = false;
    }
}

/* Acl::OptionsParser */

Acl::OptionsParser::OptionsParser(const Options &options):
    options_(options)
{
}

/// \returns named supported option paired with a name-based enable/disable flag
Acl::OptionsParser::SupportedOption
Acl::OptionsParser::supportedOption(const SBuf &name) const
{
    for (const auto option: options_) {
        if (name.cmp(option->onName) == 0)
            return SupportedOption(option, true);
        if (option->offName && name.cmp(option->offName) == 0)
            return SupportedOption(option, false);
    }

    throw TexcHere(ToSBuf("unsupported ACL option: ", name));
}

void
Acl::OptionsParser::parse()
{
    OptionExtractor oex;
    while (oex.extractOne()) {
        const auto explicitOption = supportedOption(oex.name);
        const auto &option = *explicitOption.first;
        if (explicitOption.second) {
            /* configuration enables this option */
            if (option.configured())
                debugs(28, 7, "acl uses multiple " << oex.name << " options");
            switch (option.valueExpectation)
            {
            case Option::valueNone:
                if (oex.hasValue)
                    throw TexcHere(ToSBuf("unexpected value for an ACL option: ", oex.name, '=', oex.value()));
                option.enable();
                break;
            case Option::valueRequired:
                if (!oex.hasValue)
                    throw TexcHere(ToSBuf("missing required value for ACL option ", oex.name));
                option.configureWith(oex.value());
                break;
            case Option::valueOptional:
                if (oex.hasValue)
                    option.configureWith(oex.value());
                else
                    option.enable();
                break;
            }
        } else {
            if (oex.hasValue)
                throw TexcHere(ToSBuf("unexpected value when disabling an ACL option: ", oex.name, '=', oex.value()));
            option.disable();
        }
    }
}

void
Acl::ParseFlags(const Options &options)
{
    OptionsParser parser(options);
    parser.parse();
}

const Acl::Options &
Acl::NoOptions()
{
    static const Options none;
    return none;
}

const Acl::BooleanOption &
Acl::CaseSensitivityOption()
{
    static const BooleanOption MyOption("-i", "+i");
    return MyOption;
}

std::ostream &
Acl::operator <<(std::ostream &os, const Option &option)
{
    option.print(os);
    return os;
}

std::ostream &
Acl::operator <<(std::ostream &os, const Options &options)
{
    for (const auto option: options)
        os << *option;

    // TODO: Remember "--" presence and print that delimiter when present.
    // Detecting its need is difficult because parameter flags start with "-".
    return os;
}

