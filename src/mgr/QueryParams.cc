/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/IntParam.h"
#include "mgr/QueryParams.h"
#include "mgr/StringParam.h"
#include "parser/Tokenizer.h"
#include "sbuf/StringConvert.h"

#include <limits>

Mgr::QueryParam::Pointer
Mgr::QueryParams::get(const String& name) const
{
    Must(name.size() != 0);
    Params::const_iterator pos = find(name);
    return (pos == params.end() ? NULL : pos->second);
}

void
Mgr::QueryParams::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.putInt(params.size());
    for (Params::const_iterator iter = params.begin(); iter != params.end(); ++iter) {
        Must(iter->first.size() != 0);
        msg.putString(iter->first);
        Must(iter->second != NULL);
        iter->second->pack(msg);
    }
}

void
Mgr::QueryParams::unpack(const Ipc::TypedMsgHdr& msg)
{
    int count = msg.getInt();
    Must(count >= 0);
    params.clear();
    for ( ; count > 0; --count) {
        String name;
        msg.getString(name);
        Must(name.size() != 0);
        QueryParam::Type type;
        msg.getPod(type);
        QueryParam::Pointer value = CreateParam(type);
        value->unpackValue(msg);
        params.push_back(Param(name, value));
    }
}

Mgr::QueryParams::Params::const_iterator
Mgr::QueryParams::find(const String& name) const
{
    Must(name.size() != 0);
    Params::const_iterator iter = params.begin();
    for ( ; iter != params.end(); ++iter) {
        if (name.caseCmp(iter->first) == 0)
            break;
    }
    return iter;
}

/**
 * Parses the value part of a "param=value" URL section.
 * Value can be a comma-separated list of integers or an opaque string.
 *
 *   value  = *pchar | ( 1*DIGIT *( ',' 1*DIGIT ) )
 *
 * \note opaque string may be a list with a non-integer (e.g., "1,2,3,z")
 */
Mgr::QueryParam::Pointer
ParseParamValue(const SBuf &rawValue)
{
    static const CharacterSet comma("comma", ",");

    Parser::Tokenizer tok(rawValue);
    std::vector<int> array;
    int64_t intVal = 0;
    while (tok.int64(intVal, 10, false)) {
        Must(intVal >= std::numeric_limits<int>::min());
        Must(intVal <= std::numeric_limits<int>::max());
        array.emplace_back(intVal);
        // integer list has comma between values.
        // Require at least one potential DIGIT after the skipped ','
        if (tok.remaining().length() > 1)
            (void)tok.skipOne(comma);
    }

    if (tok.atEnd())
        return new Mgr::IntParam(array);
    else
        return new Mgr::StringParam(SBufToString(rawValue));
}

/**
 * Syntax:
 *   query  = [ param *( '&' param ) ]
 *   param  = name '=' value
 *   name   = [a-zA-Z0-9]+
 *   value  = *pchar | ( 1*DIGIT *( ',' 1*DIGIT ) )
 */
void
Mgr::QueryParams::Parse(Parser::Tokenizer &tok, QueryParams &aParams)
{
    static const CharacterSet nameChars = CharacterSet("param-name", "_") + CharacterSet::ALPHA + CharacterSet::DIGIT;
    static const CharacterSet valueChars = CharacterSet("param-value", "&= #").complement();
    static const CharacterSet delimChars("param-delim", "&");

    while (!tok.atEnd()) {

        // TODO: remove '#' processing when AnyP::Uri splits 'query#fragment' properly
        // #fragment handled by caller. Do not throw.
        if (tok.remaining()[0] == '#')
            return;

        if (tok.skipAll(delimChars))
            continue;

        SBuf nameStr;
        if (!tok.prefix(nameStr, nameChars))
            throw TextException("invalid query parameter name", Here());
        if (!tok.skip('='))
            throw TextException("missing parameter value", Here());

        SBuf valueStr;
        if (!tok.prefix(valueStr, valueChars))
            throw TextException("missing or malformed parameter value", Here());

        const auto name = SBufToString(nameStr);
        const auto value = ParseParamValue(valueStr);
        aParams.params.emplace_back(name, value);
    }
}

Mgr::QueryParam::Pointer
Mgr::QueryParams::CreateParam(QueryParam::Type aType)
{
    switch (aType) {
    case QueryParam::ptInt:
        return new IntParam();

    case QueryParam::ptString:
        return new StringParam();

    default:
        throw TexcHere("unknown parameter type");
        break;
    }
    return NULL;
}
