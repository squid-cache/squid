/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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

void
Mgr::QueryParams::ParseParam(SBuf &paramStr, Param &param)
{
    static const CharacterSet nameChars = CharacterSet("param-name", "_") + CharacterSet::ALPHA + CharacterSet::DIGIT;

    Parser::Tokenizer tok(paramStr);

    SBuf name;
    if (!tok.prefix(name, nameChars))
        throw TexcHere("invalid character in action name");

    if (!tok.skip('='))
        throw TexcHere("missing parameter value");

    static const CharacterSet badValueChars = CharacterSet("param-value-bad", "&= ");
    SBuf valueStr = tok.remaining();
    if (valueStr.findFirstOf(badValueChars) != SBuf::npos)
        throw TexcHere("invalid character in parameter value");

    param.first = SBufToString(name);

    std::vector<int> array;
    int64_t intVal = 0;
    while (tok.int64(intVal, 10, false)) {
        static const CharacterSet comma("comma",",");
        (void)tok.skipAll(comma);
        Must(intVal >= std::numeric_limits<int>::min());
        Must(intVal <= std::numeric_limits<int>::max());
        array.emplace_back(int(intVal));
    }

    if (tok.atEnd())
        param.second = new IntParam(array);
    else
        param.second = new StringParam(SBufToString(valueStr));
}

void
Mgr::QueryParams::Parse(Parser::Tokenizer &tok, QueryParams &aParams)
{
    static const CharacterSet paramDelim("query-param","&");

    SBuf foundStr;
    while (tok.token(foundStr, paramDelim)) {
        Param param;
        ParseParam(foundStr, param);
        aParams.params.push_back(param);
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

