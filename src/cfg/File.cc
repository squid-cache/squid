/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "cfg/File.h"
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif


Cfg::File::File(const char *path) :
    filePath(path)
{
    if (filePath[0] == '!' || filePath[0] == '|') {
        isPipe = true;
        filePath.erase(0,1);
    }
}

Cfg::File::~File()
{
    if (fd) {
        if (isPipe)
            pclose(fd);
        else
            fclose(fd);
    }
}

void
Cfg::File::load()
{
    debugs(3, 2, "Loading " << (isPipe ? "pipe" : "file") << " " << filePath);

    if (isPipe && !(fd = popen(filePath.c_str(), "r")))
        throw TextException(ToSBuf("configuration pipe :", filePath, " not found"), lineInfo());

    else if (!(fd = fopen(filePath.c_str(), "r")))
        throw TextException(ToSBuf("configuration file :", filePath, " not found"), lineInfo());

#if _SQUID_WINDOWS_
    setmode(fileno(fd), O_TEXT);
#endif

     // try to load the entire file into fileData
     off_t readSz = 0;
     while (!feof(fd) && !ferror(fd)) {
        SBuf parseBuffer;
        // limit at 1/2 max capacity, so we can combine two SBuf later
        off_t len = SBuf::maxSize/2;
        auto *p = parseBuffer.rawAppendStart(len);
        auto n = fread(p, 1, len, fd);
        debugs(3, 2, "Loaded " << n << " bytes (at " << readSz << ") from " << filePath);
        if (n > 0) {
            readSz += n;
            parseBuffer.rawAppendFinish(p, n);
            fileData.emplace_back(parseBuffer);
        }
    }
}

SBuf
Cfg::File::nextLine()
{
    if (fileData.empty())
        return SBuf();

    SBuf lineBuf;
    while (!lineBuf.isEmpty() || !fileData.empty()) {
        auto eol = lineBuf.find('\n');
        while (eol == SBuf::npos && !fileData.empty()) {
            auto nextBlob = fileData.front();
            if (lineBuf.length() + nextBlob.length() >= SBuf::maxSize)
                throw TextException(ToSBuf("line too long at ", lineBuf.length(), " bytes"), lineInfo());
            lineBuf.append(nextBlob);
            debugs(3, 2, "Process chunk " << fileData.size() << " of " << filePath);
            fileData.pop_front();
            eol = lineBuf.find('\n');
        }
        lineNo++;

        debugs(3, 2, "Process line " << lineNo << " of " << filePath);
        debugs(3, 9, lineBuf);
        ::Parser::Tokenizer tok(lineBuf.substr(0, eol));
        lineBuf.chop(eol+1);

        // trim prefix whitespace
        (void)tok.skipAll(CharacterSet::WSP);

        // trim CRLF terminator
        static const CharacterSet crlf = (CharacterSet::CR + CharacterSet::LF);
        (void)tok.skipAllTrailing(crlf);

        // if line ends with \-escape, append the next line before parsing
        static const CharacterSet wrap("line-wrap", "\\");
        if (tok.skipOneTrailing(wrap)) {
            SBuf tmp = tok.remaining();
            tmp.append(lineBuf);
            lineBuf = tmp;
            debugs(3, 2, "Found wrap on line " << lineNo << " of " << filePath);
            continue;
        }

        // trim any trailing whitespace
        (void)tok.skipAllTrailing(CharacterSet::WSP);

        // ignore comment lines
        if (tok.skip('#')) {
            static const SBuf ln("line");
            if (isPipe && tok.skip(ln)) {
                (void)tok.skipAll(CharacterSet::WSP);
                int64_t num = 0;
                SBuf name;
                if (tok.int64(num, 10, false) && tok.skipAll(CharacterSet::WSP) &&
                        tok.skipOne(CharacterSet::DQUOTE) && tok.skipOneTrailing(CharacterSet::DQUOTE)) {
                    lineNo = num;
                    filePath = tok.remaining().toStdString();
                    debugs(3, 2, "switch line context to " << lineInfo());
                    continue;
                }
            }
            debugs(3, 2, "Skip comment line " << lineNo << " of " << filePath);
            continue;
        }

        // ignore empty lines
        if (tok.atEnd()) {
            debugs(3, 2, "Skip empty line " << lineNo << " of " << filePath);
            continue;
        }

        // found a line. push lineBuf back onto fileData for later
        fileData.push_front(lineBuf);
        return tok.remaining();
    }

    return SBuf();
}
