/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "rfc3986.h"
#include "base/CharacterSet.h"

// these should be moved to rfc1738.cc when it exists
namespace Rfc1738
{

/* RFC 1738 section 5:

  safe           = "$" | "-" | "_" | "." | "+"
  extra          = "!" | "*" | "'" | "(" | ")" | ","
  national       = "{" | "}" | "|" | "\" | "^" | "~" | "[" | "]" | "`"
  punctuation    = "<" | ">" | "#" | "%" | <">

  reserved       = ";" | "/" | "?" | ":" | "@" | "&" | "="
  hex            = digit | "A" | "B" | "C" | "D" | "E" | "F" |
                   "a" | "b" | "c" | "d" | "e" | "f"
  escape         = "%" hex hex

  unreserved     = alpha | digit | safe | extra
  uchar          = unreserved | escape
  xchar          = unreserved | reserved | escape
  digits         = 1*digit

*/

const CharacterSet
    Unsafe("rfc1738:unsafe", " <>\"#%{}|\\^~[]`"),
    Reserved("rfc1738:reserved", ";/?:@&="),
    // ? why called unescaped ? its the set which must never be used unescaped
    Unescaped = (Unsafe + CharacterSet::CTL + CharacterSet::OBSTEXT).rename("rfc1738:unescaped")
    ;

} // namespace Rfc1738

namespace Rfc3986
{

const CharacterSet
    GenDelims("rfc3986:gen-delims",":/?#[]@"),
    SubDelims("rfc3986:sub-delims","!$&'()*+,;="),
    Reserved = (GenDelims + SubDelims).rename("rfc3986:reserved"),
    Unreserved = CharacterSet("rfc3986:unreserved","-._~") +
        CharacterSet::ALPHA + CharacterSet::DIGIT,
    // ?
    All = (Rfc1738::Unsafe + Reserved + CharacterSet::CTL).rename("rfc3986:all")
    ;

// integer representation of hex numeric characters,
// or -1 for characters invalid in hex representation
int fromhex[256] = {
  // 0-127 (7-bit ASCII)
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0-15
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 16-31
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 32-47
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, // 48-63
  -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 64-79
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 80-95
  -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 96-111
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 112-127

  // 128-255 (8-bit UTF-8)
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

// a hex string representation of each UTF-8 character
const char * const tohex[256] = {
 "00","01","02","03","04","05","06","07","08","09","0A","0B","0C","0D","0E","0F",
 "10","11","12","13","14","15","16","17","18","19","1A","1B","1C","1D","1E","1F",
 "20","21","22","23","24","25","26","27","28","29","2A","2B","2C","2D","2E","2F",
 "30","31","32","33","34","35","36","37","38","39","3A","3B","3C","3D","3E","3F",
 "40","41","42","43","44","45","46","47","48","49","4A","4B","4C","4D","4E","4F",
 "50","51","52","53","54","55","56","57","58","59","5A","5B","5C","5D","5E","5F",
 "60","61","62","63","64","65","66","67","68","69","6A","6B","6C","6D","6E","6F",
 "70","71","72","73","74","75","76","77","78","79","7A","7B","7C","7D","7E","7F",
 "80","81","82","83","84","85","86","87","88","89","8A","8B","8C","8D","8E","8F",
 "90","91","92","93","94","95","96","97","98","99","9A","9B","9C","9D","9E","9F",
 "A0","A1","A2","A3","A4","A5","A6","A7","A8","A9","AA","AB","AC","AD","AE","AF",
 "B0","B1","B2","B3","B4","B5","B6","B7","B8","B9","BA","BB","BC","BD","BE","BF",
 "C0","C1","C2","C3","C4","C5","C6","C7","C8","C9","CA","CB","CC","CD","CE","CF",
 "D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","DA","DB","DC","DD","DE","DF",
 "E0","E1","E2","E3","E4","E5","E6","E7","E8","E9","EA","EB","EC","ED","EE","EF",
 "F0","F1","F2","F3","F4","F5","F6","F7","F8","F9","FA","FB","FC","FD","FE","FF"
};

} // namespace Rfc3986

