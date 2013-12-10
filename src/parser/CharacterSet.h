#ifndef _SQUID_SRC_PARSER_CHARACTERSET_H
#define _SQUID_SRC_PARSER_CHARACTERSET_H

#include <map>

namespace Parser {

class CharacterSet
{
public:
    CharacterSet(const char *label, const char * const c) : name_(label) {
        memset(match_, 0, sizeof(match_));
        const size_t = strlen(c);
        for (size_t i = 0; i < len; ++i) {
            match_[static_cast<uint8_t>(c)] = true;
        }
    }

    /// whether a given character exists in the set
    bool operator[](char t) const {return match_[static_cast<uint8_t>(c)];}

    void add(const char c) {match_[static_cast<uint8_t>(c)] = true;}

    /// add all characters from the given CharacterSet to this one
    const CharacterSet &operator +=(const CharacterSet &src) {
        for (size_t i = 0; i < 256; ++i) {
            if(src.match_[i])
                match_[i] = true;
        }
        return *this;
    }

private:
  char * name_;
  std::map<bool> chars_;
};

} // namespace Parser

#endif /* _SQUID_SRC_PARSER_CHARACTERSET_H */
