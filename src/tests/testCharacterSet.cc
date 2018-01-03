/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "testCharacterSet.h"
#include "unitTestMain.h"

#include <string>

CPPUNIT_TEST_SUITE_REGISTRATION( testCharacterSet );

void
testCharacterSet::CharacterSetConstruction()
{
    {
        CharacterSet t(nullptr,"");
        CPPUNIT_ASSERT_EQUAL(std::string("anonymous"),std::string(t.name));
    }
    {
        CharacterSet t("test","");
        CPPUNIT_ASSERT_EQUAL(std::string("test"),std::string(t.name));
    }
    {
        CharacterSet t("test","");
        for (int j = 0; j < 256; ++j)
            CPPUNIT_ASSERT_EQUAL(false,t[j]);
    }
    {
        CharacterSet t("test","0");
        CPPUNIT_ASSERT_EQUAL(true,t['0']);
        for (int j = 0; j < 256; ++j) {
            if (j != '0') {
                CPPUNIT_ASSERT_EQUAL(false,t[j]);
            } else {
                CPPUNIT_ASSERT_EQUAL(true,t[j]);
            }
        }
    }
}

void
testCharacterSet::CharacterSetAdd()
{
    CharacterSet t("test","0");
    t.add(0);
    CPPUNIT_ASSERT_EQUAL(true,t['\0']);
    CPPUNIT_ASSERT_EQUAL(true,t['0']);
}

void
testCharacterSet::CharacterSetAddRange()
{
    CharacterSet t("test","");
    t.addRange('0','9');
    CPPUNIT_ASSERT_EQUAL(true,t['0']);
    CPPUNIT_ASSERT_EQUAL(true,t['5']);
    CPPUNIT_ASSERT_EQUAL(true,t['9']);
    CPPUNIT_ASSERT_EQUAL(false,t['a']);
}

void
testCharacterSet::CharacterSetConstants()
{
    CPPUNIT_ASSERT_EQUAL(true,CharacterSet::ALPHA['a']);
    CPPUNIT_ASSERT_EQUAL(true,CharacterSet::ALPHA['z']);
    CPPUNIT_ASSERT_EQUAL(true,CharacterSet::ALPHA['A']);
    CPPUNIT_ASSERT_EQUAL(true,CharacterSet::ALPHA['Z']);
    CPPUNIT_ASSERT_EQUAL(false,CharacterSet::ALPHA['5']);
}

void
testCharacterSet::CharacterSetUnion()
{
    {
        CharacterSet hex("hex","");
        hex += CharacterSet::DIGIT;
        hex += CharacterSet(nullptr,"aAbBcCdDeEfF");
        CPPUNIT_ASSERT_EQUAL(CharacterSet::HEXDIG, hex);
        for (int j = 0; j < 256; ++j)
            CPPUNIT_ASSERT_EQUAL(CharacterSet::HEXDIG[j],hex[j]);
    }
    {
        CharacterSet hex(nullptr,"");
        hex = CharacterSet::DIGIT + CharacterSet(nullptr,"aAbBcCdDeEfF");
        for (int j = 0; j < 256; ++j)
            CPPUNIT_ASSERT_EQUAL(CharacterSet::HEXDIG[j],hex[j]);
    }
}

void
testCharacterSet::CharacterSetEqualityOp()
{
    CPPUNIT_ASSERT_EQUAL(CharacterSet::ALPHA, CharacterSet::ALPHA);
    CPPUNIT_ASSERT_EQUAL(CharacterSet::BIT, CharacterSet(nullptr,"01"));
    CPPUNIT_ASSERT_EQUAL(CharacterSet(nullptr,"01"), CharacterSet(nullptr,"01"));
    CPPUNIT_ASSERT_EQUAL(CharacterSet(nullptr,"01"), CharacterSet("","01"));
    CPPUNIT_ASSERT_EQUAL(CharacterSet::BIT, CharacterSet("bit",'0','1'));
    CPPUNIT_ASSERT_EQUAL(CharacterSet::BIT, CharacterSet("bit", {{'0','1'}}));
    CPPUNIT_ASSERT_EQUAL(CharacterSet::BIT, CharacterSet("bit", {{'0','0'},{'1','1'}}));
}

void
testCharacterSet::CharacterSetSubtract()
{
    CharacterSet sample(nullptr, "0123456789aAbBcCdDeEfFz");

    sample -= CharacterSet(nullptr, "z"); //character in set
    CPPUNIT_ASSERT_EQUAL(CharacterSet::HEXDIG, sample);

    sample -= CharacterSet(nullptr, "z"); // character not in set
    CPPUNIT_ASSERT_EQUAL(CharacterSet::HEXDIG, sample);

    sample += CharacterSet(nullptr, "z");
    // one in set, one not; test operator-
    CPPUNIT_ASSERT_EQUAL(CharacterSet::HEXDIG, sample - CharacterSet(nullptr, "qz"));
}

