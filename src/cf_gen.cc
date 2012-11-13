/*
 * DEBUG: none          Generate squid.conf.default and cf_parser.cci
 * AUTHOR: Max Okumoto
 * AUTHOR: Francesco Chemolli
 * AUTHOR: Amos Jeffries
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

/*****************************************************************************
 * Abstract:	This program parses the input file and generates code and
 *		files used to configure the variables in squid.
 *		(ie it creates the squid.conf.default file from the cf.data file)
 *
 *		The output files are as follows:
 *		cf_parser.cci - this file contains, default_all() which
 *			  initializes variables with the default
 *			  values, parse_line() that parses line from
 *			  squid.conf.default, dump_config that dumps the
 *			  current the values of the variables.
 *		squid.conf.default - default configuration file given to the server
 *			 administrator.
 *****************************************************************************/

/*
 * hack around a bug in intel's c++ compiler's libraries which do not
 * correctly support 64-bit iostreams
 */
#if defined(__INTEL_COMPILER) && defined(_FILE_OFFSET_BITS) && \
_FILE_OFFSET_BITS==64
#undef _FILE_OFFSET_BITS
#endif

#include <cassert>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <list>
#include <stack>

#include "cf_gen_defines.cci"

#define MAX_LINE	1024	/* longest configuration line */
#define _PATH_PARSER		"cf_parser.cci"
#define _PATH_SQUID_CONF	"squid.conf.documented"
#define _PATH_SQUID_CONF_SHORT	"squid.conf.default"
#define _PATH_CF_DEPEND		"cf.data.depend"

enum State {
    sSTART,
    s1,
    sDOC,
    sNOCOMMENT,
    sEXIT
};

typedef std::list<std::string> LineList;
typedef std::list<std::string> TypeDepList;
typedef std::list<std::string> EntryAliasList;

class DefaultValues
{
public:
    DefaultValues() : preset(), if_none(), docs() {}
    ~DefaultValues() {}

    /// Default config lines to be defined before parsing the config files.
    LineList preset;

    /// Default config lines to parse if the directive has no prior settings.
    /// This is mutually exclusive with preset values.
    /// An error will be printed during build if they clash.
    LineList if_none;

    /// Default config lines to parse and add to any prior settings.
    LineList postscriptum;

    /// Text description to use in documentation for the default.
    /// If unset the preset or if-none values will be displayed.
    LineList docs;
};

class Entry
{
public:
    Entry(const char *str) :
            name(str), alias(),type(), loc(),
            defaults(), comment(), ifdef(), doc(), nocomment(),
            array_flag(0) {}
    ~Entry() {}

    std::string name;
    EntryAliasList alias;
    std::string type;
    std::string loc;
    DefaultValues defaults;
    std::string comment;
    std::string ifdef;
    LineList doc;
    LineList nocomment;
    int array_flag;

    void genParse(std::ostream &fout) const;

private:
    void genParseAlias(const std::string &, std::ostream &) const;
};

typedef std::list<class Entry> EntryList;

class Type
{
public:
    Type(const char *str) : name(str) {}
    ~Type() {}

    std::string name;
    TypeDepList depend;
};

typedef std::list<class Type> TypeList;

static const char WS[] = " \t\n";
static int gen_default(const EntryList &, std::ostream &);
static void gen_parse(const EntryList &, std::ostream &);
static void gen_dump(const EntryList &, std::ostream&);
static void gen_free(const EntryList &, std::ostream&);
static void gen_conf(const EntryList &, std::ostream&, bool verbose_output);
static void gen_default_if_none(const EntryList &, std::ostream&);
static void gen_default_postscriptum(const EntryList &, std::ostream&);
static bool isDefined(const std::string &name);
static const char *available_if(const std::string &name);

static void
checkDepend(const std::string &directive, const char *name, const TypeList &types, const EntryList &entries)
{
    for (TypeList::const_iterator t = types.begin(); t != types.end(); ++t) {
        if (t->name.compare(name) != 0)
            continue;
        for (TypeDepList::const_iterator dep = t->depend.begin(); dep != t->depend.end(); ++dep) {
            EntryList::const_iterator entry = entries.begin();
            for (; entry != entries.end(); ++entry) {
                if (entry->name.compare(*dep) == 0)
                    break;
            }
            if (entry == entries.end()) {
                std::cerr << "ERROR: '" << directive << "' (" << name << ") depends on '" << *dep << "'\n";
                exit(1);
            }
        }
        return;
    }
    std::cerr << "ERROR: Dependencies for cf.data type '" << name << "' used in ' " << directive << "' not defined\n" ;
    exit(1);
}

static void
usage(const char *program_name)
{
    std::cerr << "Usage: " << program_name << " cf.data cf.data.depend\n";
    exit(1);
}

int
main(int argc, char *argv[])
{
    char *input_filename;
    const char *output_filename = _PATH_PARSER;
    const char *conf_filename = _PATH_SQUID_CONF;
    const char *conf_filename_short = _PATH_SQUID_CONF_SHORT;
    const char *type_depend;
    int linenum = 0;
    EntryList entries;
    TypeList types;
    enum State state;
    int rc = 0;
    char *ptr = NULL;
    char buff[MAX_LINE];
    std::ifstream fp;
    std::stack<std::string> IFDEFS;

    if (argc != 3)
        usage(argv[0]);

    input_filename = argv[1];
    type_depend = argv[2];

    /*-------------------------------------------------------------------*
     * Parse type dependencies
     *-------------------------------------------------------------------*/
    fp.open(type_depend, std::ifstream::in);
    if (fp.fail()) {
        std::cerr << "error while opening type dependencies file '" <<
                  type_depend << "': " << strerror(errno) << std::endl;
        exit(1);
    }

    while (fp.good()) {
        fp.getline(buff,MAX_LINE);
        const char *type = strtok(buff, WS);
        const char *dep;
        if (!type || type[0] == '#')
            continue;
        Type t(type);
        while ((dep = strtok(NULL, WS)) != NULL) {
            t.depend.push_front(dep);
        }
        types.push_front(t);
    }
    fp.close();
    fp.clear(); // BSD does not reset flags in close().

    /*-------------------------------------------------------------------*
     * Parse input file
     *-------------------------------------------------------------------*/

    /* Open input file */
    fp.open(input_filename, std::ifstream::in);
    if (fp.fail()) {
        std::cerr << "error while opening input file '" <<
                  input_filename << "': " << strerror(errno) << std::endl;
        exit(1);
    }

    state = sSTART;

    while (fp.getline(buff,MAX_LINE), fp.good() && state != sEXIT) {
        char *t;

        ++linenum;

        if ((t = strchr(buff, '\n')))
            *t = '\0';

        if (strncmp(buff, "IF ", 3) == 0) {
            if ((ptr = strtok(buff + 3, WS)) == NULL) {
                std::cerr << "Missing IF parameter on line" << linenum << std::endl;
                exit(1);
            }
            IFDEFS.push(ptr);
            continue;
        } else if (strcmp(buff, "ENDIF") == 0) {
            if (IFDEFS.size() == 0) {
                std::cerr << "ENDIF without IF before on line " << linenum << std::endl;
                exit(1);
            }
            IFDEFS.pop();
        } else if (!IFDEFS.size() || isDefined(IFDEFS.top()))
            switch (state) {

            case sSTART:

                if ((strlen(buff) == 0) || (!strncmp(buff, "#", 1))) {
                    /* ignore empty and comment lines */
                    (void) 0;
                } else if (!strncmp(buff, "NAME:", 5)) {
                    char *name, *aliasname;

                    if ((name = strtok(buff + 5, WS)) == NULL) {
                        std::cerr << "Error in input file\n";
                        exit(1);
                    }

                    entries.push_back(name);

                    while ((aliasname = strtok(NULL, WS)) != NULL)
                        entries.back().alias.push_front(aliasname);

                    state = s1;
                } else if (!strcmp(buff, "EOF")) {
                    state = sEXIT;
                } else if (!strcmp(buff, "COMMENT_START")) {
                    entries.push_back("comment");
                    entries.back().loc = "none";
                    state = sDOC;
                } else {
                    std::cerr << "Error on line " << linenum << std::endl <<
                              "--> " << buff << std::endl;
                    exit(1);
                }

                break;

            case s1: {
                Entry &curr = entries.back();

                if ((strlen(buff) == 0) || (!strncmp(buff, "#", 1))) {
                    /* ignore empty and comment lines */
                    (void) 0;
                } else if (!strncmp(buff, "COMMENT:", 8)) {
                    ptr = buff + 8;

                    while (isspace((unsigned char)*ptr))
                        ++ptr;

                    curr.comment = ptr;
                } else if (!strncmp(buff, "DEFAULT:", 8)) {
                    ptr = buff + 8;

                    while (isspace((unsigned char)*ptr))
                        ++ptr;

                    curr.defaults.preset.push_back(ptr);
                } else if (!strncmp(buff, "DEFAULT_IF_NONE:", 16)) {
                    ptr = buff + 16;

                    while (isspace((unsigned char)*ptr))
                        ++ptr;

                    curr.defaults.if_none.push_back(ptr);
                } else if (!strncmp(buff, "POSTSCRIPTUM:", 13)) {
                    ptr = buff + 13;

                    while (isspace((unsigned char)*ptr))
                        ++ptr;

                    curr.defaults.postscriptum.push_back(ptr);
                } else if (!strncmp(buff, "DEFAULT_DOC:", 12)) {
                    ptr = buff + 12;

                    while (isspace((unsigned char)*ptr))
                        ++ptr;

                    curr.defaults.docs.push_back(ptr);
                } else if (!strncmp(buff, "LOC:", 4)) {
                    if ((ptr = strtok(buff + 4, WS)) == NULL) {
                        std::cerr << "Error on line " << linenum << std::endl;
                        exit(1);
                    }

                    curr.loc = ptr;
                } else if (!strncmp(buff, "TYPE:", 5)) {
                    if ((ptr = strtok(buff + 5, WS)) == NULL) {
                        std::cerr << "Error on line " << linenum << std::endl;
                        exit(1);
                    }

                    /* hack to support arrays, rather than pointers */
                    if (0 == strcmp(ptr + strlen(ptr) - 2, "[]")) {
                        curr.array_flag = 1;
                        *(ptr + strlen(ptr) - 2) = '\0';
                    }

                    checkDepend(curr.name, ptr, types, entries);
                    curr.type = ptr;
                } else if (!strncmp(buff, "IFDEF:", 6)) {
                    if ((ptr = strtok(buff + 6, WS)) == NULL) {
                        std::cerr << "Error on line " << linenum << std::endl;
                        exit(1);
                    }

                    curr.ifdef = ptr;
                } else if (!strcmp(buff, "DOC_START")) {
                    state = sDOC;
                } else if (!strcmp(buff, "DOC_NONE")) {
                    state = sSTART;
                } else {
                    std::cerr << "Error on line " << linenum << std::endl;
                    exit(1);
                }
            }
            break;

            case sDOC:
                if (!strcmp(buff, "DOC_END") || !strcmp(buff, "COMMENT_END")) {
                    state = sSTART;
                } else if (!strcmp(buff, "NOCOMMENT_START")) {
                    state = sNOCOMMENT;
                } else { // if (buff != NULL) {
                    assert(buff != NULL);
                    entries.back().doc.push_back(buff);
                }
                break;

            case sNOCOMMENT:
                if (!strcmp(buff, "NOCOMMENT_END")) {
                    state = sDOC;
                } else { // if (buff != NULL) {
                    assert(buff != NULL);
                    entries.back().nocomment.push_back(buff);
                }
                break;

            case sEXIT:
                assert(0);		/* should never get here */
                break;
            }

    }

    if (state != sEXIT) {
        std::cerr << "Error: unexpected EOF\n";
        exit(1);
    }

    fp.close();

    /*-------------------------------------------------------------------*
     * Generate default_all()
     * Generate parse_line()
     * Generate dump_config()
     * Generate free_all()
     * Generate example squid.conf.default file
     *-------------------------------------------------------------------*/

    /* Open output x.c file */

    std::ofstream fout(output_filename,std::ostream::out);
    if (!fout.good()) {
        std::cerr << "error while opening output .c file '" <<
                  output_filename << "': " << strerror(errno) << std::endl;
        exit(1);
    }

    fout <<  "/*\n" <<
    " * Generated automatically from " << input_filename << " by " <<
    argv[0] << "\n"
    " *\n"
    " * Abstract: This file contains routines used to configure the\n"
    " *           variables in the squid server.\n"
    " */\n"
    "\n";

    rc = gen_default(entries, fout);

    gen_default_if_none(entries, fout);

    gen_default_postscriptum(entries, fout);

    gen_parse(entries, fout);

    gen_dump(entries, fout);

    gen_free(entries, fout);

    fout.close();

    /* Open output x.conf file */
    fout.open(conf_filename,std::ostream::out);
    if (!fout.good()) {
        std::cerr << "error while opening output conf file '" <<
                  output_filename << "': " << strerror(errno) << std::endl;
        exit(1);
    }

    gen_conf(entries, fout, 1);

    fout.close();

    fout.open(conf_filename_short,std::ostream::out);
    if (!fout.good()) {
        std::cerr << "error while opening output short conf file '" <<
                  output_filename << "': " << strerror(errno) << std::endl;
        exit(1);
    }
    gen_conf(entries, fout, 0);
    fout.close();

    return (rc);
}

static int
gen_default(const EntryList &head, std::ostream &fout)
{
    int rc = 0;
    fout << "static void" << std::endl <<
    "default_line(const char *s)" << std::endl <<
    "{" << std::endl <<
    "    LOCAL_ARRAY(char, tmp_line, BUFSIZ);" << std::endl <<
    "    xstrncpy(tmp_line, s, BUFSIZ);" << std::endl <<
    "    xstrncpy(config_input_line, s, BUFSIZ);" << std::endl <<
    "    config_lineno++;" << std::endl <<
    "    parse_line(tmp_line);" << std::endl <<
    "}" << std::endl << std::endl;
    fout << "static void" << std::endl <<
    "default_all(void)" << std::endl <<
    "{" << std::endl <<
    "    cfg_filename = \"Default Configuration\";" << std::endl <<
    "    config_lineno = 0;" << std::endl;

    for (EntryList::const_iterator entry = head.begin(); entry != head.end(); ++entry) {
        assert(entry->name.size());

        if (!entry->name.compare("comment"))
            continue;

        if (!entry->type.compare("obsolete"))
            continue;

        if (!entry->loc.size()) {
            std::cerr << "NO LOCATION FOR " << entry->name << std::endl;
            rc |= 1;
            continue;
        }

        if (!entry->defaults.preset.size() && entry->defaults.if_none.empty()) {
            std::cerr << "NO DEFAULT FOR " << entry->name << std::endl;
            rc |= 1;
            continue;
        }

        if (!entry->defaults.preset.size() || entry->defaults.preset.front().compare("none") == 0) {
            fout << "    // No default for " << entry->name << std::endl;
        } else {
            if (entry->ifdef.size())
                fout << "#if " << entry->ifdef << std::endl;

            for (LineList::const_iterator l = entry->defaults.preset.begin(); l != entry->defaults.preset.end(); ++l) {
                fout << "    default_line(\"" << entry->name << " " << *l << "\");" << std::endl;
            }

            if (entry->ifdef.size())
                fout << "#endif" << std::endl;
        }
    }

    fout << "    cfg_filename = NULL;" << std::endl <<
    "}" << std::endl << std::endl;
    return rc;
}

static void
gen_default_if_none(const EntryList &head, std::ostream &fout)
{
    fout << "static void" << std::endl <<
    "defaults_if_none(void)" << std::endl <<
    "{" << std::endl <<
    "    cfg_filename = \"Default Configuration (if absent)\";" << std::endl <<
    "    config_lineno = 0;" << std::endl;

    for (EntryList::const_iterator entry = head.begin(); entry != head.end(); ++entry) {
        assert(entry->name.size());

        if (!entry->loc.size())
            continue;

        if (entry->defaults.if_none.empty())
            continue;

        if (!entry->defaults.preset.empty()) {
            std::cerr << "ERROR: " << entry->name << " has preset defaults. DEFAULT_IF_NONE cannot be true." << std::endl;
            exit(1);
        }

        if (entry->ifdef.size())
            fout << "#if " << entry->ifdef << std::endl;

        fout << "    if (check_null_" << entry->type << "(" << entry->loc << ")) {" << std::endl;
        for (LineList::const_iterator l = entry->defaults.if_none.begin(); l != entry->defaults.if_none.end(); ++l)
            fout << "        default_line(\"" << entry->name << " " << *l <<"\");" << std::endl;
        fout << "    }" << std::endl;

        if (entry->ifdef.size())
            fout << "#endif" << std::endl;
    }

    fout << "    cfg_filename = NULL;" << std::endl <<
    "}" << std::endl << std::endl;
}

/// append configuration options specified by POSTSCRIPTUM lines
static void
gen_default_postscriptum(const EntryList &head, std::ostream &fout)
{
    fout << "static void" << std::endl <<
    "defaults_postscriptum(void)" << std::endl <<
    "{" << std::endl <<
    "    cfg_filename = \"Default Configuration (postscriptum)\";" << std::endl <<
    "    config_lineno = 0;" << std::endl;

    for (EntryList::const_iterator entry = head.begin(); entry != head.end(); ++entry) {
        assert(entry->name.size());

        if (!entry->loc.size())
            continue;

        if (entry->defaults.postscriptum.empty())
            continue;

        if (entry->ifdef.size())
            fout << "#if " << entry->ifdef << std::endl;

        for (LineList::const_iterator l = entry->defaults.postscriptum.begin(); l != entry->defaults.postscriptum.end(); ++l)
            fout << "    default_line(\"" << entry->name << " " << *l <<"\");" << std::endl;

        if (entry->ifdef.size())
            fout << "#endif" << std::endl;
    }

    fout << "    cfg_filename = NULL;" << std::endl <<
    "}" << std::endl << std::endl;
}

void
Entry::genParseAlias(const std::string &aName, std::ostream &fout) const
{
    fout << "    if (!strcmp(token, \"" << aName << "\")) {" << std::endl;
    if (ifdef.size())
        fout << "#if " << ifdef << std::endl;
    fout << "        ";
    if (type.compare("obsolete") == 0) {
        fout << "debugs(0, DBG_CRITICAL, \"ERROR: Directive '" << aName << "' is obsolete.\");\n";
        for (LineList::const_iterator l = doc.begin(); l != doc.end(); ++l) {
            // offset line to strip initial whitespace tab byte
            fout << "        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), \"" << aName << " : " << &(*l)[1] << "\");" << std::endl;
        }
        fout << "        parse_obsolete(token);";
    } else if (!loc.size() || loc.compare("none") == 0) {
        fout << "parse_" << type << "();";
    } else {
        fout << "parse_" << type << "(&" << loc << (array_flag ? "[0]" : "") << ");";
    }
    fout << std::endl;
    if (ifdef.size()) {
        fout <<
        "#else" << std::endl <<
        "    debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), \"ERROR: '" << name << "' requires " << available_if(ifdef) << "\");" << std::endl <<
        "#endif" << std::endl;
    }
    fout << "        return 1;" << std::endl;
    fout << "    };" << std::endl;
}

void
Entry::genParse(std::ostream &fout) const
{
    if (name.compare("comment") == 0)
        return;

    // Once for the current directive name
    genParseAlias(name, fout);

    // All accepted aliases
    for (EntryAliasList::const_iterator a = alias.begin(); a != alias.end(); ++a) {
        genParseAlias(*a, fout);
    }
}

static void
gen_parse(const EntryList &head, std::ostream &fout)
{
    fout <<
    "static int\n"
    "parse_line(char *buff)\n"
    "{\n"
    "\tchar\t*token;\n"
    "\tif ((token = strtok(buff, w_space)) == NULL) \n"
    "\t\treturn 1;\t/* ignore empty lines */\n";

    for (EntryList::const_iterator e = head.begin(); e != head.end(); ++e)
        e->genParse(fout);

    fout << "\treturn 0; /* failure */\n"
    "}\n\n";

}

static void
gen_dump(const EntryList &head, std::ostream &fout)
{
    fout <<
    "static void" << std::endl <<
    "dump_config(StoreEntry *entry)" << std::endl <<
    "{" << std::endl <<
    "    debugs(5, 4, HERE);" << std::endl;

    for (EntryList::const_iterator e = head.begin(); e != head.end(); ++e) {

        if (!e->loc.size() || e->loc.compare("none") == 0)
            continue;

        if (e->name.compare("comment") == 0)
            continue;

        if (e->ifdef.size())
            fout << "#if " << e->ifdef << std::endl;

        fout << "    dump_" << e->type << "(entry, \"" << e->name << "\", " << e->loc << ");" << std::endl;

        if (e->ifdef.size())
            fout << "#endif" << std::endl;
    }

    fout << "}" << std::endl << std::endl;
}

static void
gen_free(const EntryList &head, std::ostream &fout)
{
    fout <<
    "static void" << std::endl <<
    "free_all(void)" << std::endl <<
    "{" << std::endl <<
    "    debugs(5, 4, HERE);" << std::endl;

    for (EntryList::const_iterator e = head.begin(); e != head.end(); ++e) {
        if (!e->loc.size() || e->loc.compare("none") == 0)
            continue;

        if (e->name.compare("comment") == 0)
            continue;

        if (e->ifdef.size())
            fout << "#if " << e->ifdef << std::endl;

        fout << "    free_" << e->type << "(&" << e->loc << (e->array_flag ? "[0]" : "") << ");" << std::endl;

        if (e->ifdef.size())
            fout << "#endif" << std::endl;
    }

    fout << "}" << std::endl << std::endl;
}

static bool
isDefined(const std::string &name)
{
    if (!name.size())
        return true;

    for (int i = 0; defines[i].name; ++i) {
        if (name.compare(defines[i].name) == 0)
            return defines[i].defined;
    }

    return false;
}

static const char *
available_if(const std::string &name)
{
    assert(name.size());

    for (int i = 0; defines[i].name; ++i) {
        if (name.compare(defines[i].name) == 0)
            return defines[i].enable;
    }

    return name.c_str();
}

static void
gen_conf(const EntryList &head, std::ostream &fout, bool verbose_output)
{
    for (EntryList::const_iterator entry = head.begin(); entry != head.end(); ++entry) {
        char buf[8192];
        LineList def;
        int enabled = 1;

        // Display TAG: line
        if (!entry->name.compare("comment"))
            (void) 0;
        else if (!entry->name.compare("obsolete"))
            (void) 0;
        else if (verbose_output) {
            fout << "#  TAG: " << entry->name;

            if (entry->comment.size())
                fout << "\t" << entry->comment;

            fout << std::endl;
        }

        // Display --enable/--disable disclaimer
        if (!isDefined(entry->ifdef)) {
            if (verbose_output) {
                fout << "# Note: This option is only available if Squid is rebuilt with the" << std::endl <<
                "#       " << available_if(entry->ifdef) << std::endl <<
                "#" << std::endl;
            }
            enabled = 0;
        }

        // Display DOC_START section
        if (verbose_output && entry->doc.size()) {
            for (LineList::const_iterator line = entry->doc.begin(); line != entry->doc.end(); ++line) {
                fout << "#" << *line << std::endl;
            }
        }

        if (entry->defaults.docs.size()) {
            // Display the DEFAULT_DOC line(s)
            def = entry->defaults.docs;
        } else {
            if (entry->defaults.preset.size() && entry->defaults.preset.front().compare("none") != 0) {
                // Display DEFAULT: line(s)
                for (LineList::const_iterator l = entry->defaults.preset.begin(); l != entry->defaults.preset.end(); ++l) {
                    snprintf(buf, sizeof(buf), "%s %s", entry->name.c_str(), l->c_str());
                    def.push_back(buf);
                }
            } else if (entry->defaults.if_none.size()) {
                // Display DEFAULT_IF_NONE: line(s)
                for (LineList::const_iterator l = entry->defaults.if_none.begin(); l != entry->defaults.if_none.end(); ++l) {
                    snprintf(buf, sizeof(buf), "%s %s", entry->name.c_str(), l->c_str());
                    def.push_back(buf);
                }
            }
        }

        // Display "none" if no default is set or comments to display
        if (def.empty() && entry->nocomment.empty() && entry->name.compare("comment") != 0)
            def.push_back("none");

        if (verbose_output && def.size()) {
            fout << "#Default:\n";
            while (def.size()) {
                fout << "# " << def.front() << std::endl;
                def.pop_front();
            }
            if (entry->doc.empty() && entry->nocomment.empty())
                fout << std::endl;
        }

        if (verbose_output && entry->nocomment.size())
            fout << "#" << std::endl;

        if (enabled || verbose_output) {
            for (LineList::const_iterator line = entry->nocomment.begin(); line != entry->nocomment.end(); ++line) {
                if (!enabled && line->at(0) != '#')
                    fout << "#";
                fout << *line << std::endl;
            }
        }

        if (verbose_output && entry->doc.size()) {
            fout << std::endl;
        }
    }
}
