/*
 * DEBUG: none          Generate squid.conf.default and cf_parser.cci
 * AUTHOR: Max Okumoto
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
#include <cstring>
#include <fstream>
#include <iostream>

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

// TODO: inherit all these from link lists.

class Line
{
public:
    Line(const char *str) : data(str), next(NULL) {}
    ~Line() {}

    std::string data;
    Line *next;
};

class EntryAlias
{
public:
    EntryAlias(const char *str) : name(str), next(NULL) {}
    ~EntryAlias() {}

    std::string name;
    EntryAlias *next;
};

class Entry
{
public:
    Entry(const char *str) :
            name(str), alias(), type(), loc(),
            default_value(), default_if_none(),
            comment(), ifdef(), doc(), nocomment(),
            next(NULL) {}
    ~Entry() {}

    std::string name;
    EntryAlias *alias;
    std::string type;
    std::string loc;
    std::string default_value;
    Line *default_if_none;
    std::string comment;
    std::string ifdef;
    Line *doc;
    Line *nocomment;
    int array_flag;

    Entry *next;
};

class TypeDep
{
public:
    TypeDep(const char *str) : name(str), next(NULL) {}
    ~TypeDep() {}

    std::string name;
    TypeDep *next;
};

class Type
{
public:
    Type(const char *str) : name(str), next(NULL) {}
    ~Type() {}

    std::string name;
    TypeDep *depend;
    Type *next;
};

static const char WS[] = " \t\n";
static int gen_default(Entry *, std::ostream &);
static void gen_parse(Entry *, std::ostream &);
static void gen_parse_entry(Entry *entry, std::ostream&);
static void gen_parse_alias(const std::string &, EntryAlias *, Entry *, std::ostream &);
static void gen_dump(Entry *, std::ostream&);
static void gen_free(Entry *, std::ostream&);
static void gen_conf(Entry *, std::ostream&, bool verbose_output);
static void gen_default_if_none(Entry *, std::ostream&);

static void
lineAdd(Line ** L, const char *str)
{
    assert(str);

    while (*L)
        L = &(*L)->next;

    *L = new Line(str);
}

static void
checkDepend(const std::string &directive, const char *name, const Type *types, const Entry *entries)
{
    const Type *type;
    for (type = types; type; type = type->next) {
        const TypeDep *dep;
        if (type->name.compare(name) != 0)
            continue;
        for (dep = type->depend; dep; dep = dep->next) {
            const Entry *entry;
            for (entry = entries; entry; entry = entry->next) {
                if (entry->name.compare(dep->name) == 0)
                    break;
            }
            if (!entry) {
                std::cerr << "ERROR: '" << directive << "' (" << name << ") depends on '" << dep->name << "'\n";
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
    Entry *entries = NULL;
    Entry *curr = NULL;
    Type *types = NULL;
    enum State state;
    int rc = 0;
    char *ptr = NULL;
    char buff[MAX_LINE];
    std::ifstream fp;

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
        Type *t = new Type(type);
        while ((dep = strtok(NULL, WS)) != NULL) {
            TypeDep *d = new TypeDep(dep);
            d->next = t->depend;
            t->depend = d;
        }
        t->next = types;
        types = t;
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

        linenum++;

        if ((t = strchr(buff, '\n')))
            *t = '\0';

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

                curr = new Entry(name);

                while ((aliasname = strtok(NULL, WS)) != NULL) {
                    EntryAlias *alias = new EntryAlias(aliasname);
                    alias->next = curr->alias;
                    curr->alias = alias;
                }

                state = s1;
            } else if (!strcmp(buff, "EOF")) {
                state = sEXIT;
            } else if (!strcmp(buff, "COMMENT_START")) {
                curr = new Entry("comment");
                curr->loc = "none";
                state = sDOC;
            } else {
                std::cerr << "Error on line " << linenum << std::endl <<
                          "--> " << buff << std::endl;
                exit(1);
            }

            break;

        case s1:

            if ((strlen(buff) == 0) || (!strncmp(buff, "#", 1))) {
                /* ignore empty and comment lines */
                (void) 0;
            } else if (!strncmp(buff, "COMMENT:", 8)) {
                ptr = buff + 8;

                while (isspace((unsigned char)*ptr))
                    ptr++;

                curr->comment = ptr;
            } else if (!strncmp(buff, "DEFAULT:", 8)) {
                ptr = buff + 8;

                while (isspace((unsigned char)*ptr))
                    ptr++;

                curr->default_value = ptr;
            } else if (!strncmp(buff, "DEFAULT_IF_NONE:", 16)) {
                ptr = buff + 16;

                while (isspace((unsigned char)*ptr))
                    ptr++;

                lineAdd(&curr->default_if_none, ptr);
            } else if (!strncmp(buff, "LOC:", 4)) {
                if ((ptr = strtok(buff + 4, WS)) == NULL) {
                    std::cerr << "Error on line " << linenum << std::endl;
                    exit(1);
                }

                curr->loc = ptr;
            } else if (!strncmp(buff, "TYPE:", 5)) {
                if ((ptr = strtok(buff + 5, WS)) == NULL) {
                    std::cerr << "Error on line " << linenum << std::endl;
                    exit(1);
                }

                /* hack to support arrays, rather than pointers */
                if (0 == strcmp(ptr + strlen(ptr) - 2, "[]")) {
                    curr->array_flag = 1;
                    *(ptr + strlen(ptr) - 2) = '\0';
                }

                checkDepend(curr->name, ptr, types, entries);
                curr->type = ptr;
            } else if (!strncmp(buff, "IFDEF:", 6)) {
                if ((ptr = strtok(buff + 6, WS)) == NULL) {
                    std::cerr << "Error on line " << linenum << std::endl;
                    exit(1);
                }

                curr->ifdef = ptr;
            } else if (!strcmp(buff, "DOC_START")) {
                state = sDOC;
            } else if (!strcmp(buff, "DOC_NONE")) {
                /* add to list of entries */
                curr->next = entries;
                entries = curr;
                state = sSTART;
            } else {
                std::cerr << "Error on line " << linenum << std::endl;
                exit(1);
            }

            break;

        case sDOC:

            if (!strcmp(buff, "DOC_END") || !strcmp(buff, "COMMENT_END")) {
                Line *head = NULL;
                Line *line = curr->doc;
                /* reverse order of doc lines */

                while (line != NULL) {
                    Line *tmp;
                    tmp = line->next;
                    line->next = head;
                    head = line;
                    line = tmp;
                }

                curr->doc = head;
                /* add to list of entries */
                curr->next = entries;
                entries = curr;
                state = sSTART;
            } else if (!strcmp(buff, "NOCOMMENT_START")) {
                state = sNOCOMMENT;
            } else { // if (buff != NULL) {
                assert(buff != NULL);
                Line *line = new Line(buff);
                line->next = curr->doc;
                curr->doc = line;
            }

            break;

        case sNOCOMMENT:

            if (!strcmp(buff, "NOCOMMENT_END")) {
                Line *head = NULL;
                Line *line = curr->nocomment;
                /* reverse order of lines */

                while (line != NULL) {
                    Line *tmp;
                    tmp = line->next;
                    line->next = head;
                    head = line;
                    line = tmp;
                }

                curr->nocomment = head;
                state = sDOC;
            } else { // if (buff != NULL) {
                assert(buff != NULL);
                Line *line = new Line(buff);
                line->next = curr->nocomment;
                curr->nocomment = line;
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
    } else {
        /* reverse order of entries */
        Entry *head = NULL;

        while (entries != NULL) {
            Entry *tmp;

            tmp = entries->next;
            entries->next = head;
            head = entries;
            entries = tmp;
        }

        entries = head;
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
    "\n"
    "#include \"config.h\"\n"
    "\n";

    rc = gen_default(entries, fout);

    gen_default_if_none(entries, fout);

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
gen_default(Entry * head, std::ostream &fout)
{
    Entry *entry;
    int rc = 0;
    fout << "static void\n"
    "default_line(const char *s)\n"
    "{\n"
    "\tLOCAL_ARRAY(char, tmp_line, BUFSIZ);\n"
    "\txstrncpy(tmp_line, s, BUFSIZ);\n"
    "\txstrncpy(config_input_line, s, BUFSIZ);\n"
    "\tconfig_lineno++;\n"
    "\tparse_line(tmp_line);\n"
    "}\n";
    fout << "static void\n"
    "default_all(void)\n"
    "{\n"
    "\tcfg_filename = \"Default Configuration\";\n"
    "\tconfig_lineno = 0;\n";

    for (entry = head; entry != NULL; entry = entry->next) {
        assert(entry->name.size());
        assert(entry != entry->next);

        if (!entry->name.compare("comment"))
            continue;

        if (!entry->type.compare("obsolete"))
            continue;

        if (!entry->loc.size()) {
            std::cerr << "NO LOCATION FOR " << entry->name << std::endl;
            rc |= 1;
            continue;
        }

        if (!entry->default_value.size() && entry->default_if_none == NULL) {
            std::cerr << "NO DEFAULT FOR " << entry->name << std::endl;
            rc |= 1;
            continue;
        }

        if (!entry->default_value.size() || entry->default_value.compare("none") == 0) {
            fout << "\t/* No default for " << entry->name << " */\n";
        } else {
            if (entry->ifdef.size())
                fout << "#if " << entry->ifdef << std::endl;

            fout << "\tdefault_line(\"" << entry->name << " " <<
            entry->default_value << "\");\n";

            if (entry->ifdef.size())
                fout << "#endif\n";
        }
    }

    fout << "\tcfg_filename = NULL;\n"
    "}\n\n";
    return rc;
}

static void
gen_default_if_none(Entry * head, std::ostream &fout)
{
    Entry *entry;
    Line *line;
    fout << "static void\n"
    "defaults_if_none(void)\n"
    "{\n";

    for (entry = head; entry != NULL; entry = entry->next) {
        assert(entry->name.size());

        if (!entry->loc.size())
            continue;

        if (entry->default_if_none == NULL)
            continue;

        if (entry->ifdef.size())
            fout << "#if " << entry->ifdef << std::endl;

        if (entry->default_if_none) {
            fout << "\tif (check_null_" << entry->type << "(" <<
            entry->loc << ")) {\n";

            for (line = entry->default_if_none; line; line = line->next)
                fout << "\t\tdefault_line(\"" << entry->name << " " <<
                line->data <<"\");\n";

            fout << "\t}\n";
        }

        if (entry->ifdef.size())
            fout << "#endif\n";
    }

    fout << "}\n\n";
}

void
gen_parse_alias(const std::string &name, EntryAlias *alias, Entry *entry, std::ostream &fout)
{
    fout << "\tif (!strcmp(token, \"" << name << "\")) {\n";

    if (entry->type.compare("obsolete") == 0) {
        fout << "\t\tdebugs(0, DBG_CRITICAL, \"ERROR: Directive '" << name << "' is obsolete.\");\n";
        for (Line *line = entry->doc; line != NULL; line = line->next) {
            // offset line to strip initial whitespace tab byte
            fout << "\t\tdebugs(0, opt_parse_cfg_only?0:1, \"" << name << " : " << &line->data[1] << "\");\n";
        }
        fout << "\t\tparse_obsolete(token);\n";
    } else if (!entry->loc.size() || entry->loc.compare("none") == 0) {
        fout << "\t\tparse_" << entry->type << "();\n";
    } else {
        fout << "\t\tparse_" << entry->type << "(&" << entry->loc <<
        (entry->array_flag ? "[0]" : "") << ");\n";
    }

    fout << "\t\treturn 1;\n";
    fout << "\t};\n";
}

void
gen_parse_entry(Entry *entry, std::ostream &fout)
{
    if (entry->name.compare("comment") == 0)
        return;

    if (entry->ifdef.size())
        fout << "#if " << entry->ifdef << std::endl;

    std::string &name = entry->name;

    EntryAlias *alias = entry->alias;

    bool more;

    do {
        gen_parse_alias(name, alias, entry, fout);
        more = false;

        if (alias) {
            name = alias->name;
            alias = alias->next;
            more = true;
        }
    } while (more);

    if (entry->ifdef.size())
        fout << "#endif\n";
}

static void
gen_parse(Entry * head, std::ostream &fout)
{
    fout <<
    "static int\n"
    "parse_line(char *buff)\n"
    "{\n"
    "\tchar\t*token;\n"
    "\tif ((token = strtok(buff, w_space)) == NULL) \n"
    "\t\treturn 1;\t/* ignore empty lines */\n";

    for (Entry *entry = head; entry != NULL; entry = entry->next)
        gen_parse_entry (entry, fout);

    fout << "\treturn 0; /* failure */\n"
    "}\n\n";

}

static void
gen_dump(Entry * head, std::ostream &fout)
{
    Entry *entry;
    fout <<
    "static void\n"
    "dump_config(StoreEntry *entry)\n"
    "{\n"
    "    debugs(5, 4, HERE);\n";

    for (entry = head; entry != NULL; entry = entry->next) {

        if (!entry->loc.size() || entry->loc.compare("none") == 0)
            continue;

        if (entry->name.compare("comment") == 0)
            continue;

        if (entry->ifdef.size())
            fout << "#if " << entry->ifdef << std::endl;

        fout << "\tdump_" << entry->type << "(entry, \"" << entry->name <<
        "\", " << entry->loc << ");\n";

        if (entry->ifdef.size())
            fout << "#endif\n";
    }

    fout << "}\n\n";
}

static void
gen_free(Entry * head, std::ostream &fout)
{
    Entry *entry;
    fout <<
    "static void\n"
    "free_all(void)\n"
    "{\n"
    "    debugs(5, 4, HERE);\n";

    for (entry = head; entry != NULL; entry = entry->next) {
        if (!entry->loc.size() || entry->loc.compare("none") == 0)
            continue;

        if (entry->name.compare("comment") == 0)
            continue;

        if (entry->ifdef.size())
            fout << "#if " << entry->ifdef << std::endl;

        fout << "\tfree_" << entry->type << "(&" << entry->loc <<
        (entry->array_flag ? "[0]" : "") << ");\n";

        if (entry->ifdef.size())
            fout << "#endif\n";
    }

    fout << "}\n\n";
}

static bool
defined(const std::string &name)
{
    if (!name.size())
        return true;

    for (int i = 0; defines[i].name; i++) {
        if (name.compare(defines[i].name) == 0)
            return defines[i].defined;
    }

    return false;
}

static const char *
available_if(const std::string &name)
{
    assert(name.size());

    for (int i = 0; defines[i].name; i++) {
        if (name.compare(defines[i].name) != 0)
            return defines[i].enable;
    }

    return name.c_str();
}

static void
gen_conf(Entry * head, std::ostream &fout, bool verbose_output)
{
    Entry *entry;
    char buf[8192];
    Line *def = NULL;

    for (entry = head; entry != NULL; entry = entry->next) {
        Line *line;
        int enabled = 1;

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

        if (!defined(entry->ifdef)) {
            if (verbose_output) {

                fout << "# Note: This option is only available if "
                "Squid is rebuilt with the\n" <<
                "#       " << available_if(entry->ifdef) << "\n#\n";
            }
            enabled = 0;
        }

        if (verbose_output) {
            for (line = entry->doc; line != NULL; line = line->next) {
                fout << "#" << line->data << std::endl;
            }
        }

        if (entry->default_value.size() && entry->default_value.compare("none") != 0) {
            snprintf(buf, sizeof(buf), "%s %s", entry->name.c_str(), entry->default_value.c_str());
            lineAdd(&def, buf);
        }

        if (entry->default_if_none) {
            for (line = entry->default_if_none; line != NULL; line = line->next) {
                snprintf(buf, sizeof(buf), "%s %s", entry->name.c_str(), line->data.c_str());
                lineAdd(&def, buf);
            }
        }

        if (!def && entry->doc && !entry->nocomment &&
                entry->name.compare("comment") != 0)
            lineAdd(&def, "none");

        if (verbose_output && def && (entry->doc || entry->nocomment)) {
            fout << "#Default:\n";
            while (def != NULL) {
                line = def;
                def = line->next;
                line->next = NULL; // unlink to simplify delete
                fout << "# " << line->data << std::endl;
                delete line;
            }
        }

        if (verbose_output && entry->nocomment)
            fout << "#" << std::endl;

        if (enabled || verbose_output) {
            for (line = entry->nocomment; line != NULL; line = line->next) {
                if (!line->data.size())
                    continue;
                if (!enabled && line->data[0] != '#')
                    fout << "#" << line->data << std::endl;
                else
                    fout << line->data << std::endl;
            }
        }

        if (verbose_output && entry->doc != NULL) {
            fout << std::endl;
        }
    }
}
