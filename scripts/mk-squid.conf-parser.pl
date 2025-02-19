#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Long qw(:config auto_version auto_help);
use Pod::Usage;

=pod

=head1 NAME

 mk-squid.conf-parser.pl - Generate squid.conf.default and cf_parser.cci

=head1 SYNOPSIS

 mk-squid.conf-parser.pl [--config|--documentation|--parser] cf.data cf.data.depend

=head1 DESCRIPTION

This program parses the input file and generate code and
documentation used to configure the variables in squid.

=head1 OPTIONS

=over 12

=item B<--config>

Produce the default squid.conf contents.

=item B<--documentation>

Produce the full Squid configuration documentation texts.

=item B<--parser>

Produce C++ code definitions for:
 - default_all() which initializes variables with the default values,
 - parse_line() that parses line from squid.conf,
 - dump_config() that dumps the current the values of the variables

=item B<cf.data>

File containing definitions of all squid.conf directives,
including their documentation, default values, and syntax
to be part of squid.conf.default.

=item B<cf.data.depend>

File containing the type dependency information for
squid.conf directive types used in B<cf.data>.

=back

=head1 AUTHOR

This software is written by Amos Jeffries <amosjeffries@squid-cache.org>

=head1 COPYRIGHT

 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.

=head1 QUESTIONS

Questions on the usage of this program can be sent to the
I<Squid Developers mailing list <squid-dev@lists.squid-cache.org>>

=head1 REPORTING BUGS

Bug reports need to be made in English.
See https://wiki.squid-cache.org/SquidFaq/BugReporting for details of what you need to include with your bug report.

Report bugs or bug fixes using https://bugs.squid-cache.org/

Report serious security bugs to I<Squid Bugs <squid-bugs@lists.squid-cache.org>>

Report ideas for new improvements to the I<Squid Developers mailing list <squid-dev@lists.squid-cache.org>>

=head1 SEE ALSO

squid (8), GPL (7),

The Squid FAQ wiki https://wiki.squid-cache.org/SquidFaq

The Squid Configuration Manual http://www.squid-cache.org/Doc/config/

=cut

use YAML::Tiny;

sub verify_dependencies
{
  my ($sections, $depfile) = @_;

 # TODO: load dependency array from $depfile
 # TODO: scan across $sections checking directives are ordered correctly
}

# Strips '.' prefix from output lines.
#
# This '.' prefix is used to prevent YAML syntax from
# ignoring #comment and empty lines that are supposed
# to be passed through to display in squid.conf.default
# and squid.conf.documented.
#
sub cfg_filter
{
  my ($text) = @_;
  return if not defined $text;
  foreach my $str ( split( "\n" , $text ) ) {
    $str =~ s/^\.//;
    print "$str\n";
  }
}

# Strips '.' prefix from output lines, and
# Adds "#\t" prefix to all non-empty lines.
#
# The '.' prefix is used to prevent YAML syntax from
# ignoring #comment and empty lines that are supposed
# to be passed through to display in squid.conf.documented
#
# The "#\t" prefix is historic behaviour from cf_gen.
# Preserved for now to ensure near-identical output.
#
sub doc_filter
{
  my ($text) = @_;
  return if not defined $text;
  foreach my $str ( split( "\n" , $text ) ) {
    $str =~ s/^\.//;
    print "#";
    print "\t$str" unless $str =~ m/^$/;
    print "\n";
  }
}

sub document_directive
{
  my ($directives) = @_;
  return if not defined $directives;
  for (my $item = 0 ; defined $directives->[$item] ; $item++) {
    my $which = $directives->[$item];

    print "\n#  TAG: $which->{NAME}";
    print "\t$which->{COMMENT}" if defined $which->{COMMENT};
    print "\n";

    print "#\tUsage:   $which->{NAME} $which->{syntax}\n" if defined $which->{syntax};

    print "# Note: This option is only available if Squid is rebuilt with\n" .
          "#       $which->{IFDEF}\n" .
          "#\n" if defined $which->{IFDEF};

    doc_filter( $which->{description} );

    my $cfg = $which->{default_config};
    if ( defined $cfg ) {
      print "#Default:\n";
      if ( defined $cfg->{description} ) { doc_filter( $cfg->{description} ); }
      elsif ( defined $cfg->{value} ) { print "# $which->{NAME} $cfg->{value}\n"; }
      elsif ( defined $cfg->{DEFAULT_IF_NONE} ) { print "# $which->{NAME} $cfg->{DEFAULT_IF_NONE}\n"; }
      else { print "# none\n"; }
    }

    cfg_filter( $which->{CONFIG_START} );
  }
}

# WAS: cf_gen: Generate squid.conf.documented
sub create_documentation
{
  my ($sections) = @_;
  for (my $count = 0 ; defined $sections->[$count] ; $count++) {
    doc_filter( $sections->[$count]->{title} );
    print "# -----------------------------------------------------------------------------\n" if defined $sections->[$count]->{directives};
    doc_filter( $sections->[$count]->{description} );
    document_directive( $sections->[$count]->{obsolete} );
    document_directive( $sections->[$count]->{directives} );
    print "\n";
  }
}

# WAS: cf_gen: Generate squid.conf.default
sub create_default_config
{
  my ($sections) = @_;
  for (my $count = 0 ; defined $sections->[$count] ; $count++) {
    next if not defined $sections->[$count]->{directives};
    my ($directives) = $sections->[$count]->{directives};
    for (my $item = 0 ; defined $directives->[$item] ; $item++) {
      next if not defined $directives->[$item]->{CONFIG_START};
      cfg_filter( $directives->[$item]->{CONFIG_START} );
      print "\n";
    }
  }
}

sub cf_parser_default
{
  my ($sections) = @_;

  print "static void\n" .
        "default_line(const char *s)\n" .
        "{\n" .
        "    char *tmp_line = xstrdup(s);\n" .
        "    int len = strlen(tmp_line);\n" .
        "    ProcessMacros(tmp_line, len);\n" .
        "    xstrncpy(config_input_line, tmp_line, sizeof(config_input_line));\n" .
        "    config_lineno++;\n" .
        "    parse_line(tmp_line);\n" .
        "    xfree(tmp_line);\n" .
        "}\n" .
        "\n";

  print "static void\n" .
        "default_all(void)\n" .
        "{\n" .
         "    cfg_filename = \"Default Configuration\";\n" .
         "    config_lineno = 0;\n";

  for (my $count = 0 ; defined $sections->[$count] ; $count++) {
    next unless defined $sections->[$count]->{directives};
    my ($directives) = $sections->[$count]->{directives};

    for (my $item = 0 ; defined $directives->[$item] ; $item++) {
      my $which = $directives->[$item];
      my $cfg = $which->{default_config};
      if ( defined $cfg ) {
        if ( defined $cfg->{value} ) {
          print "#if $which->{IFDEF}\n" if defined $which->{IFDEF};
          if ( ref $cfg->{value} eq "ARRAY") {
            for (my $n = 0 ; defined $cfg->{value}->[$n] ; $n++) {
              print "    default_line(\"$which->{NAME} $cfg->{value}->[$n]\");\n";
            }
          } else {
            print "    default_line(\"$which->{NAME} $cfg->{value}\");\n";
          }
          print "#endif\n" if defined $which->{IFDEF};
        } else { #( not defined $cfg->{DEFAULT_IF_NONE} ) {
          print "    // No default for $which->{NAME}\n";
        }
      } else {
        print "    // No default for $which->{NAME}\n";
      }
    }
  }

  print "    cfg_filename = nullptr;\n" .
        "}\n" .
        "\n" .
        "static void\n" .
        "defaults_if_none(void)\n" .
        "{\n" .
         "    cfg_filename = \"Default Configuration (if absent)\";\n" .
         "    config_lineno = 0;\n";

  for (my $count = 0 ; defined $sections->[$count] ; $count++) {
    next unless defined $sections->[$count]->{directives};
    my ($directives) = $sections->[$count]->{directives};

    for (my $item = 0 ; defined $directives->[$item] ; $item++) {
      my $which = $directives->[$item];
      next unless defined $which->{LOC};
      my $cfg = $which->{default_config};
      next unless defined $cfg;
      next unless defined $cfg->{DEFAULT_IF_NONE};

      print "#if $which->{IFDEF}\n" if defined $which->{IFDEF};
      print "    if (check_null_" . $which->{TYPE} ."($which->{LOC})) {\n";
      if ( ref $cfg->{DEFAULT_IF_NONE} eq "ARRAY") {
        for (my $n = 0 ; defined $cfg->{DEFAULT_IF_NONE}->[$n] ; $n++) {
          print "        default_line(\"$which->{NAME} $cfg->{DEFAULT_IF_NONE}->[$n]\");\n";
        }
      } else {
        print "        default_line(\"$which->{NAME} $cfg->{DEFAULT_IF_NONE}\");\n";
      }
      print "    }\n";
      print "#endif\n" if defined $which->{IFDEF};
    }
  }

  print "    cfg_filename = nullptr;\n" .
        "}\n" .
        "\n" .
        "static void\n" .
        "defaults_postscriptum(void)\n" .
        "{\n" .
         "    cfg_filename = \"Default Configuration (postscriptum)\";\n" .
         "    config_lineno = 0;\n";

  for (my $count = 0 ; defined $sections->[$count] ; $count++) {
    next unless defined $sections->[$count]->{directives};
    my ($directives) = $sections->[$count]->{directives};

    for (my $item = 0 ; defined $directives->[$item] ; $item++) {
      my $which = $directives->[$item];
      next unless defined $which->{LOC};
      next unless defined $which->{default_config};
      my $cfg = $which->{default_config};
      next unless defined $cfg->{POSTSCRIPTUM};

      print "#if $which->{IFDEF}\n" if defined $which->{IFDEF};
      if ( ref $cfg->{POSTSCRIPTUM} eq "ARRAY") {
        for (my $n = 0 ; defined $cfg->{POSTSCRIPTUM}->[$n] ; $n++) {
          print "    default_line(\"$which->{NAME} $cfg->{POSTSCRIPTUM}->[$n]\");\n";
        }
      } else {
        print "    default_line(\"$which->{NAME} $cfg->{POSTSCRIPTUM}\");\n";
      }
      print "#endif\n" if defined $which->{IFDEF};
    }
  }

  print "    cfg_filename = nullptr;\n" .
        "}\n\n";
}

sub cf_parser_parse
{
  my ($sections) = @_;

  print "static int\n" .
        "parse_line(char *buff)\n" .
        "{\n" .
        "    char *token;\n" .
        "    if ((token = strtok(buff, \" \\t\")) == NULL)\n" .
        "        return 1; /* ignore empty lines */\n" .
        "    ConfigParser::SetCfgLine(strtok(nullptr, \"\"));\n";

  for (my $count = 0 ; defined $sections->[$count] ; $count++) {
    next unless defined $sections->[$count]->{obsolete};
    my ($directives) = $sections->[$count]->{obsolete};

    for (my $item = 0 ; defined $directives->[$item] ; $item++) {
      my $which = $directives->[$item];
      print "    if (!strcmp(token, \"$which->{NAME}\")) {\n" .
            "        cfg_directive = \"$which->{NAME}\";\n" .
            "        debugs(0, DBG_CRITICAL, \"ERROR: Directive '$which->{NAME}' is obsolete.\");\n";
      if ( defined $which->{description} ) {
        foreach my $message ( split( "\n" , $which->{description} ) ) {
          $message =~ s/^\.//;
          print "        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), \"$which->{NAME} : $message\");\n";
        }
      }
      print "        parse_obsolete(token);\n" .
            "        cfg_directive = nullptr;\n" .
            "        return 1;\n" .
            "    }\n";
    }
  }

  for (my $count = 0 ; defined $sections->[$count] ; $count++) {
    next unless defined $sections->[$count]->{directives};
    my ($directives) = $sections->[$count]->{directives};

    for (my $item = 0 ; defined $directives->[$item] ; $item++) {
      my $which = $directives->[$item];
      print "    if (!strcmp(token, \"$which->{NAME}\")) {\n";
      print "#if $which->{IFDEF}\n" if defined $which->{IFDEF};
      print "        cfg_directive = \"$which->{NAME}\";\n";
      if ( not defined $which->{LOC} ) {
          print "        parse_" . $which->{TYPE} ."();\n";
      } elsif ( $which->{TYPE} =~ m/::/ ) {
          print "        ParseDirective<" . $which->{TYPE} . ">(" . $which->{LOC} . ", LegacyParser);\n";
      } else {
          print "        parse_" . $which->{TYPE} . "(&" . $which->{LOC} . ");\n";
      }
      print "        cfg_directive = nullptr;\n";
      if ( defined $which->{IFDEF} ) {
        print "#else\n" .
              "        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), \"ERROR: '" . $which->{NAME} ."' requires " . $which->{IFDEF} . "\");\n" .
              "#endif\n";
      }
      print "        return 1;\n" .
            "    };\n";
    }
  }

  print "    return 0;  /* failure */\n" .
        "}\n\n";
}

sub cf_parser_dump
{
  my ($sections) = @_;

  print "static void\n" .
        "dump_config(StoreEntry *entry)\n" .
        "{\n" .
        "    debugs(5, 4, MYNAME);\n";

  for (my $count = 0 ; defined $sections->[$count] ; $count++) {
    next unless defined $sections->[$count]->{directives};
    my ($directives) = $sections->[$count]->{directives};

    for (my $item = 0 ; defined $directives->[$item] ; $item++) {
      my $which = $directives->[$item];
      next unless defined $which->{LOC};
      print "#if $which->{IFDEF}\n" if defined $which->{IFDEF};
      if ( $which->{TYPE} =~ m/::/ ) {
          print "    DumpDirective<" . $which->{TYPE} . ">(" . $which->{LOC} . ", entry, \"" . $which->{NAME} . "\");\n";
      } else {
          print "    dump_" . $which->{TYPE} . "(entry, \"" . $which->{NAME} . "\", " . $which->{LOC} . ");\n";
      }
      print "#endif\n" if defined $which->{IFDEF};
    }
  }

  print "}\n\n";
}

sub cf_parser_free
{
  my ($sections) = @_;

  print "static void\n" .
        "free_all(void)\n" .
        "{\n" .
        "    debugs(5, 4, MYNAME);\n";

  for (my $count = 0 ; defined $sections->[$count] ; $count++) {
    next unless defined $sections->[$count]->{directives};
    my ($directives) = $sections->[$count]->{directives};

    for (my $item = 0 ; defined $directives->[$item] ; $item++) {
      my $which = $directives->[$item];
      next unless defined $which->{LOC};
      print "#if $which->{IFDEF}\n" if defined $which->{IFDEF};
      if ( $which->{TYPE} =~ m/::/ ) {
          print "    FreeDirective<" . $which->{TYPE} . ">(" . $which->{LOC} . ");\n";
      } else {
          print "    free_" . $which->{TYPE} . "(&" . $which->{LOC} . ");\n";
      }
      print "#endif\n" if defined $which->{IFDEF};
    }
  }

  print "}\n\n";
}

# WAS: cf_gen: Generate cf_parser.cci
sub create_parser
{
  my ($sections) = @_;

  print "/*\n" .
        " * Generated automatically from squid.conf.yaml.in by mk-squid.conf-parser.pl\n" .
        " * \n" .
        " * Abstract: This file contains routines used to configure the\n" .
        " *           variables in the squid server.\n" .
        " */\n" .
        "\n";

  cf_parser_default($sections);
  cf_parser_parse($sections);
  cf_parser_dump($sections);
  cf_parser_free($sections);
}

my $outcfg = 0;
my $outdocs = 0;
my $outparser = 0;
Getopt::Long::Configure("require_order");
GetOptions(
        'config', \$outcfg,
        'documentation', \$outdocs,
        'parser', \$outparser
        ) or die("ERROR: Unknown Output Type.\n");

my $indata;
my $independs;
if (@ARGV <= 1) {
  die("ERROR: Missing required input file parameter(s).\n");
} elsif (@ARGV == 2) {
  my $yaml = YAML::Tiny->read($ARGV[0]);
  verify_dependencies($yaml, $ARGV[1]);
  create_default_config($yaml->[0]) if $outcfg;
  create_documentation($yaml->[0]) if $outdocs;
  create_parser($yaml->[0]) if $outparser;
} else {
    die("ERROR: Too many filename parameters.\n");
}
