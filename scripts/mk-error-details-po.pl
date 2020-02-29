#!/usr/bin/perl -w
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# Author: Tsantilas Christos
# (C) 2011 The Measurement Factory
# 
# Usage: 
#     mk-error-details-po.pl error-details.txt
#
# This script read the error-details.txt error details template, and prints to the
# std output the contents of a .PO file template for translation.
# The error-details.txt file consist of records like the following:
#
#  name: X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
#  detail: "SSL Certficate error: certificate issuer (CA) not known: %ssl_ca_name"
#  descr: "Unable to get issuer certificate"
#
# The records separated with an empty line.
# Comments starting with '#' supported.
#

use warnings;
use strict;

my $File;
my $mode;

$File = shift @ARGV or 
    die "Usage: \n ".$0." error-detail-file\n\n";

open(IN, "<$File") or
    die "Can not open file '$File': $!";

my @PO_RECORDS = ();
my $lineNumber=0;
while(my $line = <IN>) {
    $lineNumber++;

    if ($line =~ /^\#.*/ ) {
        next;
    }
    elsif ($line =~ /^\s*$/ ) {
        next;
    }
    my($rec) = "";
    my($lineOffset) = 0;
    do {
        $rec = $rec.$line;
        $line = <IN>;
        $lineOffset++;
    } while($line && $line !~ /^\s*$/);

    processRecord(\@PO_RECORDS, $rec, $lineNumber);
    $lineNumber= $lineNumber + $lineOffset;
}

foreach my $poRec (@PO_RECORDS) {
    print $poRec->{"comment"};
    print "msgid ".$poRec->{"msgid"}."\n";
    # Being a template msgstr is always empty awaiting translated texts.
    print "msgstr \"\"\n\n";
}

exit(0);


sub processRecord
{
    my($RECS, $rec, $lnumber) = @_;
    my(@lines) = split /\n/, $rec;
    my($currentField) = "";
    my(%currentRec);
    my $offset = 0;
    foreach my $l (@lines) {
        if ($l =~ /^name:(.*)/) {
            $currentRec{"name"} = trim($1);
            $currentField = "name";
        }
        elsif ( $l =~ /^detail:(.*)/ ) {
            $currentRec{"detail"} = toCstr(trim_quoted($1));
            $currentField = "detail";
        }
        elsif ($l =~ /^descr:(.*)/) {
            $currentRec{"descr"} = toCstr(trim_quoted($1));
            $currentField = "descr";
        }
        elsif($l = ~ /^(\s+.*)/  && defined($currentRec{$currentField})) {
            my($fmtl) = toCstr($1);
            $currentRec{$currentField}= $currentRec{$currentField}."\\n".$fmtl;
        }
    }

    my (%poRecDetail, %poRecDescr);
    
    $poRecDetail{"comment"} = "#: $File+".$currentRec{"name"}.".detail:$lnumber\n";
    $poRecDetail{"msgid"} = $currentRec{"detail"};
    merge(\@$RECS, \%poRecDetail);

    $poRecDescr{"comment"} = "#: $File+".$currentRec{"name"}.".descr:$lnumber\n";
    $poRecDescr{"msgid"} = $currentRec{"descr"};
    merge(\@$RECS, \%poRecDescr);
}

sub merge {
    my ($RECS, $poRec) = @_;
    foreach my $item (@$RECS) {
        if ($poRec->{"msgid"} eq $item->{"msgid"}) {
            $item->{"comment"} = $item->{"comment"}.$poRec->{"comment"};
            return;
        }
    }
    push @$RECS, $poRec;
    return;
}

sub trim
{
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    return $string;
}

sub trim_quoted
{
    my $string = shift;
    $string =~ s/^\s+"/"/;
    $string =~ s/"\s+$/"/;
    return $string;
}

sub toCstr
{
    my $string = shift;
    $string =~ s/\t/\\t/g;
    return $string;
}
