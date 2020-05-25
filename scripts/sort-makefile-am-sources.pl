#!/usr/bin/perl

while (<>) {
    # print "read1: $_";
    if (! /^(nodist_)?tests_test.*_SOURCES/) {
        print;
        next;
    }
    print;
    # accumulate files and prep for sorting
    my %files;
    while (<>) {
        # print "read2: $_";
        chop;
        /\s*(tests\/stub_|tests\/test)?(\S+)(\s+\\\s*)?$/ || die "no parse";
    #    print "parts: $1 / $2 / _$3_\n";
        $files{"$2.$1"}="$1$2";
        # print "### $2$1 -> $1$2\n";
        if (! /\\$/ ) {  # last line in the list
            &print_files(\%files);
            last;
        }
    }
}

# arg is hash ref, print values in order of key
sub print_files
{
    my %files=%{$_[0]};
    my @q=();
    foreach my $k (sort {lc $a cmp lc $b} keys %files) {
        # print "k: $k\n";
        push @q, "\t".$files{$k};
    }
    # print "Dump: \n";
    print join(" \\\n", @q)."\n";
}