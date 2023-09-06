#!/usr/bin/perl
#
## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

use strict;
use warnings;
use IPC::Open2;
use Getopt::Long;

my $ASTYLE_BIN = "astyle";
my $ASTYLE_ARGS ="--mode=c -s4 --convert-tabs --keep-one-line-blocks --lineend=linux";
#$ASTYLE_ARGS="--mode=c -s4 -O --break-blocks -l";

Getopt::Long::Configure("require_order");
GetOptions(
	'help', sub { usage($0) },
	'with-astyle=s', \$ASTYLE_BIN
	) or die(usage($0));

$ASTYLE_BIN=$ASTYLE_BIN." ".$ASTYLE_ARGS;

if (@ARGV <= 0) {
    usage($0);
    die("ERROR: Missing required filename parameter.\n");
} elsif (@ARGV == 1) {
    &main(shift @ARGV);
    exit 0;
} else {
    usage($0);
    die("ERROR: Too many filename parameters.\n");
}

sub main
{
    my ($out) = @_;

    local (*FROM_ASTYLE, *TO_ASTYLE);
    my $pid_style=open2(\*FROM_ASTYLE, \*TO_ASTYLE, $ASTYLE_BIN);
    die() unless $pid_style; # paranoid: open2() does not return on failures

    my $pid;
    if($pid=fork()){
        #do parent staf
        close(FROM_ASTYLE);

        my $in = $out;
        if (!open(IN, "<$in")) {
            die("ERROR: Cannot open input file: $in\n");
        }
        my $line = '';
        while (<IN>) {
            $line=$line.$_;
            if (input_filter(\$line)==0) {
                next;
            }
            print TO_ASTYLE $line;
            $line = '';
        }
        if ($line) {
            print TO_ASTYLE $line;
        }
        close(TO_ASTYLE);
        waitpid($pid,0);
        waitpid($pid_style, 0);
    }
    else{
        # child staf
        close(TO_ASTYLE);

        my $formattedCode = '';
        my($line)='';
        while(<FROM_ASTYLE>){
            $line = $line.$_;
            if(output_filter(\$line)==0){
                next;
            }
            $formattedCode .= $line;
            $line = '';
        }
        if($line){
            $formattedCode .= $line;
        }

        my $originalCode = &slurpFile($out);

        if (!length $formattedCode) {
            warn("ERROR: Running astyle produced no output while formatting $out\n".
                 "    astyle command: $ASTYLE_BIN\n");
            print $originalCode;
            return;
        }

        my $originalEssence = &sourceCodeEssense($originalCode);
        my $formattedEssence = &sourceCodeEssense($formattedCode);
        if ($originalEssence eq $formattedEssence) {
            print $formattedCode;
            return;
        }

        warn("ERROR: Unexpected source code changes while formatting $out\n");
        eval { &createFile($formattedCode, "$out.astylebad") };
        warn("WARNING: Cannot keep a copy of malformed $out: $@\n") if $@;
        print $originalCode;
    }
}

# strips all space characters from the given input
sub sourceCodeEssense
{
    my ($sourceCode) = @_;
    $sourceCode =~ s/\s+//g;
    return $sourceCode;
}

# reads and returns the entire file contents
sub slurpFile {
    my ($fname) = @_;
    local $/ = undef;
    open(my $input, "<", $fname) or die("Cannot open $fname for reading: $!\n");
    return <$input>;
}

# (re)creates a file with the given name, filling it with the given content
sub createFile {
    my ($content, $fname) = @_;
    open(my $output, ">", $fname) or die("Cannot create $fname: $!\n");
    print($output $content) or die("Cannot write to $fname: $!\n");
    close($output) or die("Cannot finalize $fname: $!\n");
}

sub input_filter{
    my($line)=@_;
    #if we have integer declaration, get it all before processing it..

    if($$line =~/\s+int\s+.*/s || $$line=~ /\s+unsigned\s+.*/s ||
        $$line =~/^int\s+.*/s || $$line=~ /^unsigned\s+.*/s
        ) {
        if( $$line =~ /(\(|,|\)|\#|typedef)/s ){
            # excluding int/unsigned appeared inside function prototypes,
            # typedefs etc....
            return 1;
        }

        if(index($$line,";") == -1){
            # print "Getting one more for \"".$$line."\"\n";
            return 0;
        }

        if($$line =~ /(.*)\s*int\s+([^:]*):\s*(\w+)\s*\;(.*)/s){
            # print ">>>>> ".$$line."    ($1)\n";
            my ($prx,$name,$val,$extra)=($1,$2,$3,$4);
            $prx =~ s/\s*$//g;
            $$line= $prx." int ".$name."__FORASTYLE__".$val.";".$extra;
            # print "----->".$$line."\n";
        }
        elsif($$line =~ /\s*unsigned\s+([^:]*):\s*(\w+)\s*\;(.*)/s){
            # print ">>>>> ".$$line."    ($1)\n";
            my ($name,$val,$extra)=($1,$2,$3);
            $$line= "unsigned ".$name."__FORASTYLE__".$val.";".$extra;
            # print "----->".$$line."\n";
        }
        return 1;
    }

    if($$line =~ /\#endif/ ||
        $$line =~ /\#else/ ||
        $$line =~ /\#if/
        ) {
        $$line =$$line."//__ASTYLECOMMENT__\n";
        return 1;
    }

    return 1;
}

my $last_line_was_empty=0;
#param: a reference to input line
#retval 1: print line
#retval 0: don't print line
sub output_filter{
    my($line)=@_;

    # collapse multiple empty lines onto the first one
    if($$line =~ /^\s*$/){
        if ($last_line_was_empty==1) {
            $$line="";
            return 0;
        } else {
            $last_line_was_empty=1;
            return 1;
        }
    } else {
        $last_line_was_empty=0;
    }

    if($$line =~ s/\s*\/\/__ASTYLECOMMENT__//) {
        chomp($$line);
    }

    # "The "unsigned int:1; case ....."
    $$line =~ s/__FORASTYLE__/:/;

    return 1;
}

sub usage{
    my($name)=@_;
    print "Usage:\n";
    print "   $name [options] <filename-to-format>\n";
    print "\n";
    print "Options:\n";
    print "    --help              This usage text.\n";
    print "    --with-astyle <PATH>  astyle executable to use.\n";
}
