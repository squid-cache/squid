#!/usr/bin/perl
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##
#
# Author: Tsantilas Christos
# email:  christos@chtsanti.net
#
# Distributed under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
# See COPYING or http://www.gnu.org/licenses/gpl.html for details.
#

use strict;
use IPC::Open2;

#
# NP: The Squid code requires astyle version 2.04 (exactly for now)
#
my $ASTYLE_BIN="/usr/local/bin/astyle";
if (! -x $ASTYLE_BIN) {
  $ASTYLE_BIN="/usr/bin/astyle";
}
if (! -x $ASTYLE_BIN) {
  $ASTYLE_BIN="/usr/local/src/astyle-2.04/bin/astyle";
}

my $ASTYLE_ARGS ="--mode=c -s4 --convert-tabs --keep-one-line-blocks --lineend=linux";
#$ASTYLE_ARGS="--mode=c -s4 -O --break-blocks -l";


if(! -e $ASTYLE_BIN || ! -x $ASTYLE_BIN){
    print "\nFile $ASTYLE_BIN not found\n";
    print "Please fix the ASTYLE_BIN variable in this script!\n\n";
    exit -1;
}
$ASTYLE_BIN=$ASTYLE_BIN." ".$ASTYLE_ARGS;

my $INDENT = "";

my $out = shift @ARGV;
#read options, currently no options available
while($out eq "" ||  $out =~ /^-\w+$/){
   if($out eq "-h") {
        usage($0);
        exit 0;
   }
   else {
       usage($0);
       exit -1;
   }
}


while($out){

    if( $out !~ /\.cc$|\.cci$|\.h$|\.c$/) {
         print "Unknown suffix for file $out, ignoring....\n";
         $out = shift @ARGV;
         next;
    }

    my $in= "$out.astylebak";
    my($new_in) = $in;
    my($i) = 0;
    while(-e $new_in) {
	$new_in=$in.".".$i;
	$i++;
    }
    $in=$new_in;
    rename($out, $in);
    
    local (*FROM_ASTYLE, *TO_ASTYLE);
    my $pid_style=open2(\*FROM_ASTYLE, \*TO_ASTYLE, $ASTYLE_BIN);
    
    if(!$pid_style){
	print "An error while open2\n";
	exit -1;
    }

    my $pid;
    if($pid=fork()){
	#do parrent staf
	close(FROM_ASTYLE);
	
	if(!open(IN, "<$in")){
	    print "Can not open input file: $in\n";
	    exit -1;
	}
	my($line) = '';
	while(<IN>){
	    $line=$line.$_;
	    if(input_filter(\$line)==0){
		next;
	    }
	    print TO_ASTYLE $line;
	    $line = '';
	}
	if($line){
	    print TO_ASTYLE $line;
	}
	close(TO_ASTYLE);
	waitpid($pid,0);
    }
    else{
	# child staf
	close(TO_ASTYLE);

	if(!open(OUT,">$out")){
	    print "Can't open output file: $out\n";
	    exit -1;
	}
	my($line)='';
	while(<FROM_ASTYLE>){
	    $line = $line.$_;
	    if(output_filter(\$line)==0){
		next;
	    }
	    print OUT $line;
	    $line = '';
	}
	if($line){
	    print OUT $line;
	}
	close(OUT);
	exit 0;
    }

    $out = shift @ARGV;
}

sub input_filter{
    my($line)=@_;
     #if we have integer declaration, get it all before processing it..

    if($$line =~/\s+int\s+.*/s || $$line=~ /\s+unsigned\s+.*/s ||
       $$line =~/^int\s+.*/s || $$line=~ /^unsigned\s+.*/s
       ){
	if( $$line =~ /(\(|,|\)|\#|typedef)/s ){
	    #excluding int/unsigned appeared inside function prototypes,typedefs etc....
	    return 1;
	}

	if(index($$line,";") == -1){
#	    print "Getting one more for \"".$$line."\"\n";
	    return 0;
	}

	if($$line =~ /(.*)\s*int\s+([^:]*):\s*(\w+)\s*\;(.*)/s){
#	    print ">>>>> ".$$line."    ($1)\n";
            my ($prx,$name,$val,$extra)=($1,$2,$3,$4);
            $prx =~ s/\s*$//g;
	    $$line= $prx." int ".$name."__FORASTYLE__".$val.";".$extra;
#	    print "----->".$$line."\n";
	}
	elsif($$line =~ /\s*unsigned\s+([^:]*):\s*(\w+)\s*\;(.*)/s){
#	    print ">>>>> ".$$line."    ($1)\n";
            my ($name,$val,$extra)=($1,$2,$3);
            my $prx =~ s/\s*$//g;
	    $$line= "unsigned ".$name."__FORASTYLE__".$val.";".$extra;
#	    print "----->".$$line."\n";
	}
	return 1;
    }

    if($$line =~ /\#endif/ ||
       $$line =~ /\#else/ ||
       $$line =~ /\#if/
       ){
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
    print "Usage:\n   $name file1 file2 file3 ....\n";
}
