#!/usr/local/bin/perl

# $Id: upgrade-1.0-store.pl,v 1.2 1996/10/11 19:56:06 wessels Exp $

select(STDERR); $|=1;
select(STDOUT); $|=1;

$USAGE="Usage: $0 swaplog cachedir1 cachedir2 ...\n";

$dry_run = 0;

$swaplog = shift || die $USAGE;
(@cachedirs = @ARGV) || die $USAGE;
$ncache_dirs = $#cachedirs + 1;

$OLD_SWAP_DIRECTORIES = 100;
$NEW_SWAP_DIRECTORIES_L1 = 16;
$NEW_SWAP_DIRECTORIES_L2 = 256;

$EEXIST = 17; 		# check your /usr/include/errno.h

print <<EOF;
This script converts Squid 1.0 cache directories to the Squid 1.1
format.  The first step is to create the new directory structure.
The second step is to link the swapfiles from the old directories
into the new directories.  After this script runs you must manually
remove the old directories.

Filesystem operations are slow, so this script may take a while.
Your cache should NOT be running while this script runs.

Are you ready to proceed?
EOF

$ans = <STDIN>;

exit(1) unless ($ans =~ /^y$/ || $ans =~ /^yes$/);

# make new directories
foreach $c (@cachedirs) {
	$cn = "$c.new";
	&my_mkdir ($cn);
	foreach $d1 (0..($NEW_SWAP_DIRECTORIES_L1-1)) {
		$p1 = sprintf ("$cn/%02X", $d1);
		&my_mkdir ($p1);
		foreach $d2 (0..($NEW_SWAP_DIRECTORIES_L2-1)) {
			$p2 = sprintf ("$p1/%02X", $d2);
			&my_mkdir ($p2);
		}
	}
}

$newlog = "$swaplog.1.1";
open (newlog, ">$newlog") || die "$newlog: $!\n";
select(newlog); $|=1; select(STDOUT);
open (swaplog)	|| die "$swaplog: $!\n";
$count = 0;
while (<swaplog>) {
	chop;
	($file,$url,$expires,$timestamp,$size) = split;
	@F = split('/', $file);
	$oldfileno = pop @F;
	$oldpath = &old_fileno_to_path($oldfileno);
	unless (@S = stat($oldpath)) {
		print "$oldpath: $!\n";
		next;
	}
	unless ($S[7] == $size) {
		print "$oldpath: Wrong Size.\n";
		next;
	}
	$newpath = &new_fileno_to_path($oldfileno);
	next unless &my_link($oldpath,$newpath);
	printf newlog "%08x %08x %08x %08x %9d %s\n",
		$oldfileno,
		$timestamp,
		$expires,
		$timestamp,	# lastmod
		$size,
		$url;
	$count++;
}


print <<EOF;
Done converting.

$count files were linked to the new directories.

At this point you need to manually run these commands:
EOF

foreach $c (@cachedirs) {
    print "    /bin/mv $c $c.old; /bin/mv $c.new $c\n";
}

print <<EOF;
    /bin/mv $swaplog $swaplog.old; /bin/mv $newlog $swaplog\n";

And then start up Squid version 1.1.
EOF
exit(0);





sub old_fileno_to_path {
	local($fn) = @_;
	sprintf ("%s/%02d/%d",
		$cachedirs[$fn % $ncache_dirs],
		($fn / $ncache_dirs) % $OLD_SWAP_DIRECTORIES,
		$fn);
}

sub new_fileno_to_path {
	local($fn) = @_;
	sprintf ("%s.new/%02X/%02X/%08X",
		$cachedirs[$fn % $ncache_dirs],
		($fn / $ncache_dirs) % $NEW_SWAP_DIRECTORIES_L1,
		($fn / $ncache_dirs) / $NEW_SWAP_DIRECTORIES_L1 % $NEW_SWAP_DIRECTORIES_L2,
		$fn);
}

sub my_mkdir {
	local($p) = @_;
	print "Making $p...\n";
	return if ($dry_run);
	unless (mkdir ($p, 0755)) {
		return 1 if ($! == $EEXIST);
		die "$p: $!\n";
	}
}

sub my_link {
	local($f,$t) = @_;
	print "$f --> $t\n";
	return 1 if ($dry_run);
	unlink($t);
	$rc = link ($f,$t);
	warn "$t: $!\n" unless ($rc);
	$rc;
}
