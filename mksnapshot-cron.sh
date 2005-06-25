#!/bin/sh -e
# Nightly cron job to generate snapshot releases
cd `dirname $0`
top=$PWD
versions=/server/httpd/htdocs/squid-cache.org/Versions/
TMPDIR=/tmp/hno.cron
export TMPDIR
if [ -d $TMPDIR ]; then
	chmod -R +w $TMPDIR
	rm -rf $TMPDIR
fi
mkdir -p $TMPDIR
trap "cd /; chmod -R +w $TMPDIR; rm -rf $TMPDIR" 0

PATH=/bin:/usr/bin:/usr/local/bin
export PATH

# Be nice to our friends. This is a batch job
renice 10 $$ >/dev/null

make_snapshot()
{ {
  set -e
  cd ../release
  mksnap=$1
  tag=$2
  dir=$3
  ver=$4
  save=${5:-3}
  dst=$versions/$dir/$ver
  $mksnap $tag 2>&1 | grep -v "set owner/group"
  for file in `cat $tag.out` ; do
    type=`echo $file | sed -e 's/.*\.tar\.gz/.tar.gz/' -e 's/.*\.tar\.bz2/.tar.bz2/' -e 's/.*\.patch/.patch/' -e 's/.*\.diff/.diff/' -e 's/.*-RELEASENOTES.html/-RELEASENOTES.html/' -e 's/^.*ChangeLog.txt$/-ChangeLog.txt/'`

    # move tarball
    rm -f $dst/$file
    cp -p $file $dst/$file
    rm -f $file

    # update snapshot symlink
    rm -f $dst/squid-$ver.snapshot$type
    ln -s $file $dst/squid-$ver.snapshot$type

    # cleanup old snapshots
    ls $dst/*-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]$type | sort -r -t- +2 | tail +$save | xargs rm -f
  done

  # update web page
  if [ -x $dst/make.sh ]; then
      $dst/make.sh
  fi

} }

set +e

../commit/bootstrap squid
make_snapshot ../commit/squid/mksnapshot.sh HEAD v3 HEAD 6

rm -f /server/httpd/htdocs/squid-cache.org/CONTRIBUTORS.new
cp ../commit/squid/CONTRIBUTORS /server/httpd/htdocs/squid-cache.org/CONTRIBUTORS.new
chmod 444 /server/httpd/htdocs/squid-cache.org/CONTRIBUTORS.new
mv -f /server/httpd/htdocs/squid-cache.org/CONTRIBUTORS.new /server/httpd/htdocs/squid-cache.org/CONTRIBUTORS.txt

rm -f /server/httpd/htdocs/squid-cache.org/SPONSORS.new
cp ../commit/squid/SPONSORS /server/httpd/htdocs/squid-cache.org/SPONSORS.new
chmod 444 /server/httpd/htdocs/squid-cache.org/SPONSORS.new
mv -f /server/httpd/htdocs/squid-cache.org/SPONSORS.new /server/httpd/htdocs/squid-cache.org/SPONSORS.txt

#../commit/bootstrap squid-3.0
#make_snapshot ../commit/squid/mksnapshot.sh SQUID_3_0 v3 3.0 3
make_snapshot ../commit/squid/mksnapshot.sh HEAD v3 3.0 3

#../commit/bootstrap squid-2
#make_snapshot ../commit/squid-2/mksnapshot.sh HEAD v2 2.6 6

../commit/bootstrap squid-2.5
make_snapshot ../commit/squid-2.5/mksnapshot.sh SQUID_2_5 v2 2.5 3

#../commit/squid3-SQUID2.sync
