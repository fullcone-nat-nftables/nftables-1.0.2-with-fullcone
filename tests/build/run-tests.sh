#!/bin/bash

log_file="`pwd`/tests.log"
dir=../..
argument=( --without-cli --with-cli=linenoise --with-cli=editline --enable-debug --with-mini-gmp
	   --enable-man-doc --with-xtables --with-json)
ok=0
failed=0

[ -f $log_file ] && rm -rf $log_file

tmpdir=$(mktemp -d)
if [ ! -w $tmpdir ] ; then
        echo "Failed to create tmp file" >&2
        exit 0
fi

git clone $dir $tmpdir >/dev/null 2>>$log_file
cd $tmpdir

autoreconf -fi >/dev/null 2>>$log_file
./configure >/dev/null 2>>$log_file

echo  "Testing build with distcheck"
make distcheck >/dev/null 2>>$log_file
rt=$?

if [ $rt != 0 ] ; then
	echo "Something went wrong. Check the log for details."
	exit 1
fi

echo -en "\033[1A\033[K"
echo "Build works. Now, testing compile options"

for var in "${argument[@]}" ; do
	echo "[EXECUTING] Testing compile option $var"
	./configure $var >/dev/null 2>>$log_file
	make -j 8 >/dev/null 2>>$log_file
	rt=$?
	echo -en "\033[1A\033[K" # clean the [EXECUTING] foobar line

	if [ $rt -eq 0 ] ; then
		echo "[OK] Compile option $var works."
		((ok++))
	else
		echo "[FAILED] Compile option $var does not work. Check log for details."
		((failed++))
	fi
done

rm -rf $tmpdir

echo "results: [OK] $ok [FAILED] $failed [TOTAL] $((ok+failed))"
[ "$failed" -eq 0 ]
