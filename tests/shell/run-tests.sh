#!/bin/bash

# Configuration
TESTDIR="./$(dirname $0)/testcases"
SRC_NFT="$(dirname $0)/../../src/nft"
DIFF=$(which diff)

msg_error() {
	echo "E: $1 ..." >&2
	exit 1
}

msg_warn() {
	echo "W: $1" >&2
}

msg_info() {
	echo "I: $1"
}

if [ "$(id -u)" != "0" ] ; then
	msg_error "this requires root!"
fi

if [ "${1}" != "run" ]; then
	if unshare -f -n true; then
		unshare -n "${0}" run $@
		exit $?
	fi
	msg_warn "cannot run in own namespace, connectivity might break"
fi
shift

[ -z "$NFT" ] && NFT=$SRC_NFT
${NFT} > /dev/null 2>&1
ret=$?
if [ ${ret} -eq 126 ] || [ ${ret} -eq 127 ]; then
	msg_error "cannot execute nft command: ${NFT}"
else
	msg_info "using nft command: ${NFT}"
fi

if [ ! -d "$TESTDIR" ] ; then
	msg_error "missing testdir $TESTDIR"
fi

FIND="$(which find)"
if [ ! -x "$FIND" ] ; then
	msg_error "no find binary found"
fi

MODPROBE="$(which modprobe)"
if [ ! -x "$MODPROBE" ] ; then
	msg_error "no modprobe binary found"
fi

DIFF="$(which diff)"
if [ ! -x "$DIFF" ] ; then
	DIFF=true
fi

if [ "$1" == "-v" ] ; then
	VERBOSE=y
	shift
fi

if [ "$1" == "-g" ] ; then
	DUMPGEN=y
	shift
fi

for arg in "$@"; do
	SINGLE+=" $arg"
	VERBOSE=y
done

kernel_cleanup() {
	$NFT flush ruleset
	$MODPROBE -raq \
	nft_reject_ipv4 nft_reject_bridge nft_reject_ipv6 nft_reject \
	nft_redir_ipv4 nft_redir_ipv6 nft_redir \
	nft_dup_ipv4 nft_dup_ipv6 nft_dup nft_nat \
	nft_masq_ipv4 nft_masq_ipv6 nft_masq \
	nft_exthdr nft_payload nft_cmp nft_range \
	nft_quota nft_queue nft_numgen nft_osf nft_socket nft_tproxy \
	nft_meta nft_meta_bridge nft_counter nft_log nft_limit \
	nft_fib nft_fib_ipv4 nft_fib_ipv6 nft_fib_inet \
	nft_hash nft_ct nft_compat nft_rt nft_objref \
	nft_set_hash nft_set_rbtree nft_set_bitmap \
	nft_chain_nat \
	nft_chain_route_ipv4 nft_chain_route_ipv6 \
	nft_dup_netdev nft_fwd_netdev \
	nft_reject nft_reject_inet nft_reject_netdev \
	nf_tables_set nf_tables \
	nf_flow_table nf_flow_table_ipv4 nf_flow_tables_ipv6 \
	nf_flow_table_inet nft_flow_offload \
	nft_xfrm
}

find_tests() {
	if [ ! -z "$SINGLE" ] ; then
		echo $SINGLE
		return
	fi
	${FIND} ${TESTDIR} -type f -executable | sort
}

echo ""
ok=0
failed=0
for testfile in $(find_tests)
do
	kernel_cleanup

	msg_info "[EXECUTING]	$testfile"
	test_output=$(NFT="$NFT" DIFF=$DIFF ${testfile} 2>&1)
	rc_got=$?
	echo -en "\033[1A\033[K" # clean the [EXECUTING] foobar line

	if [ "$rc_got" -eq 0 ] ; then
		# check nft dump only for positive tests
		dumppath="$(dirname ${testfile})/dumps"
		dumpfile="${dumppath}/$(basename ${testfile}).nft"
		rc_spec=0
		if [ "$rc_got" -eq 0 ] && [ -f ${dumpfile} ]; then
			test_output=$(${DIFF} -u ${dumpfile} <($NFT list ruleset) 2>&1)
			rc_spec=$?
		fi

		if [ "$rc_spec" -eq 0 ]; then
			msg_info "[OK]		$testfile"
			[ "$VERBOSE" == "y" ] && [ ! -z "$test_output" ] && echo "$test_output"
			((ok++))

			if [ "$DUMPGEN" == "y" ] && [ "$rc_got" == 0 ] && [ ! -f "${dumpfile}" ]; then
				mkdir -p "${dumppath}"
				$NFT list ruleset > "${dumpfile}"
			fi
		else
			((failed++))
			if [ "$VERBOSE" == "y" ] ; then
				msg_warn "[DUMP FAIL]	$testfile: dump diff detected"
				[ ! -z "$test_output" ] && echo "$test_output"
			else
				msg_warn "[DUMP FAIL]	$testfile"
			fi
		fi
	else
		((failed++))
		if [ "$VERBOSE" == "y" ] ; then
			msg_warn "[FAILED]	$testfile: got $rc_got"
			[ ! -z "$test_output" ] && echo "$test_output"
		else
			msg_warn "[FAILED]	$testfile"
		fi
	fi
done

echo ""
msg_info "results: [OK] $ok [FAILED] $failed [TOTAL] $((ok+failed))"

kernel_cleanup
[ "$failed" -eq 0 ]
