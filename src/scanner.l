/*
 * Copyright (c) 2007-2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

%{

#include <limits.h>
#include <glob.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/netfilter.h>

#include <nftables.h>
#include <erec.h>
#include <rule.h>
#include <parser.h>
#include "parser_bison.h"

#define YY_NO_INPUT

/*
 * Work around flex behaviour when reaching the end of buffer: normally, flex
 * regexes are greedy, when reaching the end of buffer however it tries to
 * match whatever is left in the buffer and only backs up in case it doesn't
 * match *any* pattern. Since we accept unquoted strings, this means any partial
 * token will be recognized as string.
 *
 * Make sure to only pass input to flex linewise to avoid this.
 */
#define YY_INPUT(buf,result,max_size)						\
{										\
	result = 0;								\
	errno = 0;								\
										\
	while (result < max_size) {						\
		int chr = fgetc(yyin);						\
										\
		if (chr != EOF) {						\
			buf[result++] = chr;					\
			if (chr == '\n' || chr == ' ')				\
				break;						\
			continue;						\
		}								\
										\
		if (ferror(yyin)) {						\
			if (errno != EINTR) {					\
				YY_FATAL_ERROR("input in flex scanner failed");	\
				break;						\
			}							\
			errno = 0;						\
			clearerr(yyin);						\
		}								\
		break;								\
	}									\
}

static void scanner_pop_buffer(yyscan_t scanner);


static void init_pos(struct input_descriptor *indesc)
{
	indesc->lineno		= 1;
	indesc->column		= 1;
	indesc->token_offset	= 0;
	indesc->line_offset 	= 0;
}

static void update_pos(struct parser_state *state, struct location *loc,
		       int len)
{
	loc->indesc			= state->indesc;
	loc->first_line			= state->indesc->lineno;
	loc->last_line			= state->indesc->lineno;
	loc->first_column		= state->indesc->column;
	loc->last_column		= state->indesc->column + len - 1;
	state->indesc->column		+= len;
}

static void update_offset(struct parser_state *state, struct location *loc,
			  unsigned int len)
{
	state->indesc->token_offset	+= len;
	loc->token_offset		= state->indesc->token_offset;
	loc->line_offset		= state->indesc->line_offset;
}

static void reset_pos(struct parser_state *state, struct location *loc)
{
	state->indesc->line_offset	= state->indesc->token_offset;
	state->indesc->lineno		+= 1;
	state->indesc->column		= 1;
}

static void scanner_push_start_cond(void *scanner, enum startcond_type type);

#define YY_USER_ACTION {					\
	update_pos(yyget_extra(yyscanner), yylloc, yyleng);	\
	update_offset(yyget_extra(yyscanner), yylloc, yyleng);	\
}

/* avoid warnings with -Wmissing-prototypes */
extern int	yyget_column(yyscan_t);
extern void	yyset_column(int, yyscan_t);

%}

space		[ ]
tab		\t
newline		\n
digit		[0-9]
hexdigit	[0-9a-fA-F]
decstring	{digit}+
hexstring	0[xX]{hexdigit}+
numberstring	({decstring}|{hexstring})
letter		[a-zA-Z]
string		({letter}|[_.])({letter}|{digit}|[/\-_\.])*
quotedstring	\"[^"]*\"
asteriskstring	({string}\*|{string}\\\*|\\\*|{string}\\\*{string})
comment		#.*$
slash		\/

timestring	([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?([0-9]+ms)?

hex4		([[:xdigit:]]{1,4})
v680		(({hex4}:){7}{hex4})
v670		((:)((:{hex4}){7}))
v671		((({hex4}:){1})((:{hex4}){6}))
v672		((({hex4}:){2})((:{hex4}){5}))
v673		((({hex4}:){3})((:{hex4}){4}))
v674		((({hex4}:){4})((:{hex4}){3}))
v675		((({hex4}:){5})((:{hex4}){2}))
v676		((({hex4}:){6})(:{hex4}{1}))
v677		((({hex4}:){7})(:))
v67		({v670}|{v671}|{v672}|{v673}|{v674}|{v675}|{v676}|{v677})
v660		((:)((:{hex4}){6}))
v661		((({hex4}:){1})((:{hex4}){5}))
v662		((({hex4}:){2})((:{hex4}){4}))
v663		((({hex4}:){3})((:{hex4}){3}))
v664		((({hex4}:){4})((:{hex4}){2}))
v665		((({hex4}:){5})((:{hex4}){1}))
v666		((({hex4}:){6})(:))
v66		({v660}|{v661}|{v662}|{v663}|{v664}|{v665}|{v666})
v650		((:)((:{hex4}){5}))
v651		((({hex4}:){1})((:{hex4}){4}))
v652		((({hex4}:){2})((:{hex4}){3}))
v653		((({hex4}:){3})((:{hex4}){2}))
v654		((({hex4}:){4})(:{hex4}{1}))
v655		((({hex4}:){5})(:))
v65		({v650}|{v651}|{v652}|{v653}|{v654}|{v655})
v640		((:)((:{hex4}){4}))
v641		((({hex4}:){1})((:{hex4}){3}))
v642		((({hex4}:){2})((:{hex4}){2}))
v643		((({hex4}:){3})((:{hex4}){1}))
v644		((({hex4}:){4})(:))
v64		({v640}|{v641}|{v642}|{v643}|{v644})
v630		((:)((:{hex4}){3}))
v631		((({hex4}:){1})((:{hex4}){2}))
v632		((({hex4}:){2})((:{hex4}){1}))
v633		((({hex4}:){3})(:))
v63		({v630}|{v631}|{v632}|{v633})
v620		((:)((:{hex4}){2}))
v620_rfc4291	((:)(:{ip4addr}))
v621		((({hex4}:){1})((:{hex4}){1}))
v622		((({hex4}:){2})(:))
v62_rfc4291	((:)(:[fF]{4})(:{ip4addr}))
v62		({v620}|{v621}|{v622}|{v62_rfc4291}|{v620_rfc4291})
v610		((:)(:{hex4}{1}))
v611		((({hex4}:){1})(:))
v61		({v610}|{v611})
v60		(::)

macaddr		(([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2})
ip4addr		(([[:digit:]]{1,3}"."){3}([[:digit:]]{1,3}))
ip6addr		({v680}|{v67}|{v66}|{v65}|{v64}|{v63}|{v62}|{v61}|{v60})
ip6addr_rfc2732	(\[{ip6addr}\])

classid		({hexdigit}{1,4}:{hexdigit}{1,4})
addrstring	({macaddr}|{ip4addr}|{ip6addr})

%option prefix="nft_"
%option outfile="lex.yy.c"
%option reentrant
%option noyywrap
%option nounput
%option bison-bridge
%option bison-locations
%option debug
%option yylineno
%option nodefault
%option warn
%option stack
%s SCANSTATE_ARP
%s SCANSTATE_CT
%s SCANSTATE_COUNTER
%s SCANSTATE_ETH
%s SCANSTATE_IP
%s SCANSTATE_IP6
%s SCANSTATE_LIMIT
%s SCANSTATE_QUOTA
%s SCANSTATE_SCTP
%s SCANSTATE_SECMARK
%s SCANSTATE_TCP
%s SCANSTATE_VLAN
%s SCANSTATE_CMD_LIST
%s SCANSTATE_EXPR_FIB
%s SCANSTATE_EXPR_HASH
%s SCANSTATE_EXPR_IPSEC
%s SCANSTATE_EXPR_NUMGEN
%s SCANSTATE_EXPR_QUEUE
%s SCANSTATE_EXPR_RT
%s SCANSTATE_EXPR_SCTP_CHUNK
%s SCANSTATE_EXPR_SOCKET

%s SCANSTATE_STMT_LOG

%%

"=="			{ return EQ; }
"eq"			{ return EQ; }
"!="			{ return NEQ; }
"ne"			{ return NEQ; }
"<="			{ return LTE; }
"le"			{ return LTE; }
"<"			{ return LT; }
"lt"			{ return LT; }
">="			{ return GTE; }
"ge"			{ return GTE; }
">"			{ return GT; }
"gt"			{ return GT; }
","			{ return COMMA; }
"."			{ return DOT; }
":"			{ return COLON; }
";"			{ return SEMICOLON; }
"{"			{ return '{'; }
"}"			{ return '}'; }
"["			{ return '['; }
"]"			{ return ']'; }
"("			{ return '('; }
")"			{ return ')'; }
"<<"			{ return LSHIFT; }
"lshift"		{ return LSHIFT; }
">>"			{ return RSHIFT; }
"rshift"		{ return RSHIFT; }
"^"			{ return CARET; }
"xor"			{ return CARET; }
"&"			{ return AMPERSAND; }
"and"			{ return AMPERSAND; }
"|"			{ return '|'; }
"or"			{ return '|'; }
"!"			{ return NOT; }
"not"			{ return NOT; }
"/"			{ return SLASH; }
"-"			{ return DASH; }
"*"			{ return ASTERISK; }
"@"			{ return AT; }
"$"			{ return '$'; }
"="			{ return '='; }
"vmap"			{ return VMAP; }

"+"			{ return PLUS; }

"include"		{ return INCLUDE; }
"define"		{ return DEFINE; }
"redefine"		{ return REDEFINE; }
"undefine"		{ return UNDEFINE; }

"describe"		{ return DESCRIBE; }

"hook"			{ return HOOK; }
"device"		{ return DEVICE; }
"devices"		{ return DEVICES; }
"table"			{ return TABLE; }
"tables"		{ return TABLES; }
"chain"			{ return CHAIN; }
"chains"		{ return CHAINS; }
"rule"			{ return RULE; }
"rules"			{ return RULES; }
"sets"			{ return SETS; }
"set"			{ return SET; }
"element"		{ return ELEMENT; }
"map"			{ return MAP; }
"flowtable"		{ return FLOWTABLE; }
"handle"		{ return HANDLE; }
"ruleset"		{ return RULESET; }
"trace"			{ return TRACE; }

"socket"		{ scanner_push_start_cond(yyscanner, SCANSTATE_EXPR_SOCKET); return SOCKET; }
<SCANSTATE_EXPR_SOCKET>{
	"transparent"		{ return TRANSPARENT; }
	"wildcard"		{ return WILDCARD; }
	"cgroupv2"		{ return CGROUPV2; }
	"level"			{ return LEVEL; }
}
"tproxy"		{ return TPROXY; }

"accept"		{ return ACCEPT; }
"drop"			{ return DROP; }
"continue"		{ return CONTINUE; }
"jump"			{ return JUMP; }
"goto"			{ return GOTO; }
"return"		{ return RETURN; }
"to"			{ return TO; }

"inet"			{ return INET; }
"netdev"		{ return NETDEV; }

"add"			{ return ADD; }
"replace"		{ return REPLACE; }
"update"		{ return UPDATE; }
"create"		{ return CREATE; }
"insert"		{ return INSERT; }
"delete"		{ return DELETE; }
"get"			{ return GET; }
"list"			{ scanner_push_start_cond(yyscanner, SCANSTATE_CMD_LIST); return LIST; }
"reset"			{ return RESET; }
"flush"			{ return FLUSH; }
"rename"		{ return RENAME; }
"import"                { return IMPORT; }
"export"		{ return EXPORT; }
"monitor"		{ return MONITOR; }

"position"		{ return POSITION; }
"index"			{ return INDEX; }
"comment"		{ return COMMENT; }

"constant"		{ return CONSTANT; }
"interval"		{ return INTERVAL; }
"dynamic"		{ return DYNAMIC; }
"auto-merge"		{ return AUTOMERGE; }
"timeout"		{ return TIMEOUT; }
"gc-interval"		{ return GC_INTERVAL; }
"elements"		{ return ELEMENTS; }
"expires"		{ return EXPIRES; }

"policy"		{ return POLICY; }
"size"			{ return SIZE; }
"performance"		{ return PERFORMANCE; }
"memory"		{ return MEMORY; }

"flow"			{ return FLOW; }
"offload"		{ return OFFLOAD; }
"meter"			{ return METER; }

<SCANSTATE_CMD_LIST>{
	"meters"		{ return METERS; }
	"flowtables"		{ return FLOWTABLES; }
	"limits"		{ return LIMITS; }
	"maps"			{ return MAPS; }
	"secmarks"		{ return SECMARKS; }
	"synproxys"		{ return SYNPROXYS; }
	"hooks"			{ return HOOKS; }
}

"counter"		{ scanner_push_start_cond(yyscanner, SCANSTATE_COUNTER); return COUNTER; }
"name"			{ return NAME; }
<SCANSTATE_COUNTER,SCANSTATE_CT,SCANSTATE_LIMIT>"packets"		{ return PACKETS; }
<SCANSTATE_COUNTER,SCANSTATE_CT,SCANSTATE_LIMIT,SCANSTATE_QUOTA>"bytes"	{ return BYTES; }

"counters"		{ return COUNTERS; }
"quotas"		{ return QUOTAS; }

"log"			{ scanner_push_start_cond(yyscanner, SCANSTATE_STMT_LOG); return LOG; }
"prefix"		{ return PREFIX; }
"group"			{ return GROUP; }
<SCANSTATE_STMT_LOG>{
	"snaplen"		{ return SNAPLEN; }
	"queue-threshold"	{ return QUEUE_THRESHOLD; }
	"level"			{ return LEVEL; }
}

"queue"			{ scanner_push_start_cond(yyscanner, SCANSTATE_EXPR_QUEUE); return QUEUE;}
<SCANSTATE_EXPR_QUEUE>{
	"num"		{ return QUEUENUM;}
	"bypass"	{ return BYPASS;}
	"fanout"	{ return FANOUT;}
}
"limit"			{ scanner_push_start_cond(yyscanner, SCANSTATE_LIMIT); return LIMIT; }
<SCANSTATE_LIMIT>{
	"rate"			{ return RATE; }
	"burst"			{ return BURST; }

	/* time_unit */
	"second"		{ return SECOND; }
	"minute"		{ return MINUTE; }
	"week"			{ return WEEK; }
}
<SCANSTATE_CT,SCANSTATE_LIMIT,SCANSTATE_QUOTA>"over"		{ return OVER; }

"quota"			{ scanner_push_start_cond(yyscanner, SCANSTATE_QUOTA); return QUOTA; }
<SCANSTATE_QUOTA>{
	"used"		{ return USED; }
	"until"		{ return UNTIL; }
}

"hour"			{ return HOUR; }
"day"			{ return DAY; }

"reject"		{ return _REJECT; }
"with"			{ return WITH; }
"icmpx"			{ return ICMPX; }

"snat"			{ return SNAT; }
"dnat"			{ return DNAT; }
"masquerade"		{ return MASQUERADE; }
"fullcone"		{ return FULLCONE; }
"redirect"		{ return REDIRECT; }
"random"		{ return RANDOM; }
"fully-random"		{ return FULLY_RANDOM; }
"persistent"		{ return PERSISTENT; }

"ll"			{ return LL_HDR; }
"nh"			{ return NETWORK_HDR; }
"th"			{ return TRANSPORT_HDR; }

"bridge"		{ return BRIDGE; }

"ether"			{ scanner_push_start_cond(yyscanner, SCANSTATE_ETH); return ETHER; }
<SCANSTATE_ARP,SCANSTATE_CT,SCANSTATE_ETH,SCANSTATE_IP,SCANSTATE_IP6,SCANSTATE_EXPR_FIB,SCANSTATE_EXPR_IPSEC>{
	"saddr"			{ return SADDR; }
	"daddr"			{ return DADDR; }
}
"type"			{ return TYPE; }
"typeof"		{ return TYPEOF; }

"vlan"			{ scanner_push_start_cond(yyscanner, SCANSTATE_VLAN); return VLAN; }
"id"			{ return ID; }
<SCANSTATE_VLAN>{
	"cfi"		{ return CFI; }
	"dei"		{ return DEI; }
	"pcp"		{ return PCP; }
}
"8021ad"		{ yylval->string = xstrdup(yytext); return STRING; }
"8021q"			{ yylval->string = xstrdup(yytext); return STRING; }

"arp"			{ scanner_push_start_cond(yyscanner, SCANSTATE_ARP); return ARP; }
<SCANSTATE_ARP>{
	"htype"			{ return HTYPE; }
	"ptype"			{ return PTYPE; }
	"hlen"			{ return HLEN; }
	"plen"			{ return PLEN; }
	"operation"		{ return OPERATION; }
}

"ip"			{ scanner_push_start_cond(yyscanner, SCANSTATE_IP); return IP; }
"version"		{ return HDRVERSION; }
"hdrlength"		{ return HDRLENGTH; }
"dscp"			{ return DSCP; }
"ecn"			{ return ECN; }
"length"		{ return LENGTH; }
"frag-off"		{ return FRAG_OFF; }
"ttl"			{ return TTL; }
"protocol"		{ return PROTOCOL; }
"checksum"		{ return CHECKSUM; }

<SCANSTATE_IP>{
	"lsrr"			{ return LSRR; }
	"rr"			{ return RR; }
	"ssrr"			{ return SSRR; }
	"ra"			{ return RA; }

	"ptr"			{ return PTR; }
	"value"			{ return VALUE; }
}

<SCANSTATE_TCP>{
"echo"			{ return ECHO; }
"eol"			{ return EOL; }
"fastopen"		{ return FASTOPEN; }
"mptcp"			{ return MPTCP; }
"md5sig"		{ return MD5SIG; }
"subtype"		{ return SUBTYPE; }
"nop"			{ return NOP; }
"noop"			{ return NOP; }
"sack"			{ return SACK; }
"sack0"			{ return SACK0; }
"sack1"			{ return SACK1; }
"sack2"			{ return SACK2; }
"sack3"			{ return SACK3; }
"time"			{ return TIME; }

"count"			{ return COUNT; }
"left"			{ return LEFT; }
"right"			{ return RIGHT; }
"tsval"			{ return TSVAL; }
"tsecr"			{ return TSECR; }
}
"maxseg"		{ return MSS; }
"mss"			{ return MSS; }
"sack-permitted"	{ return SACK_PERM; }
"sack-perm"		{ return SACK_PERM; }
"timestamp"		{ return TIMESTAMP; }

"icmp"			{ return ICMP; }
"code"			{ return CODE; }
"sequence"		{ return SEQUENCE; }
"gateway"		{ return GATEWAY; }
"mtu"			{ return MTU; }

"igmp"			{ return IGMP; }
"mrt"			{ return MRT; }

"ip6"			{ scanner_push_start_cond(yyscanner, SCANSTATE_IP6); return IP6; }
"priority"		{ return PRIORITY; }
<SCANSTATE_IP6>{
	"flowlabel"		{ return FLOWLABEL; }
	"hoplimit"		{ return HOPLIMIT; }
}
"nexthdr"		{ return NEXTHDR; }

"icmpv6"		{ return ICMP6; }
"param-problem"		{ return PPTR; }
"max-delay"		{ return MAXDELAY; }

"ah"			{ return AH; }
"reserved"		{ return RESERVED; }
"spi"			{ return SPI; }

"esp"			{ return ESP; }

"comp"			{ return COMP; }
"flags"			{ return FLAGS; }
"cpi"			{ return CPI; }

"udp"			{ return UDP; }
"udplite"		{ return UDPLITE; }
"sport"			{ return SPORT; }
"dport"			{ return DPORT; }
"port"			{ return PORT; }

"tcp"			{ scanner_push_start_cond(yyscanner, SCANSTATE_TCP); return TCP; }
"ackseq"		{ return ACKSEQ; }
"doff"			{ return DOFF; }
"window"		{ return WINDOW; }
"urgptr"		{ return URGPTR; }
"option"		{ return OPTION; }

"dccp"			{ return DCCP; }

"sctp"			{ scanner_push_start_cond(yyscanner, SCANSTATE_SCTP); return SCTP; }

<SCANSTATE_SCTP>{
	"chunk"			{ scanner_push_start_cond(yyscanner, SCANSTATE_EXPR_SCTP_CHUNK); return CHUNK; }
	"vtag"			{ return VTAG; }
}

<SCANSTATE_EXPR_SCTP_CHUNK>{
	"data"			{ return DATA; }
	"init"			{ return INIT; }
	"init-ack"		{ return INIT_ACK; }
	"heartbeat"		{ return HEARTBEAT; }
	"heartbeat-ack"		{ return HEARTBEAT_ACK; }
	"abort"			{ return ABORT; }
	"shutdown"		{ return SHUTDOWN; }
	"shutdown-ack"		{ return SHUTDOWN_ACK; }
	"error"			{ return ERROR; }
	"cookie-echo"		{ return COOKIE_ECHO; }
	"cookie-ack"		{ return COOKIE_ACK; }
	"ecne"			{ return ECNE; }
	"cwr"			{ return CWR; }
	"shutdown-complete"	{ return SHUTDOWN_COMPLETE; }
	"asconf-ack"		{ return ASCONF_ACK; }
	"forward-tsn"		{ return FORWARD_TSN; }
	"asconf"		{ return ASCONF; }

	"tsn"			{ return TSN; }
	"sack"			{ return SACK; }
	"stream"		{ return STREAM; }
	"ssn"			{ return SSN; }
	"ppid"			{ return PPID; }
	"init-tag"		{ return INIT_TAG; }
	"a-rwnd"		{ return A_RWND; }
	"num-outbound-streams"	{ return NUM_OSTREAMS; }
	"num-inbound-streams"	{ return NUM_ISTREAMS; }
	"initial-tsn"		{ return INIT_TSN; }
	"cum-tsn-ack"		{ return CUM_TSN_ACK; }
	"num-gap-ack-blocks"	{ return NUM_GACK_BLOCKS; }
	"num-dup-tsns"		{ return NUM_DUP_TSNS; }
	"lowest-tsn"		{ return LOWEST_TSN; }
	"seqno"			{ return SEQNO; }
	"new-cum-tsn"		{ return NEW_CUM_TSN; }
}

"rt"			{ scanner_push_start_cond(yyscanner, SCANSTATE_EXPR_RT); return RT; }
"rt0"			{ return RT0; }
"rt2"			{ return RT2; }
"srh"			{ return RT4; }
"addr"			{ return ADDR; }
"last-entry"		{ return LAST_ENT; }
"tag"			{ return TAG; }
"sid"			{ return SID; }

"hbh"			{ return HBH; }

"frag"			{ return FRAG; }
"reserved2"		{ return RESERVED2; }
"more-fragments"	{ return MORE_FRAGMENTS; }

"dst"			{ return DST; }

"mh"			{ return MH; }

"meta"			{ return META; }
"mark"			{ return MARK; }
"iif"			{ return IIF; }
"iifname"		{ return IIFNAME; }
"iiftype"		{ return IIFTYPE; }
"oif"			{ return OIF; }
"oifname"		{ return OIFNAME; }
"oiftype"		{ return OIFTYPE; }
"skuid"			{ return SKUID; }
"skgid"			{ return SKGID; }
"nftrace"		{ return NFTRACE; }
"rtclassid"		{ return RTCLASSID; }
"ibriport"		{ return IBRIPORT; }
"ibrname"		{ return IBRIDGENAME; }
"obriport"		{ return OBRIPORT; }
"obrname"		{ return OBRIDGENAME; }
"pkttype"		{ return PKTTYPE; }
"cpu"			{ return CPU; }
"iifgroup"		{ return IIFGROUP; }
"oifgroup"		{ return OIFGROUP; }
"cgroup"		{ return CGROUP; }

<SCANSTATE_EXPR_RT>{
	"classid"		{ return CLASSID; }
	"nexthop"		{ return NEXTHOP; }
	"seg-left"		{ return SEG_LEFT; }
}

"ct"			{ scanner_push_start_cond(yyscanner, SCANSTATE_CT); return CT; }
<SCANSTATE_CT>{
	"avgpkt"		{ return AVGPKT; }
	"l3proto"		{ return L3PROTOCOL; }
	"proto-src"		{ return PROTO_SRC; }
	"proto-dst"		{ return PROTO_DST; }
	"zone"			{ return ZONE; }
	"original"		{ return ORIGINAL; }
	"reply"			{ return REPLY; }
	"direction"		{ return DIRECTION; }
	"event"			{ return EVENT; }
	"expectation"		{ return EXPECTATION; }
	"expiration"		{ return EXPIRATION; }
	"helper"		{ return HELPER; }
	"helpers"		{ return HELPERS; }
	"label"			{ return LABEL; }
	"state"			{ return STATE; }
	"status"		{ return STATUS; }
	"count"			{ return COUNT; }
}

"numgen"		{ scanner_push_start_cond(yyscanner, SCANSTATE_EXPR_NUMGEN); return NUMGEN; }
<SCANSTATE_EXPR_NUMGEN>{
	"inc"		{ return INC; }
}

"jhash"			{ scanner_push_start_cond(yyscanner, SCANSTATE_EXPR_HASH); return JHASH; }
"symhash"		{ scanner_push_start_cond(yyscanner, SCANSTATE_EXPR_HASH); return SYMHASH; }

<SCANSTATE_EXPR_HASH>{
	"seed"		{ return SEED; }
}
<SCANSTATE_EXPR_HASH,SCANSTATE_EXPR_NUMGEN>{
	"mod"		{ return MOD; }
	"offset"	{ return OFFSET; }
}
"dup"			{ return DUP; }
"fwd"			{ return FWD; }

"fib"			{ scanner_push_start_cond(yyscanner, SCANSTATE_EXPR_FIB); return FIB; }

"osf"			{ return OSF; }

"synproxy"		{ return SYNPROXY; }
"wscale"		{ return WSCALE; }

"notrack"		{ return NOTRACK; }

"options"		{ return OPTIONS; }
"all"			{ return ALL; }

"xml"			{ return XML; }
"json"			{ return JSON; }
"vm"                    { return VM; }

"exists"		{ return EXISTS; }
"missing"		{ return MISSING; }

"exthdr"		{ return EXTHDR; }

"ipsec"			{ scanner_push_start_cond(yyscanner, SCANSTATE_EXPR_IPSEC); return IPSEC; }
<SCANSTATE_EXPR_IPSEC>{
	"reqid"			{ return REQID; }
	"spnum"			{ return SPNUM; }

	"in"			{ return IN; }
	"out"			{ return OUT; }
}

"secmark"		{ scanner_push_start_cond(yyscanner, SCANSTATE_SECMARK); return SECMARK; }

{addrstring}		{
				yylval->string = xstrdup(yytext);
				return STRING;
			}

{ip6addr_rfc2732}	{
				yytext[yyleng - 1] = '\0';
				yylval->string = xstrdup(yytext + 1);
				return STRING;
			}

{timestring}		{
				yylval->string = xstrdup(yytext);
				return STRING;
			}

{numberstring}		{
				errno = 0;
				yylval->val = strtoull(yytext, NULL, 0);
				if (errno != 0) {
					yylval->string = xstrdup(yytext);
					return STRING;
				}
				return NUM;
			}

{classid}/[ \t\n:\-},]	{
				yylval->string = xstrdup(yytext);
				return STRING;
			}

{quotedstring}		{
				yytext[yyleng - 1] = '\0';
				yylval->string = xstrdup(yytext + 1);
				return QUOTED_STRING;
			}

{asteriskstring}	{
				yylval->string = xstrdup(yytext);
				return ASTERISK_STRING;
			}

{string}		{
				yylval->string = xstrdup(yytext);
				return STRING;
			}

\\{newline}		{
				reset_pos(yyget_extra(yyscanner), yylloc);
			}

{newline}		{
				reset_pos(yyget_extra(yyscanner), yylloc);
				return NEWLINE;
			}

{tab}+
{space}+
{comment}

<<EOF>> 		{
				update_pos(yyget_extra(yyscanner), yylloc, 1);
				scanner_pop_buffer(yyscanner);
				if (YY_CURRENT_BUFFER == NULL)
					return TOKEN_EOF;
			}

.			{ return JUNK; }

%%

static void scanner_push_indesc(struct parser_state *state,
				struct input_descriptor *indesc)
{
	if (!state->indesc)
		list_add_tail(&indesc->list, &state->indesc_list);
	else
		list_add(&indesc->list, &state->indesc->list);

	state->indesc = indesc;
}

static void scanner_pop_indesc(struct parser_state *state)
{
	if (!list_is_first(&state->indesc->list, &state->indesc_list)) {
		state->indesc = list_entry(state->indesc->list.prev,
					   struct input_descriptor, list);
	} else {
		state->indesc = NULL;
	}
}

static void scanner_pop_buffer(yyscan_t scanner)
{
	struct parser_state *state = yyget_extra(scanner);

	yypop_buffer_state(scanner);
	scanner_pop_indesc(state);
}

static void scanner_push_file(struct nft_ctx *nft, void *scanner,
			      FILE *f, const char *filename,
			      const struct location *loc,
			      const struct input_descriptor *parent_indesc)
{
	struct parser_state *state = yyget_extra(scanner);
	struct input_descriptor *indesc;
	YY_BUFFER_STATE b;

	b = yy_create_buffer(f, YY_BUF_SIZE, scanner);
	yypush_buffer_state(b, scanner);

	indesc = xzalloc(sizeof(struct input_descriptor));

	if (loc != NULL)
		indesc->location = *loc;
	indesc->type	= INDESC_FILE;
	indesc->name	= xstrdup(filename);
	indesc->f	= f;
	if (!parent_indesc) {
		indesc->depth = 1;
	} else {
		indesc->depth = parent_indesc->depth + 1;
	}
	init_pos(indesc);

	scanner_push_indesc(state, indesc);
}

static int include_file(struct nft_ctx *nft, void *scanner,
			const char *filename, const struct location *loc,
			const struct input_descriptor *parent_indesc)
{
	struct parser_state *state = yyget_extra(scanner);
	struct error_record *erec;
	FILE *f;

	if (parent_indesc && parent_indesc->depth == MAX_INCLUDE_DEPTH) {
		erec = error(loc, "Include nested too deeply, max %u levels",
			     MAX_INCLUDE_DEPTH);
		goto err;
	}

	f = fopen(filename, "r");
	if (f == NULL) {
		erec = error(loc, "Could not open file \"%s\": %s\n",
			     filename, strerror(errno));
		goto err;
	}
	scanner_push_file(nft, scanner, f, filename, loc, parent_indesc);
	return 0;
err:
	erec_queue(erec, state->msgs);
	return -1;
}

static int include_glob(struct nft_ctx *nft, void *scanner, const char *pattern,
			const struct location *loc)
{
	struct parser_state *state = yyget_extra(scanner);
	struct input_descriptor *indesc = state->indesc;
	struct error_record *erec = NULL;
	bool wildcard = false;
	glob_t glob_data;
	unsigned int i;
	int flags = 0;
	int ret;
	char *p;

	/* This function can return four meaningful values:
	 *
	 *  -1 means that there was an error.
	 *   0 means that a single non-wildcard match was done.
	 *   1 means that there are no wildcards in the pattern and the
	 *     search can continue.
	 *   2 means that there are wildcards in the pattern and the search
	 *     can continue.
	 *
	 * The diffrence is needed, because there is a semantic difference
	 * between patterns with wildcards and no wildcards. Not finding a
	 * non-wildcard file is an error but not finding any matches for a
	 * wildcard pattern is not.
	 */

	/* There shouldn't be a need to use escape characters in include paths.
	 */
	flags |= GLOB_NOESCAPE;

	/* Mark directories so we can filter them out (also links). */
	flags |= GLOB_MARK;

	/* If there is no match, glob() doesn't set GLOB_MAGCHAR even if there
	 * are wildcard characters in the pattern. We need to look for (luckily
	 * well-known and not likely to change) magic characters ourselves. In a
	 * perfect world, we could use glob() itself to figure out if there are
	 * wildcards in the pattern.
	 */
	p = (char *)pattern;
	while (*p) {
		if (*p == '*' || *p == '?' || *p == '[') {
			wildcard = true;
			break;
		}
		p++;
	}

	ret = glob(pattern, flags, NULL, &glob_data);
	if (ret == 0) {
		char *path;
		int len;

		/* reverse alphabetical order due to stack */
		for (i = glob_data.gl_pathc; i > 0; i--) {

			path = glob_data.gl_pathv[i-1];

			/* ignore directories */
			len = strlen(path);
			if (len == 0 || path[len - 1] == '/')
				continue;

			ret = include_file(nft, scanner, path, loc, indesc);
			if (ret != 0)
				goto err;
		}

		globfree(&glob_data);

		/* If no wildcards and we found the file, stop the search (with
		 * 0). In case of wildcards we need to still continue the
		 * search, because other matches might be in other include
		 * directories. We handled the case with a non-wildcard pattern
		 * and no matches already before.
		 */
		 return wildcard ? 2 : 0;
	} else if (ret == GLOB_NOMATCH) {
		globfree(&glob_data);

		/* We need to tell the caller whether wildcards were used in
		 * case of no match, because the semantics for handling the
		 * cases are different.
		 */
		return wildcard ? 2 : 1;
	}

	erec = error(loc, "Failed to glob the pattern %s", pattern);

	/* intentional fall through */
err:
	if (erec)
		erec_queue(erec, state->msgs);
	globfree(&glob_data);
	return -1;
}

int scanner_read_file(struct nft_ctx *nft, const char *filename,
		      const struct location *loc)
{
	return include_file(nft, nft->scanner, filename, loc, NULL);
}

static bool search_in_include_path(const char *filename)
{
	return (strncmp(filename, "./", strlen("./")) != 0 &&
		strncmp(filename, "../", strlen("../")) != 0 &&
		filename[0] != '/');
}

int scanner_include_file(struct nft_ctx *nft, void *scanner,
			 const char *filename, const struct location *loc)
{
	struct parser_state *state = yyget_extra(scanner);
	struct error_record *erec;
	char buf[PATH_MAX];
	unsigned int i;
	int ret = -1;

	if (search_in_include_path(filename)) {
		for (i = 0; i < nft->num_include_paths; i++) {
			ret = snprintf(buf, sizeof(buf), "%s/%s",
				       nft->include_paths[i], filename);
			if (ret < 0 || ret >= PATH_MAX) {
				erec = error(loc, "Too long file path \"%s/%s\"\n",
					     nft->include_paths[i], filename);
				erec_queue(erec, state->msgs);
				return -1;
			}

			ret = include_glob(nft, scanner, buf, loc);

			/* error was already handled */
			if (ret == -1)
				return -1;
			/* no wildcards and file was processed: break early. */
			if (ret == 0)
				return 0;

			/* else 1 (no wildcards) or 2 (wildcards): keep
			 * searching.
			 */
		}
	} else {
		/* an absolute path (starts with '/') */
		ret = include_glob(nft, scanner, filename, loc);
	}

	/* handle the case where no file was found */
	if (ret == -1)
		return -1;
	else if (ret == 0 || ret == 2)
		return 0;

	/* 1 means an error, because there are no more include directories to
	 * search, and the pattern does not have wildcard characters.
	 */
	erec = error(loc, "File not found: %s", filename);
	erec_queue(erec, state->msgs);
	return -1;
}

void scanner_push_buffer(void *scanner, const struct input_descriptor *indesc,
			 const char *buffer)
{
	struct parser_state *state = yyget_extra(scanner);
	struct input_descriptor *new_indesc;
	YY_BUFFER_STATE b;

	new_indesc = xzalloc(sizeof(struct input_descriptor));
	memcpy(new_indesc, indesc, sizeof(*new_indesc));
	new_indesc->data = buffer;
	new_indesc->name = xstrdup(indesc->name);
	scanner_push_indesc(state, new_indesc);

	b = yy_scan_string(buffer, scanner);
	assert(b != NULL);
	init_pos(state->indesc);
}

void *scanner_init(struct parser_state *state)
{
	yyscan_t scanner;

	yylex_init_extra(state, &scanner);
	yyset_out(NULL, scanner);

	return scanner;
}

static void input_descriptor_destroy(const struct input_descriptor *indesc)
{
	if (indesc->name)
		xfree(indesc->name);
	xfree(indesc);
}

static void input_descriptor_list_destroy(struct parser_state *state)
{
	struct input_descriptor *indesc, *next;

	list_for_each_entry_safe(indesc, next, &state->indesc_list, list) {
		if (indesc->f) {
			fclose(indesc->f);
			indesc->f = NULL;
		}
		list_del(&indesc->list);
		input_descriptor_destroy(indesc);
	}
}

void scanner_destroy(struct nft_ctx *nft)
{
	struct parser_state *state = yyget_extra(nft->scanner);

	input_descriptor_list_destroy(state);
	yylex_destroy(nft->scanner);
}

static void scanner_push_start_cond(void *scanner, enum startcond_type type)
{
	struct parser_state *state = yyget_extra(scanner);

	state->startcond_type = type;

	yy_push_state((int)type, scanner);
}

void scanner_pop_start_cond(void *scanner, enum startcond_type t)
{
	struct parser_state *state = yyget_extra(scanner);

	if (state->startcond_type != t) {
		state->flex_state_pop++;
		return; /* Can't pop just yet! */
	}

	while (state->flex_state_pop) {
		state->flex_state_pop--;
		state->startcond_type = yy_top_state(scanner);
		yy_pop_state(scanner);
	}

	state->startcond_type = yy_top_state(scanner);

	yy_pop_state(scanner);
}
