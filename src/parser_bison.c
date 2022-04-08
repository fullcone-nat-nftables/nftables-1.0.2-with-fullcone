/* A Bison parser, made by GNU Bison 3.7.5.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30705

/* Bison version string.  */
#define YYBISON_VERSION "3.7.5"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         nft_parse
#define yylex           nft_lex
#define yyerror         nft_error
#define yydebug         nft_debug
#define yynerrs         nft_nerrs

/* First part of user prologue.  */
#line 11 "parser_bison.y"


#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>
#include <syslog.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/nf_log.h>
#include <linux/netfilter/nfnetlink_osf.h>
#include <linux/netfilter/nf_synproxy.h>
#include <linux/xfrm.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <libnftnl/common.h>
#include <libnftnl/set.h>
#include <libnftnl/udata.h>

#include <rule.h>
#include <statement.h>
#include <expression.h>
#include <headers.h>
#include <utils.h>
#include <parser.h>
#include <erec.h>
#include <sctp_chunk.h>

#include "parser_bison.h"

void parser_init(struct nft_ctx *nft, struct parser_state *state,
		 struct list_head *msgs, struct list_head *cmds,
		 struct scope *top_scope)
{
	memset(state, 0, sizeof(*state));
	state->msgs = msgs;
	state->cmds = cmds;
	state->scopes[0] = scope_init(top_scope, NULL);
	init_list_head(&state->indesc_list);
}

static void yyerror(struct location *loc, struct nft_ctx *nft, void *scanner,
		    struct parser_state *state, const char *s)
{
	erec_queue(error(loc, "%s", s), state->msgs);
}

static struct scope *current_scope(const struct parser_state *state)
{
	return state->scopes[state->scope];
}

static void open_scope(struct parser_state *state, struct scope *scope)
{
	assert(state->scope < array_size(state->scopes) - 1);
	scope_init(scope, current_scope(state));
	state->scopes[++state->scope] = scope;
}

static void close_scope(struct parser_state *state)
{
	assert(state->scope > 0);
	state->scope--;
}

static void location_init(void *scanner, struct parser_state *state,
			  struct location *loc)
{
	memset(loc, 0, sizeof(*loc));
	loc->indesc = state->indesc;
}

static void location_update(struct location *loc, struct location *rhs, int n)
{
	if (n) {
		loc->indesc       = rhs[n].indesc;
		loc->token_offset = rhs[1].token_offset;
		loc->line_offset  = rhs[1].line_offset;
		loc->first_line   = rhs[1].first_line;
		loc->first_column = rhs[1].first_column;
		loc->last_line    = rhs[n].last_line;
		loc->last_column  = rhs[n].last_column;
	} else {
		loc->indesc       = rhs[0].indesc;
		loc->token_offset = rhs[0].token_offset;
		loc->line_offset  = rhs[0].line_offset;
		loc->first_line   = loc->last_line   = rhs[0].last_line;
		loc->first_column = loc->last_column = rhs[0].last_column;
	}
}

static struct expr *handle_concat_expr(const struct location *loc,
					 struct expr *expr,
					 struct expr *expr_l, struct expr *expr_r,
					 struct location loc_rhs[3])
{
	if (expr->etype != EXPR_CONCAT) {
		expr = concat_expr_alloc(loc);
		compound_expr_add(expr, expr_l);
	} else {
		location_update(&expr_r->location, loc_rhs, 2);

		expr = expr_l;
		expr->location = *loc;
	}

	compound_expr_add(expr, expr_r);
	return expr;
}

static bool already_set(const void *attr, const struct location *loc,
			struct parser_state *state)
{
	if (!attr)
		return false;

	erec_queue(error(loc, "You can only specify this once. This statement is duplicated."),
		   state->msgs);
	return true;
}

#define YYLLOC_DEFAULT(Current, Rhs, N)	location_update(&Current, Rhs, N)

#define symbol_value(loc, str) \
	symbol_expr_alloc(loc, SYMBOL_VALUE, current_scope(state), str)

/* Declare those here to avoid compiler warnings */
void nft_set_debug(int, void *);
int nft_lex(void *, void *, void *);

#line 212 "parser_bison.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_NFT_PARSER_BISON_H_INCLUDED
# define YY_NFT_PARSER_BISON_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 1
#endif
#if YYDEBUG
extern int nft_debug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    TOKEN_EOF = 0,                 /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    JUNK = 258,                    /* "junk"  */
    NEWLINE = 259,                 /* "newline"  */
    COLON = 260,                   /* "colon"  */
    SEMICOLON = 261,               /* "semicolon"  */
    COMMA = 262,                   /* "comma"  */
    DOT = 263,                     /* "."  */
    EQ = 264,                      /* "=="  */
    NEQ = 265,                     /* "!="  */
    LT = 266,                      /* "<"  */
    GT = 267,                      /* ">"  */
    GTE = 268,                     /* ">="  */
    LTE = 269,                     /* "<="  */
    LSHIFT = 270,                  /* "<<"  */
    RSHIFT = 271,                  /* ">>"  */
    AMPERSAND = 272,               /* "&"  */
    CARET = 273,                   /* "^"  */
    NOT = 274,                     /* "!"  */
    SLASH = 275,                   /* "/"  */
    ASTERISK = 276,                /* "*"  */
    DASH = 277,                    /* "-"  */
    AT = 278,                      /* "@"  */
    VMAP = 279,                    /* "vmap"  */
    PLUS = 280,                    /* "+"  */
    INCLUDE = 281,                 /* "include"  */
    DEFINE = 282,                  /* "define"  */
    REDEFINE = 283,                /* "redefine"  */
    UNDEFINE = 284,                /* "undefine"  */
    FIB = 285,                     /* "fib"  */
    SOCKET = 286,                  /* "socket"  */
    TRANSPARENT = 287,             /* "transparent"  */
    WILDCARD = 288,                /* "wildcard"  */
    CGROUPV2 = 289,                /* "cgroupv2"  */
    TPROXY = 290,                  /* "tproxy"  */
    OSF = 291,                     /* "osf"  */
    SYNPROXY = 292,                /* "synproxy"  */
    MSS = 293,                     /* "mss"  */
    WSCALE = 294,                  /* "wscale"  */
    TYPEOF = 295,                  /* "typeof"  */
    HOOK = 296,                    /* "hook"  */
    HOOKS = 297,                   /* "hooks"  */
    DEVICE = 298,                  /* "device"  */
    DEVICES = 299,                 /* "devices"  */
    TABLE = 300,                   /* "table"  */
    TABLES = 301,                  /* "tables"  */
    CHAIN = 302,                   /* "chain"  */
    CHAINS = 303,                  /* "chains"  */
    RULE = 304,                    /* "rule"  */
    RULES = 305,                   /* "rules"  */
    SETS = 306,                    /* "sets"  */
    SET = 307,                     /* "set"  */
    ELEMENT = 308,                 /* "element"  */
    MAP = 309,                     /* "map"  */
    MAPS = 310,                    /* "maps"  */
    FLOWTABLE = 311,               /* "flowtable"  */
    HANDLE = 312,                  /* "handle"  */
    RULESET = 313,                 /* "ruleset"  */
    TRACE = 314,                   /* "trace"  */
    INET = 315,                    /* "inet"  */
    NETDEV = 316,                  /* "netdev"  */
    ADD = 317,                     /* "add"  */
    UPDATE = 318,                  /* "update"  */
    REPLACE = 319,                 /* "replace"  */
    CREATE = 320,                  /* "create"  */
    INSERT = 321,                  /* "insert"  */
    DELETE = 322,                  /* "delete"  */
    GET = 323,                     /* "get"  */
    LIST = 324,                    /* "list"  */
    RESET = 325,                   /* "reset"  */
    FLUSH = 326,                   /* "flush"  */
    RENAME = 327,                  /* "rename"  */
    DESCRIBE = 328,                /* "describe"  */
    IMPORT = 329,                  /* "import"  */
    EXPORT = 330,                  /* "export"  */
    MONITOR = 331,                 /* "monitor"  */
    ALL = 332,                     /* "all"  */
    ACCEPT = 333,                  /* "accept"  */
    DROP = 334,                    /* "drop"  */
    CONTINUE = 335,                /* "continue"  */
    JUMP = 336,                    /* "jump"  */
    GOTO = 337,                    /* "goto"  */
    RETURN = 338,                  /* "return"  */
    TO = 339,                      /* "to"  */
    CONSTANT = 340,                /* "constant"  */
    INTERVAL = 341,                /* "interval"  */
    DYNAMIC = 342,                 /* "dynamic"  */
    AUTOMERGE = 343,               /* "auto-merge"  */
    TIMEOUT = 344,                 /* "timeout"  */
    GC_INTERVAL = 345,             /* "gc-interval"  */
    ELEMENTS = 346,                /* "elements"  */
    EXPIRES = 347,                 /* "expires"  */
    POLICY = 348,                  /* "policy"  */
    MEMORY = 349,                  /* "memory"  */
    PERFORMANCE = 350,             /* "performance"  */
    SIZE = 351,                    /* "size"  */
    FLOW = 352,                    /* "flow"  */
    OFFLOAD = 353,                 /* "offload"  */
    METER = 354,                   /* "meter"  */
    METERS = 355,                  /* "meters"  */
    FLOWTABLES = 356,              /* "flowtables"  */
    NUM = 357,                     /* "number"  */
    STRING = 358,                  /* "string"  */
    QUOTED_STRING = 359,           /* "quoted string"  */
    ASTERISK_STRING = 360,         /* "string with a trailing asterisk"  */
    LL_HDR = 361,                  /* "ll"  */
    NETWORK_HDR = 362,             /* "nh"  */
    TRANSPORT_HDR = 363,           /* "th"  */
    BRIDGE = 364,                  /* "bridge"  */
    ETHER = 365,                   /* "ether"  */
    SADDR = 366,                   /* "saddr"  */
    DADDR = 367,                   /* "daddr"  */
    TYPE = 368,                    /* "type"  */
    VLAN = 369,                    /* "vlan"  */
    ID = 370,                      /* "id"  */
    CFI = 371,                     /* "cfi"  */
    DEI = 372,                     /* "dei"  */
    PCP = 373,                     /* "pcp"  */
    ARP = 374,                     /* "arp"  */
    HTYPE = 375,                   /* "htype"  */
    PTYPE = 376,                   /* "ptype"  */
    HLEN = 377,                    /* "hlen"  */
    PLEN = 378,                    /* "plen"  */
    OPERATION = 379,               /* "operation"  */
    IP = 380,                      /* "ip"  */
    HDRVERSION = 381,              /* "version"  */
    HDRLENGTH = 382,               /* "hdrlength"  */
    DSCP = 383,                    /* "dscp"  */
    ECN = 384,                     /* "ecn"  */
    LENGTH = 385,                  /* "length"  */
    FRAG_OFF = 386,                /* "frag-off"  */
    TTL = 387,                     /* "ttl"  */
    PROTOCOL = 388,                /* "protocol"  */
    CHECKSUM = 389,                /* "checksum"  */
    PTR = 390,                     /* "ptr"  */
    VALUE = 391,                   /* "value"  */
    LSRR = 392,                    /* "lsrr"  */
    RR = 393,                      /* "rr"  */
    SSRR = 394,                    /* "ssrr"  */
    RA = 395,                      /* "ra"  */
    ICMP = 396,                    /* "icmp"  */
    CODE = 397,                    /* "code"  */
    SEQUENCE = 398,                /* "seq"  */
    GATEWAY = 399,                 /* "gateway"  */
    MTU = 400,                     /* "mtu"  */
    IGMP = 401,                    /* "igmp"  */
    MRT = 402,                     /* "mrt"  */
    OPTIONS = 403,                 /* "options"  */
    IP6 = 404,                     /* "ip6"  */
    PRIORITY = 405,                /* "priority"  */
    FLOWLABEL = 406,               /* "flowlabel"  */
    NEXTHDR = 407,                 /* "nexthdr"  */
    HOPLIMIT = 408,                /* "hoplimit"  */
    ICMP6 = 409,                   /* "icmpv6"  */
    PPTR = 410,                    /* "param-problem"  */
    MAXDELAY = 411,                /* "max-delay"  */
    AH = 412,                      /* "ah"  */
    RESERVED = 413,                /* "reserved"  */
    SPI = 414,                     /* "spi"  */
    ESP = 415,                     /* "esp"  */
    COMP = 416,                    /* "comp"  */
    FLAGS = 417,                   /* "flags"  */
    CPI = 418,                     /* "cpi"  */
    PORT = 419,                    /* "port"  */
    UDP = 420,                     /* "udp"  */
    SPORT = 421,                   /* "sport"  */
    DPORT = 422,                   /* "dport"  */
    UDPLITE = 423,                 /* "udplite"  */
    CSUMCOV = 424,                 /* "csumcov"  */
    TCP = 425,                     /* "tcp"  */
    ACKSEQ = 426,                  /* "ackseq"  */
    DOFF = 427,                    /* "doff"  */
    WINDOW = 428,                  /* "window"  */
    URGPTR = 429,                  /* "urgptr"  */
    OPTION = 430,                  /* "option"  */
    ECHO = 431,                    /* "echo"  */
    EOL = 432,                     /* "eol"  */
    MPTCP = 433,                   /* "mptcp"  */
    NOP = 434,                     /* "nop"  */
    SACK = 435,                    /* "sack"  */
    SACK0 = 436,                   /* "sack0"  */
    SACK1 = 437,                   /* "sack1"  */
    SACK2 = 438,                   /* "sack2"  */
    SACK3 = 439,                   /* "sack3"  */
    SACK_PERM = 440,               /* "sack-permitted"  */
    FASTOPEN = 441,                /* "fastopen"  */
    MD5SIG = 442,                  /* "md5sig"  */
    TIMESTAMP = 443,               /* "timestamp"  */
    COUNT = 444,                   /* "count"  */
    LEFT = 445,                    /* "left"  */
    RIGHT = 446,                   /* "right"  */
    TSVAL = 447,                   /* "tsval"  */
    TSECR = 448,                   /* "tsecr"  */
    SUBTYPE = 449,                 /* "subtype"  */
    DCCP = 450,                    /* "dccp"  */
    SCTP = 451,                    /* "sctp"  */
    CHUNK = 452,                   /* "chunk"  */
    DATA = 453,                    /* "data"  */
    INIT = 454,                    /* "init"  */
    INIT_ACK = 455,                /* "init-ack"  */
    HEARTBEAT = 456,               /* "heartbeat"  */
    HEARTBEAT_ACK = 457,           /* "heartbeat-ack"  */
    ABORT = 458,                   /* "abort"  */
    SHUTDOWN = 459,                /* "shutdown"  */
    SHUTDOWN_ACK = 460,            /* "shutdown-ack"  */
    ERROR = 461,                   /* "error"  */
    COOKIE_ECHO = 462,             /* "cookie-echo"  */
    COOKIE_ACK = 463,              /* "cookie-ack"  */
    ECNE = 464,                    /* "ecne"  */
    CWR = 465,                     /* "cwr"  */
    SHUTDOWN_COMPLETE = 466,       /* "shutdown-complete"  */
    ASCONF_ACK = 467,              /* "asconf-ack"  */
    FORWARD_TSN = 468,             /* "forward-tsn"  */
    ASCONF = 469,                  /* "asconf"  */
    TSN = 470,                     /* "tsn"  */
    STREAM = 471,                  /* "stream"  */
    SSN = 472,                     /* "ssn"  */
    PPID = 473,                    /* "ppid"  */
    INIT_TAG = 474,                /* "init-tag"  */
    A_RWND = 475,                  /* "a-rwnd"  */
    NUM_OSTREAMS = 476,            /* "num-outbound-streams"  */
    NUM_ISTREAMS = 477,            /* "num-inbound-streams"  */
    INIT_TSN = 478,                /* "initial-tsn"  */
    CUM_TSN_ACK = 479,             /* "cum-tsn-ack"  */
    NUM_GACK_BLOCKS = 480,         /* "num-gap-ack-blocks"  */
    NUM_DUP_TSNS = 481,            /* "num-dup-tsns"  */
    LOWEST_TSN = 482,              /* "lowest-tsn"  */
    SEQNO = 483,                   /* "seqno"  */
    NEW_CUM_TSN = 484,             /* "new-cum-tsn"  */
    VTAG = 485,                    /* "vtag"  */
    RT = 486,                      /* "rt"  */
    RT0 = 487,                     /* "rt0"  */
    RT2 = 488,                     /* "rt2"  */
    RT4 = 489,                     /* "srh"  */
    SEG_LEFT = 490,                /* "seg-left"  */
    ADDR = 491,                    /* "addr"  */
    LAST_ENT = 492,                /* "last-entry"  */
    TAG = 493,                     /* "tag"  */
    SID = 494,                     /* "sid"  */
    HBH = 495,                     /* "hbh"  */
    FRAG = 496,                    /* "frag"  */
    RESERVED2 = 497,               /* "reserved2"  */
    MORE_FRAGMENTS = 498,          /* "more-fragments"  */
    DST = 499,                     /* "dst"  */
    MH = 500,                      /* "mh"  */
    META = 501,                    /* "meta"  */
    MARK = 502,                    /* "mark"  */
    IIF = 503,                     /* "iif"  */
    IIFNAME = 504,                 /* "iifname"  */
    IIFTYPE = 505,                 /* "iiftype"  */
    OIF = 506,                     /* "oif"  */
    OIFNAME = 507,                 /* "oifname"  */
    OIFTYPE = 508,                 /* "oiftype"  */
    SKUID = 509,                   /* "skuid"  */
    SKGID = 510,                   /* "skgid"  */
    NFTRACE = 511,                 /* "nftrace"  */
    RTCLASSID = 512,               /* "rtclassid"  */
    IBRIPORT = 513,                /* "ibriport"  */
    OBRIPORT = 514,                /* "obriport"  */
    IBRIDGENAME = 515,             /* "ibrname"  */
    OBRIDGENAME = 516,             /* "obrname"  */
    PKTTYPE = 517,                 /* "pkttype"  */
    CPU = 518,                     /* "cpu"  */
    IIFGROUP = 519,                /* "iifgroup"  */
    OIFGROUP = 520,                /* "oifgroup"  */
    CGROUP = 521,                  /* "cgroup"  */
    TIME = 522,                    /* "time"  */
    CLASSID = 523,                 /* "classid"  */
    NEXTHOP = 524,                 /* "nexthop"  */
    CT = 525,                      /* "ct"  */
    L3PROTOCOL = 526,              /* "l3proto"  */
    PROTO_SRC = 527,               /* "proto-src"  */
    PROTO_DST = 528,               /* "proto-dst"  */
    ZONE = 529,                    /* "zone"  */
    DIRECTION = 530,               /* "direction"  */
    EVENT = 531,                   /* "event"  */
    EXPECTATION = 532,             /* "expectation"  */
    EXPIRATION = 533,              /* "expiration"  */
    HELPER = 534,                  /* "helper"  */
    LABEL = 535,                   /* "label"  */
    STATE = 536,                   /* "state"  */
    STATUS = 537,                  /* "status"  */
    ORIGINAL = 538,                /* "original"  */
    REPLY = 539,                   /* "reply"  */
    COUNTER = 540,                 /* "counter"  */
    NAME = 541,                    /* "name"  */
    PACKETS = 542,                 /* "packets"  */
    BYTES = 543,                   /* "bytes"  */
    AVGPKT = 544,                  /* "avgpkt"  */
    COUNTERS = 545,                /* "counters"  */
    QUOTAS = 546,                  /* "quotas"  */
    LIMITS = 547,                  /* "limits"  */
    SYNPROXYS = 548,               /* "synproxys"  */
    HELPERS = 549,                 /* "helpers"  */
    LOG = 550,                     /* "log"  */
    PREFIX = 551,                  /* "prefix"  */
    GROUP = 552,                   /* "group"  */
    SNAPLEN = 553,                 /* "snaplen"  */
    QUEUE_THRESHOLD = 554,         /* "queue-threshold"  */
    LEVEL = 555,                   /* "level"  */
    LIMIT = 556,                   /* "limit"  */
    RATE = 557,                    /* "rate"  */
    BURST = 558,                   /* "burst"  */
    OVER = 559,                    /* "over"  */
    UNTIL = 560,                   /* "until"  */
    QUOTA = 561,                   /* "quota"  */
    USED = 562,                    /* "used"  */
    SECMARK = 563,                 /* "secmark"  */
    SECMARKS = 564,                /* "secmarks"  */
    SECOND = 565,                  /* "second"  */
    MINUTE = 566,                  /* "minute"  */
    HOUR = 567,                    /* "hour"  */
    DAY = 568,                     /* "day"  */
    WEEK = 569,                    /* "week"  */
    _REJECT = 570,                 /* "reject"  */
    WITH = 571,                    /* "with"  */
    ICMPX = 572,                   /* "icmpx"  */
    SNAT = 573,                    /* "snat"  */
    DNAT = 574,                    /* "dnat"  */
    MASQUERADE = 575,              /* "masquerade"  */
    REDIRECT = 576,                /* "redirect"  */
    RANDOM = 577,                  /* "random"  */
    FULLY_RANDOM = 578,            /* "fully-random"  */
    PERSISTENT = 579,              /* "persistent"  */
    QUEUE = 580,                   /* "queue"  */
    QUEUENUM = 581,                /* "num"  */
    BYPASS = 582,                  /* "bypass"  */
    FANOUT = 583,                  /* "fanout"  */
    DUP = 584,                     /* "dup"  */
    FWD = 585,                     /* "fwd"  */
    NUMGEN = 586,                  /* "numgen"  */
    INC = 587,                     /* "inc"  */
    MOD = 588,                     /* "mod"  */
    OFFSET = 589,                  /* "offset"  */
    JHASH = 590,                   /* "jhash"  */
    SYMHASH = 591,                 /* "symhash"  */
    SEED = 592,                    /* "seed"  */
    POSITION = 593,                /* "position"  */
    INDEX = 594,                   /* "index"  */
    COMMENT = 595,                 /* "comment"  */
    XML = 596,                     /* "xml"  */
    JSON = 597,                    /* "json"  */
    VM = 598,                      /* "vm"  */
    NOTRACK = 599,                 /* "notrack"  */
    EXISTS = 600,                  /* "exists"  */
    MISSING = 601,                 /* "missing"  */
    EXTHDR = 602,                  /* "exthdr"  */
    IPSEC = 603,                   /* "ipsec"  */
    REQID = 604,                   /* "reqid"  */
    SPNUM = 605,                   /* "spnum"  */
    IN = 606,                      /* "in"  */
    OUT = 607                      /* "out"  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
#define TOKEN_EOF 0
#define YYerror 256
#define YYUNDEF 257
#define JUNK 258
#define NEWLINE 259
#define COLON 260
#define SEMICOLON 261
#define COMMA 262
#define DOT 263
#define EQ 264
#define NEQ 265
#define LT 266
#define GT 267
#define GTE 268
#define LTE 269
#define LSHIFT 270
#define RSHIFT 271
#define AMPERSAND 272
#define CARET 273
#define NOT 274
#define SLASH 275
#define ASTERISK 276
#define DASH 277
#define AT 278
#define VMAP 279
#define PLUS 280
#define INCLUDE 281
#define DEFINE 282
#define REDEFINE 283
#define UNDEFINE 284
#define FIB 285
#define SOCKET 286
#define TRANSPARENT 287
#define WILDCARD 288
#define CGROUPV2 289
#define TPROXY 290
#define OSF 291
#define SYNPROXY 292
#define MSS 293
#define WSCALE 294
#define TYPEOF 295
#define HOOK 296
#define HOOKS 297
#define DEVICE 298
#define DEVICES 299
#define TABLE 300
#define TABLES 301
#define CHAIN 302
#define CHAINS 303
#define RULE 304
#define RULES 305
#define SETS 306
#define SET 307
#define ELEMENT 308
#define MAP 309
#define MAPS 310
#define FLOWTABLE 311
#define HANDLE 312
#define RULESET 313
#define TRACE 314
#define INET 315
#define NETDEV 316
#define ADD 317
#define UPDATE 318
#define REPLACE 319
#define CREATE 320
#define INSERT 321
#define DELETE 322
#define GET 323
#define LIST 324
#define RESET 325
#define FLUSH 326
#define RENAME 327
#define DESCRIBE 328
#define IMPORT 329
#define EXPORT 330
#define MONITOR 331
#define ALL 332
#define ACCEPT 333
#define DROP 334
#define CONTINUE 335
#define JUMP 336
#define GOTO 337
#define RETURN 338
#define TO 339
#define CONSTANT 340
#define INTERVAL 341
#define DYNAMIC 342
#define AUTOMERGE 343
#define TIMEOUT 344
#define GC_INTERVAL 345
#define ELEMENTS 346
#define EXPIRES 347
#define POLICY 348
#define MEMORY 349
#define PERFORMANCE 350
#define SIZE 351
#define FLOW 352
#define OFFLOAD 353
#define METER 354
#define METERS 355
#define FLOWTABLES 356
#define NUM 357
#define STRING 358
#define QUOTED_STRING 359
#define ASTERISK_STRING 360
#define LL_HDR 361
#define NETWORK_HDR 362
#define TRANSPORT_HDR 363
#define BRIDGE 364
#define ETHER 365
#define SADDR 366
#define DADDR 367
#define TYPE 368
#define VLAN 369
#define ID 370
#define CFI 371
#define DEI 372
#define PCP 373
#define ARP 374
#define HTYPE 375
#define PTYPE 376
#define HLEN 377
#define PLEN 378
#define OPERATION 379
#define IP 380
#define HDRVERSION 381
#define HDRLENGTH 382
#define DSCP 383
#define ECN 384
#define LENGTH 385
#define FRAG_OFF 386
#define TTL 387
#define PROTOCOL 388
#define CHECKSUM 389
#define PTR 390
#define VALUE 391
#define LSRR 392
#define RR 393
#define SSRR 394
#define RA 395
#define ICMP 396
#define CODE 397
#define SEQUENCE 398
#define GATEWAY 399
#define MTU 400
#define IGMP 401
#define MRT 402
#define OPTIONS 403
#define IP6 404
#define PRIORITY 405
#define FLOWLABEL 406
#define NEXTHDR 407
#define HOPLIMIT 408
#define ICMP6 409
#define PPTR 410
#define MAXDELAY 411
#define AH 412
#define RESERVED 413
#define SPI 414
#define ESP 415
#define COMP 416
#define FLAGS 417
#define CPI 418
#define PORT 419
#define UDP 420
#define SPORT 421
#define DPORT 422
#define UDPLITE 423
#define CSUMCOV 424
#define TCP 425
#define ACKSEQ 426
#define DOFF 427
#define WINDOW 428
#define URGPTR 429
#define OPTION 430
#define ECHO 431
#define EOL 432
#define MPTCP 433
#define NOP 434
#define SACK 435
#define SACK0 436
#define SACK1 437
#define SACK2 438
#define SACK3 439
#define SACK_PERM 440
#define FASTOPEN 441
#define MD5SIG 442
#define TIMESTAMP 443
#define COUNT 444
#define LEFT 445
#define RIGHT 446
#define TSVAL 447
#define TSECR 448
#define SUBTYPE 449
#define DCCP 450
#define SCTP 451
#define CHUNK 452
#define DATA 453
#define INIT 454
#define INIT_ACK 455
#define HEARTBEAT 456
#define HEARTBEAT_ACK 457
#define ABORT 458
#define SHUTDOWN 459
#define SHUTDOWN_ACK 460
#define ERROR 461
#define COOKIE_ECHO 462
#define COOKIE_ACK 463
#define ECNE 464
#define CWR 465
#define SHUTDOWN_COMPLETE 466
#define ASCONF_ACK 467
#define FORWARD_TSN 468
#define ASCONF 469
#define TSN 470
#define STREAM 471
#define SSN 472
#define PPID 473
#define INIT_TAG 474
#define A_RWND 475
#define NUM_OSTREAMS 476
#define NUM_ISTREAMS 477
#define INIT_TSN 478
#define CUM_TSN_ACK 479
#define NUM_GACK_BLOCKS 480
#define NUM_DUP_TSNS 481
#define LOWEST_TSN 482
#define SEQNO 483
#define NEW_CUM_TSN 484
#define VTAG 485
#define RT 486
#define RT0 487
#define RT2 488
#define RT4 489
#define SEG_LEFT 490
#define ADDR 491
#define LAST_ENT 492
#define TAG 493
#define SID 494
#define HBH 495
#define FRAG 496
#define RESERVED2 497
#define MORE_FRAGMENTS 498
#define DST 499
#define MH 500
#define META 501
#define MARK 502
#define IIF 503
#define IIFNAME 504
#define IIFTYPE 505
#define OIF 506
#define OIFNAME 507
#define OIFTYPE 508
#define SKUID 509
#define SKGID 510
#define NFTRACE 511
#define RTCLASSID 512
#define IBRIPORT 513
#define OBRIPORT 514
#define IBRIDGENAME 515
#define OBRIDGENAME 516
#define PKTTYPE 517
#define CPU 518
#define IIFGROUP 519
#define OIFGROUP 520
#define CGROUP 521
#define TIME 522
#define CLASSID 523
#define NEXTHOP 524
#define CT 525
#define L3PROTOCOL 526
#define PROTO_SRC 527
#define PROTO_DST 528
#define ZONE 529
#define DIRECTION 530
#define EVENT 531
#define EXPECTATION 532
#define EXPIRATION 533
#define HELPER 534
#define LABEL 535
#define STATE 536
#define STATUS 537
#define ORIGINAL 538
#define REPLY 539
#define COUNTER 540
#define NAME 541
#define PACKETS 542
#define BYTES 543
#define AVGPKT 544
#define COUNTERS 545
#define QUOTAS 546
#define LIMITS 547
#define SYNPROXYS 548
#define HELPERS 549
#define LOG 550
#define PREFIX 551
#define GROUP 552
#define SNAPLEN 553
#define QUEUE_THRESHOLD 554
#define LEVEL 555
#define LIMIT 556
#define RATE 557
#define BURST 558
#define OVER 559
#define UNTIL 560
#define QUOTA 561
#define USED 562
#define SECMARK 563
#define SECMARKS 564
#define SECOND 565
#define MINUTE 566
#define HOUR 567
#define DAY 568
#define WEEK 569
#define _REJECT 570
#define WITH 571
#define ICMPX 572
#define SNAT 573
#define DNAT 574
#define MASQUERADE 575
#define REDIRECT 576
#define RANDOM 577
#define FULLY_RANDOM 578
#define PERSISTENT 579
#define QUEUE 580
#define QUEUENUM 581
#define BYPASS 582
#define FANOUT 583
#define DUP 584
#define FWD 585
#define NUMGEN 586
#define INC 587
#define MOD 588
#define OFFSET 589
#define JHASH 590
#define SYMHASH 591
#define SEED 592
#define POSITION 593
#define INDEX 594
#define COMMENT 595
#define XML 596
#define JSON 597
#define VM 598
#define NOTRACK 599
#define EXISTS 600
#define MISSING 601
#define EXTHDR 602
#define IPSEC 603
#define REQID 604
#define SPNUM 605
#define IN 606
#define OUT 607

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 167 "parser_bison.y"

	uint64_t		val;
	uint32_t		val32;
	uint8_t			val8;
	const char *		string;

	struct list_head	*list;
	struct cmd		*cmd;
	struct handle		handle;
	struct table		*table;
	struct chain		*chain;
	struct rule		*rule;
	struct stmt		*stmt;
	struct expr		*expr;
	struct set		*set;
	struct obj		*obj;
	struct flowtable	*flowtable;
	struct ct		*ct;
	const struct datatype	*datatype;
	struct handle_spec	handle_spec;
	struct position_spec	position_spec;
	struct prio_spec	prio_spec;
	struct limit_rate	limit_rate;
	struct tcp_kind_field {
		uint16_t kind; /* must allow > 255 for SACK1, 2.. hack */
		uint8_t field;
	} tcp_kind_field;

#line 998 "parser_bison.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif

/* Location type.  */
#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE YYLTYPE;
struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
};
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif



int nft_parse (struct nft_ctx *nft, void *scanner, struct parser_state *state);

#endif /* !YY_NFT_PARSER_BISON_H_INCLUDED  */
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_JUNK = 3,                       /* "junk"  */
  YYSYMBOL_NEWLINE = 4,                    /* "newline"  */
  YYSYMBOL_COLON = 5,                      /* "colon"  */
  YYSYMBOL_SEMICOLON = 6,                  /* "semicolon"  */
  YYSYMBOL_COMMA = 7,                      /* "comma"  */
  YYSYMBOL_DOT = 8,                        /* "."  */
  YYSYMBOL_EQ = 9,                         /* "=="  */
  YYSYMBOL_NEQ = 10,                       /* "!="  */
  YYSYMBOL_LT = 11,                        /* "<"  */
  YYSYMBOL_GT = 12,                        /* ">"  */
  YYSYMBOL_GTE = 13,                       /* ">="  */
  YYSYMBOL_LTE = 14,                       /* "<="  */
  YYSYMBOL_LSHIFT = 15,                    /* "<<"  */
  YYSYMBOL_RSHIFT = 16,                    /* ">>"  */
  YYSYMBOL_AMPERSAND = 17,                 /* "&"  */
  YYSYMBOL_CARET = 18,                     /* "^"  */
  YYSYMBOL_NOT = 19,                       /* "!"  */
  YYSYMBOL_SLASH = 20,                     /* "/"  */
  YYSYMBOL_ASTERISK = 21,                  /* "*"  */
  YYSYMBOL_DASH = 22,                      /* "-"  */
  YYSYMBOL_AT = 23,                        /* "@"  */
  YYSYMBOL_VMAP = 24,                      /* "vmap"  */
  YYSYMBOL_PLUS = 25,                      /* "+"  */
  YYSYMBOL_INCLUDE = 26,                   /* "include"  */
  YYSYMBOL_DEFINE = 27,                    /* "define"  */
  YYSYMBOL_REDEFINE = 28,                  /* "redefine"  */
  YYSYMBOL_UNDEFINE = 29,                  /* "undefine"  */
  YYSYMBOL_FIB = 30,                       /* "fib"  */
  YYSYMBOL_SOCKET = 31,                    /* "socket"  */
  YYSYMBOL_TRANSPARENT = 32,               /* "transparent"  */
  YYSYMBOL_WILDCARD = 33,                  /* "wildcard"  */
  YYSYMBOL_CGROUPV2 = 34,                  /* "cgroupv2"  */
  YYSYMBOL_TPROXY = 35,                    /* "tproxy"  */
  YYSYMBOL_OSF = 36,                       /* "osf"  */
  YYSYMBOL_SYNPROXY = 37,                  /* "synproxy"  */
  YYSYMBOL_MSS = 38,                       /* "mss"  */
  YYSYMBOL_WSCALE = 39,                    /* "wscale"  */
  YYSYMBOL_TYPEOF = 40,                    /* "typeof"  */
  YYSYMBOL_HOOK = 41,                      /* "hook"  */
  YYSYMBOL_HOOKS = 42,                     /* "hooks"  */
  YYSYMBOL_DEVICE = 43,                    /* "device"  */
  YYSYMBOL_DEVICES = 44,                   /* "devices"  */
  YYSYMBOL_TABLE = 45,                     /* "table"  */
  YYSYMBOL_TABLES = 46,                    /* "tables"  */
  YYSYMBOL_CHAIN = 47,                     /* "chain"  */
  YYSYMBOL_CHAINS = 48,                    /* "chains"  */
  YYSYMBOL_RULE = 49,                      /* "rule"  */
  YYSYMBOL_RULES = 50,                     /* "rules"  */
  YYSYMBOL_SETS = 51,                      /* "sets"  */
  YYSYMBOL_SET = 52,                       /* "set"  */
  YYSYMBOL_ELEMENT = 53,                   /* "element"  */
  YYSYMBOL_MAP = 54,                       /* "map"  */
  YYSYMBOL_MAPS = 55,                      /* "maps"  */
  YYSYMBOL_FLOWTABLE = 56,                 /* "flowtable"  */
  YYSYMBOL_HANDLE = 57,                    /* "handle"  */
  YYSYMBOL_RULESET = 58,                   /* "ruleset"  */
  YYSYMBOL_TRACE = 59,                     /* "trace"  */
  YYSYMBOL_INET = 60,                      /* "inet"  */
  YYSYMBOL_NETDEV = 61,                    /* "netdev"  */
  YYSYMBOL_ADD = 62,                       /* "add"  */
  YYSYMBOL_UPDATE = 63,                    /* "update"  */
  YYSYMBOL_REPLACE = 64,                   /* "replace"  */
  YYSYMBOL_CREATE = 65,                    /* "create"  */
  YYSYMBOL_INSERT = 66,                    /* "insert"  */
  YYSYMBOL_DELETE = 67,                    /* "delete"  */
  YYSYMBOL_GET = 68,                       /* "get"  */
  YYSYMBOL_LIST = 69,                      /* "list"  */
  YYSYMBOL_RESET = 70,                     /* "reset"  */
  YYSYMBOL_FLUSH = 71,                     /* "flush"  */
  YYSYMBOL_RENAME = 72,                    /* "rename"  */
  YYSYMBOL_DESCRIBE = 73,                  /* "describe"  */
  YYSYMBOL_IMPORT = 74,                    /* "import"  */
  YYSYMBOL_EXPORT = 75,                    /* "export"  */
  YYSYMBOL_MONITOR = 76,                   /* "monitor"  */
  YYSYMBOL_ALL = 77,                       /* "all"  */
  YYSYMBOL_ACCEPT = 78,                    /* "accept"  */
  YYSYMBOL_DROP = 79,                      /* "drop"  */
  YYSYMBOL_CONTINUE = 80,                  /* "continue"  */
  YYSYMBOL_JUMP = 81,                      /* "jump"  */
  YYSYMBOL_GOTO = 82,                      /* "goto"  */
  YYSYMBOL_RETURN = 83,                    /* "return"  */
  YYSYMBOL_TO = 84,                        /* "to"  */
  YYSYMBOL_CONSTANT = 85,                  /* "constant"  */
  YYSYMBOL_INTERVAL = 86,                  /* "interval"  */
  YYSYMBOL_DYNAMIC = 87,                   /* "dynamic"  */
  YYSYMBOL_AUTOMERGE = 88,                 /* "auto-merge"  */
  YYSYMBOL_TIMEOUT = 89,                   /* "timeout"  */
  YYSYMBOL_GC_INTERVAL = 90,               /* "gc-interval"  */
  YYSYMBOL_ELEMENTS = 91,                  /* "elements"  */
  YYSYMBOL_EXPIRES = 92,                   /* "expires"  */
  YYSYMBOL_POLICY = 93,                    /* "policy"  */
  YYSYMBOL_MEMORY = 94,                    /* "memory"  */
  YYSYMBOL_PERFORMANCE = 95,               /* "performance"  */
  YYSYMBOL_SIZE = 96,                      /* "size"  */
  YYSYMBOL_FLOW = 97,                      /* "flow"  */
  YYSYMBOL_OFFLOAD = 98,                   /* "offload"  */
  YYSYMBOL_METER = 99,                     /* "meter"  */
  YYSYMBOL_METERS = 100,                   /* "meters"  */
  YYSYMBOL_FLOWTABLES = 101,               /* "flowtables"  */
  YYSYMBOL_NUM = 102,                      /* "number"  */
  YYSYMBOL_STRING = 103,                   /* "string"  */
  YYSYMBOL_QUOTED_STRING = 104,            /* "quoted string"  */
  YYSYMBOL_ASTERISK_STRING = 105,          /* "string with a trailing asterisk"  */
  YYSYMBOL_LL_HDR = 106,                   /* "ll"  */
  YYSYMBOL_NETWORK_HDR = 107,              /* "nh"  */
  YYSYMBOL_TRANSPORT_HDR = 108,            /* "th"  */
  YYSYMBOL_BRIDGE = 109,                   /* "bridge"  */
  YYSYMBOL_ETHER = 110,                    /* "ether"  */
  YYSYMBOL_SADDR = 111,                    /* "saddr"  */
  YYSYMBOL_DADDR = 112,                    /* "daddr"  */
  YYSYMBOL_TYPE = 113,                     /* "type"  */
  YYSYMBOL_VLAN = 114,                     /* "vlan"  */
  YYSYMBOL_ID = 115,                       /* "id"  */
  YYSYMBOL_CFI = 116,                      /* "cfi"  */
  YYSYMBOL_DEI = 117,                      /* "dei"  */
  YYSYMBOL_PCP = 118,                      /* "pcp"  */
  YYSYMBOL_ARP = 119,                      /* "arp"  */
  YYSYMBOL_HTYPE = 120,                    /* "htype"  */
  YYSYMBOL_PTYPE = 121,                    /* "ptype"  */
  YYSYMBOL_HLEN = 122,                     /* "hlen"  */
  YYSYMBOL_PLEN = 123,                     /* "plen"  */
  YYSYMBOL_OPERATION = 124,                /* "operation"  */
  YYSYMBOL_IP = 125,                       /* "ip"  */
  YYSYMBOL_HDRVERSION = 126,               /* "version"  */
  YYSYMBOL_HDRLENGTH = 127,                /* "hdrlength"  */
  YYSYMBOL_DSCP = 128,                     /* "dscp"  */
  YYSYMBOL_ECN = 129,                      /* "ecn"  */
  YYSYMBOL_LENGTH = 130,                   /* "length"  */
  YYSYMBOL_FRAG_OFF = 131,                 /* "frag-off"  */
  YYSYMBOL_TTL = 132,                      /* "ttl"  */
  YYSYMBOL_PROTOCOL = 133,                 /* "protocol"  */
  YYSYMBOL_CHECKSUM = 134,                 /* "checksum"  */
  YYSYMBOL_PTR = 135,                      /* "ptr"  */
  YYSYMBOL_VALUE = 136,                    /* "value"  */
  YYSYMBOL_LSRR = 137,                     /* "lsrr"  */
  YYSYMBOL_RR = 138,                       /* "rr"  */
  YYSYMBOL_SSRR = 139,                     /* "ssrr"  */
  YYSYMBOL_RA = 140,                       /* "ra"  */
  YYSYMBOL_ICMP = 141,                     /* "icmp"  */
  YYSYMBOL_CODE = 142,                     /* "code"  */
  YYSYMBOL_SEQUENCE = 143,                 /* "seq"  */
  YYSYMBOL_GATEWAY = 144,                  /* "gateway"  */
  YYSYMBOL_MTU = 145,                      /* "mtu"  */
  YYSYMBOL_IGMP = 146,                     /* "igmp"  */
  YYSYMBOL_MRT = 147,                      /* "mrt"  */
  YYSYMBOL_OPTIONS = 148,                  /* "options"  */
  YYSYMBOL_IP6 = 149,                      /* "ip6"  */
  YYSYMBOL_PRIORITY = 150,                 /* "priority"  */
  YYSYMBOL_FLOWLABEL = 151,                /* "flowlabel"  */
  YYSYMBOL_NEXTHDR = 152,                  /* "nexthdr"  */
  YYSYMBOL_HOPLIMIT = 153,                 /* "hoplimit"  */
  YYSYMBOL_ICMP6 = 154,                    /* "icmpv6"  */
  YYSYMBOL_PPTR = 155,                     /* "param-problem"  */
  YYSYMBOL_MAXDELAY = 156,                 /* "max-delay"  */
  YYSYMBOL_AH = 157,                       /* "ah"  */
  YYSYMBOL_RESERVED = 158,                 /* "reserved"  */
  YYSYMBOL_SPI = 159,                      /* "spi"  */
  YYSYMBOL_ESP = 160,                      /* "esp"  */
  YYSYMBOL_COMP = 161,                     /* "comp"  */
  YYSYMBOL_FLAGS = 162,                    /* "flags"  */
  YYSYMBOL_CPI = 163,                      /* "cpi"  */
  YYSYMBOL_PORT = 164,                     /* "port"  */
  YYSYMBOL_UDP = 165,                      /* "udp"  */
  YYSYMBOL_SPORT = 166,                    /* "sport"  */
  YYSYMBOL_DPORT = 167,                    /* "dport"  */
  YYSYMBOL_UDPLITE = 168,                  /* "udplite"  */
  YYSYMBOL_CSUMCOV = 169,                  /* "csumcov"  */
  YYSYMBOL_TCP = 170,                      /* "tcp"  */
  YYSYMBOL_ACKSEQ = 171,                   /* "ackseq"  */
  YYSYMBOL_DOFF = 172,                     /* "doff"  */
  YYSYMBOL_WINDOW = 173,                   /* "window"  */
  YYSYMBOL_URGPTR = 174,                   /* "urgptr"  */
  YYSYMBOL_OPTION = 175,                   /* "option"  */
  YYSYMBOL_ECHO = 176,                     /* "echo"  */
  YYSYMBOL_EOL = 177,                      /* "eol"  */
  YYSYMBOL_MPTCP = 178,                    /* "mptcp"  */
  YYSYMBOL_NOP = 179,                      /* "nop"  */
  YYSYMBOL_SACK = 180,                     /* "sack"  */
  YYSYMBOL_SACK0 = 181,                    /* "sack0"  */
  YYSYMBOL_SACK1 = 182,                    /* "sack1"  */
  YYSYMBOL_SACK2 = 183,                    /* "sack2"  */
  YYSYMBOL_SACK3 = 184,                    /* "sack3"  */
  YYSYMBOL_SACK_PERM = 185,                /* "sack-permitted"  */
  YYSYMBOL_FASTOPEN = 186,                 /* "fastopen"  */
  YYSYMBOL_MD5SIG = 187,                   /* "md5sig"  */
  YYSYMBOL_TIMESTAMP = 188,                /* "timestamp"  */
  YYSYMBOL_COUNT = 189,                    /* "count"  */
  YYSYMBOL_LEFT = 190,                     /* "left"  */
  YYSYMBOL_RIGHT = 191,                    /* "right"  */
  YYSYMBOL_TSVAL = 192,                    /* "tsval"  */
  YYSYMBOL_TSECR = 193,                    /* "tsecr"  */
  YYSYMBOL_SUBTYPE = 194,                  /* "subtype"  */
  YYSYMBOL_DCCP = 195,                     /* "dccp"  */
  YYSYMBOL_SCTP = 196,                     /* "sctp"  */
  YYSYMBOL_CHUNK = 197,                    /* "chunk"  */
  YYSYMBOL_DATA = 198,                     /* "data"  */
  YYSYMBOL_INIT = 199,                     /* "init"  */
  YYSYMBOL_INIT_ACK = 200,                 /* "init-ack"  */
  YYSYMBOL_HEARTBEAT = 201,                /* "heartbeat"  */
  YYSYMBOL_HEARTBEAT_ACK = 202,            /* "heartbeat-ack"  */
  YYSYMBOL_ABORT = 203,                    /* "abort"  */
  YYSYMBOL_SHUTDOWN = 204,                 /* "shutdown"  */
  YYSYMBOL_SHUTDOWN_ACK = 205,             /* "shutdown-ack"  */
  YYSYMBOL_ERROR = 206,                    /* "error"  */
  YYSYMBOL_COOKIE_ECHO = 207,              /* "cookie-echo"  */
  YYSYMBOL_COOKIE_ACK = 208,               /* "cookie-ack"  */
  YYSYMBOL_ECNE = 209,                     /* "ecne"  */
  YYSYMBOL_CWR = 210,                      /* "cwr"  */
  YYSYMBOL_SHUTDOWN_COMPLETE = 211,        /* "shutdown-complete"  */
  YYSYMBOL_ASCONF_ACK = 212,               /* "asconf-ack"  */
  YYSYMBOL_FORWARD_TSN = 213,              /* "forward-tsn"  */
  YYSYMBOL_ASCONF = 214,                   /* "asconf"  */
  YYSYMBOL_TSN = 215,                      /* "tsn"  */
  YYSYMBOL_STREAM = 216,                   /* "stream"  */
  YYSYMBOL_SSN = 217,                      /* "ssn"  */
  YYSYMBOL_PPID = 218,                     /* "ppid"  */
  YYSYMBOL_INIT_TAG = 219,                 /* "init-tag"  */
  YYSYMBOL_A_RWND = 220,                   /* "a-rwnd"  */
  YYSYMBOL_NUM_OSTREAMS = 221,             /* "num-outbound-streams"  */
  YYSYMBOL_NUM_ISTREAMS = 222,             /* "num-inbound-streams"  */
  YYSYMBOL_INIT_TSN = 223,                 /* "initial-tsn"  */
  YYSYMBOL_CUM_TSN_ACK = 224,              /* "cum-tsn-ack"  */
  YYSYMBOL_NUM_GACK_BLOCKS = 225,          /* "num-gap-ack-blocks"  */
  YYSYMBOL_NUM_DUP_TSNS = 226,             /* "num-dup-tsns"  */
  YYSYMBOL_LOWEST_TSN = 227,               /* "lowest-tsn"  */
  YYSYMBOL_SEQNO = 228,                    /* "seqno"  */
  YYSYMBOL_NEW_CUM_TSN = 229,              /* "new-cum-tsn"  */
  YYSYMBOL_VTAG = 230,                     /* "vtag"  */
  YYSYMBOL_RT = 231,                       /* "rt"  */
  YYSYMBOL_RT0 = 232,                      /* "rt0"  */
  YYSYMBOL_RT2 = 233,                      /* "rt2"  */
  YYSYMBOL_RT4 = 234,                      /* "srh"  */
  YYSYMBOL_SEG_LEFT = 235,                 /* "seg-left"  */
  YYSYMBOL_ADDR = 236,                     /* "addr"  */
  YYSYMBOL_LAST_ENT = 237,                 /* "last-entry"  */
  YYSYMBOL_TAG = 238,                      /* "tag"  */
  YYSYMBOL_SID = 239,                      /* "sid"  */
  YYSYMBOL_HBH = 240,                      /* "hbh"  */
  YYSYMBOL_FRAG = 241,                     /* "frag"  */
  YYSYMBOL_RESERVED2 = 242,                /* "reserved2"  */
  YYSYMBOL_MORE_FRAGMENTS = 243,           /* "more-fragments"  */
  YYSYMBOL_DST = 244,                      /* "dst"  */
  YYSYMBOL_MH = 245,                       /* "mh"  */
  YYSYMBOL_META = 246,                     /* "meta"  */
  YYSYMBOL_MARK = 247,                     /* "mark"  */
  YYSYMBOL_IIF = 248,                      /* "iif"  */
  YYSYMBOL_IIFNAME = 249,                  /* "iifname"  */
  YYSYMBOL_IIFTYPE = 250,                  /* "iiftype"  */
  YYSYMBOL_OIF = 251,                      /* "oif"  */
  YYSYMBOL_OIFNAME = 252,                  /* "oifname"  */
  YYSYMBOL_OIFTYPE = 253,                  /* "oiftype"  */
  YYSYMBOL_SKUID = 254,                    /* "skuid"  */
  YYSYMBOL_SKGID = 255,                    /* "skgid"  */
  YYSYMBOL_NFTRACE = 256,                  /* "nftrace"  */
  YYSYMBOL_RTCLASSID = 257,                /* "rtclassid"  */
  YYSYMBOL_IBRIPORT = 258,                 /* "ibriport"  */
  YYSYMBOL_OBRIPORT = 259,                 /* "obriport"  */
  YYSYMBOL_IBRIDGENAME = 260,              /* "ibrname"  */
  YYSYMBOL_OBRIDGENAME = 261,              /* "obrname"  */
  YYSYMBOL_PKTTYPE = 262,                  /* "pkttype"  */
  YYSYMBOL_CPU = 263,                      /* "cpu"  */
  YYSYMBOL_IIFGROUP = 264,                 /* "iifgroup"  */
  YYSYMBOL_OIFGROUP = 265,                 /* "oifgroup"  */
  YYSYMBOL_CGROUP = 266,                   /* "cgroup"  */
  YYSYMBOL_TIME = 267,                     /* "time"  */
  YYSYMBOL_CLASSID = 268,                  /* "classid"  */
  YYSYMBOL_NEXTHOP = 269,                  /* "nexthop"  */
  YYSYMBOL_CT = 270,                       /* "ct"  */
  YYSYMBOL_L3PROTOCOL = 271,               /* "l3proto"  */
  YYSYMBOL_PROTO_SRC = 272,                /* "proto-src"  */
  YYSYMBOL_PROTO_DST = 273,                /* "proto-dst"  */
  YYSYMBOL_ZONE = 274,                     /* "zone"  */
  YYSYMBOL_DIRECTION = 275,                /* "direction"  */
  YYSYMBOL_EVENT = 276,                    /* "event"  */
  YYSYMBOL_EXPECTATION = 277,              /* "expectation"  */
  YYSYMBOL_EXPIRATION = 278,               /* "expiration"  */
  YYSYMBOL_HELPER = 279,                   /* "helper"  */
  YYSYMBOL_LABEL = 280,                    /* "label"  */
  YYSYMBOL_STATE = 281,                    /* "state"  */
  YYSYMBOL_STATUS = 282,                   /* "status"  */
  YYSYMBOL_ORIGINAL = 283,                 /* "original"  */
  YYSYMBOL_REPLY = 284,                    /* "reply"  */
  YYSYMBOL_COUNTER = 285,                  /* "counter"  */
  YYSYMBOL_NAME = 286,                     /* "name"  */
  YYSYMBOL_PACKETS = 287,                  /* "packets"  */
  YYSYMBOL_BYTES = 288,                    /* "bytes"  */
  YYSYMBOL_AVGPKT = 289,                   /* "avgpkt"  */
  YYSYMBOL_COUNTERS = 290,                 /* "counters"  */
  YYSYMBOL_QUOTAS = 291,                   /* "quotas"  */
  YYSYMBOL_LIMITS = 292,                   /* "limits"  */
  YYSYMBOL_SYNPROXYS = 293,                /* "synproxys"  */
  YYSYMBOL_HELPERS = 294,                  /* "helpers"  */
  YYSYMBOL_LOG = 295,                      /* "log"  */
  YYSYMBOL_PREFIX = 296,                   /* "prefix"  */
  YYSYMBOL_GROUP = 297,                    /* "group"  */
  YYSYMBOL_SNAPLEN = 298,                  /* "snaplen"  */
  YYSYMBOL_QUEUE_THRESHOLD = 299,          /* "queue-threshold"  */
  YYSYMBOL_LEVEL = 300,                    /* "level"  */
  YYSYMBOL_LIMIT = 301,                    /* "limit"  */
  YYSYMBOL_RATE = 302,                     /* "rate"  */
  YYSYMBOL_BURST = 303,                    /* "burst"  */
  YYSYMBOL_OVER = 304,                     /* "over"  */
  YYSYMBOL_UNTIL = 305,                    /* "until"  */
  YYSYMBOL_QUOTA = 306,                    /* "quota"  */
  YYSYMBOL_USED = 307,                     /* "used"  */
  YYSYMBOL_SECMARK = 308,                  /* "secmark"  */
  YYSYMBOL_SECMARKS = 309,                 /* "secmarks"  */
  YYSYMBOL_SECOND = 310,                   /* "second"  */
  YYSYMBOL_MINUTE = 311,                   /* "minute"  */
  YYSYMBOL_HOUR = 312,                     /* "hour"  */
  YYSYMBOL_DAY = 313,                      /* "day"  */
  YYSYMBOL_WEEK = 314,                     /* "week"  */
  YYSYMBOL__REJECT = 315,                  /* "reject"  */
  YYSYMBOL_WITH = 316,                     /* "with"  */
  YYSYMBOL_ICMPX = 317,                    /* "icmpx"  */
  YYSYMBOL_SNAT = 318,                     /* "snat"  */
  YYSYMBOL_DNAT = 319,                     /* "dnat"  */
  YYSYMBOL_MASQUERADE = 320,               /* "masquerade"  */
  YYSYMBOL_REDIRECT = 321,                 /* "redirect"  */
  YYSYMBOL_RANDOM = 322,                   /* "random"  */
  YYSYMBOL_FULLY_RANDOM = 323,             /* "fully-random"  */
  YYSYMBOL_PERSISTENT = 324,               /* "persistent"  */
  YYSYMBOL_QUEUE = 325,                    /* "queue"  */
  YYSYMBOL_QUEUENUM = 326,                 /* "num"  */
  YYSYMBOL_BYPASS = 327,                   /* "bypass"  */
  YYSYMBOL_FANOUT = 328,                   /* "fanout"  */
  YYSYMBOL_DUP = 329,                      /* "dup"  */
  YYSYMBOL_FWD = 330,                      /* "fwd"  */
  YYSYMBOL_NUMGEN = 331,                   /* "numgen"  */
  YYSYMBOL_INC = 332,                      /* "inc"  */
  YYSYMBOL_MOD = 333,                      /* "mod"  */
  YYSYMBOL_OFFSET = 334,                   /* "offset"  */
  YYSYMBOL_JHASH = 335,                    /* "jhash"  */
  YYSYMBOL_SYMHASH = 336,                  /* "symhash"  */
  YYSYMBOL_SEED = 337,                     /* "seed"  */
  YYSYMBOL_POSITION = 338,                 /* "position"  */
  YYSYMBOL_INDEX = 339,                    /* "index"  */
  YYSYMBOL_COMMENT = 340,                  /* "comment"  */
  YYSYMBOL_XML = 341,                      /* "xml"  */
  YYSYMBOL_JSON = 342,                     /* "json"  */
  YYSYMBOL_VM = 343,                       /* "vm"  */
  YYSYMBOL_NOTRACK = 344,                  /* "notrack"  */
  YYSYMBOL_EXISTS = 345,                   /* "exists"  */
  YYSYMBOL_MISSING = 346,                  /* "missing"  */
  YYSYMBOL_EXTHDR = 347,                   /* "exthdr"  */
  YYSYMBOL_IPSEC = 348,                    /* "ipsec"  */
  YYSYMBOL_REQID = 349,                    /* "reqid"  */
  YYSYMBOL_SPNUM = 350,                    /* "spnum"  */
  YYSYMBOL_IN = 351,                       /* "in"  */
  YYSYMBOL_OUT = 352,                      /* "out"  */
  YYSYMBOL_353_ = 353,                     /* '='  */
  YYSYMBOL_354_ = 354,                     /* '{'  */
  YYSYMBOL_355_ = 355,                     /* '}'  */
  YYSYMBOL_356_ = 356,                     /* '('  */
  YYSYMBOL_357_ = 357,                     /* ')'  */
  YYSYMBOL_358_ = 358,                     /* '|'  */
  YYSYMBOL_359_ = 359,                     /* '$'  */
  YYSYMBOL_360_ = 360,                     /* '['  */
  YYSYMBOL_361_ = 361,                     /* ']'  */
  YYSYMBOL_YYACCEPT = 362,                 /* $accept  */
  YYSYMBOL_input = 363,                    /* input  */
  YYSYMBOL_stmt_separator = 364,           /* stmt_separator  */
  YYSYMBOL_opt_newline = 365,              /* opt_newline  */
  YYSYMBOL_close_scope_arp = 366,          /* close_scope_arp  */
  YYSYMBOL_close_scope_ct = 367,           /* close_scope_ct  */
  YYSYMBOL_close_scope_counter = 368,      /* close_scope_counter  */
  YYSYMBOL_close_scope_eth = 369,          /* close_scope_eth  */
  YYSYMBOL_close_scope_fib = 370,          /* close_scope_fib  */
  YYSYMBOL_close_scope_hash = 371,         /* close_scope_hash  */
  YYSYMBOL_close_scope_ip = 372,           /* close_scope_ip  */
  YYSYMBOL_close_scope_ip6 = 373,          /* close_scope_ip6  */
  YYSYMBOL_close_scope_vlan = 374,         /* close_scope_vlan  */
  YYSYMBOL_close_scope_ipsec = 375,        /* close_scope_ipsec  */
  YYSYMBOL_close_scope_list = 376,         /* close_scope_list  */
  YYSYMBOL_close_scope_limit = 377,        /* close_scope_limit  */
  YYSYMBOL_close_scope_numgen = 378,       /* close_scope_numgen  */
  YYSYMBOL_close_scope_quota = 379,        /* close_scope_quota  */
  YYSYMBOL_close_scope_tcp = 380,          /* close_scope_tcp  */
  YYSYMBOL_close_scope_queue = 381,        /* close_scope_queue  */
  YYSYMBOL_close_scope_rt = 382,           /* close_scope_rt  */
  YYSYMBOL_close_scope_sctp = 383,         /* close_scope_sctp  */
  YYSYMBOL_close_scope_sctp_chunk = 384,   /* close_scope_sctp_chunk  */
  YYSYMBOL_close_scope_secmark = 385,      /* close_scope_secmark  */
  YYSYMBOL_close_scope_socket = 386,       /* close_scope_socket  */
  YYSYMBOL_close_scope_log = 387,          /* close_scope_log  */
  YYSYMBOL_common_block = 388,             /* common_block  */
  YYSYMBOL_line = 389,                     /* line  */
  YYSYMBOL_base_cmd = 390,                 /* base_cmd  */
  YYSYMBOL_add_cmd = 391,                  /* add_cmd  */
  YYSYMBOL_replace_cmd = 392,              /* replace_cmd  */
  YYSYMBOL_create_cmd = 393,               /* create_cmd  */
  YYSYMBOL_insert_cmd = 394,               /* insert_cmd  */
  YYSYMBOL_table_or_id_spec = 395,         /* table_or_id_spec  */
  YYSYMBOL_chain_or_id_spec = 396,         /* chain_or_id_spec  */
  YYSYMBOL_set_or_id_spec = 397,           /* set_or_id_spec  */
  YYSYMBOL_obj_or_id_spec = 398,           /* obj_or_id_spec  */
  YYSYMBOL_delete_cmd = 399,               /* delete_cmd  */
  YYSYMBOL_get_cmd = 400,                  /* get_cmd  */
  YYSYMBOL_list_cmd = 401,                 /* list_cmd  */
  YYSYMBOL_basehook_device_name = 402,     /* basehook_device_name  */
  YYSYMBOL_basehook_spec = 403,            /* basehook_spec  */
  YYSYMBOL_reset_cmd = 404,                /* reset_cmd  */
  YYSYMBOL_flush_cmd = 405,                /* flush_cmd  */
  YYSYMBOL_rename_cmd = 406,               /* rename_cmd  */
  YYSYMBOL_import_cmd = 407,               /* import_cmd  */
  YYSYMBOL_export_cmd = 408,               /* export_cmd  */
  YYSYMBOL_monitor_cmd = 409,              /* monitor_cmd  */
  YYSYMBOL_monitor_event = 410,            /* monitor_event  */
  YYSYMBOL_monitor_object = 411,           /* monitor_object  */
  YYSYMBOL_monitor_format = 412,           /* monitor_format  */
  YYSYMBOL_markup_format = 413,            /* markup_format  */
  YYSYMBOL_describe_cmd = 414,             /* describe_cmd  */
  YYSYMBOL_table_block_alloc = 415,        /* table_block_alloc  */
  YYSYMBOL_table_options = 416,            /* table_options  */
  YYSYMBOL_table_block = 417,              /* table_block  */
  YYSYMBOL_chain_block_alloc = 418,        /* chain_block_alloc  */
  YYSYMBOL_chain_block = 419,              /* chain_block  */
  YYSYMBOL_subchain_block = 420,           /* subchain_block  */
  YYSYMBOL_typeof_data_expr = 421,         /* typeof_data_expr  */
  YYSYMBOL_typeof_expr = 422,              /* typeof_expr  */
  YYSYMBOL_set_block_alloc = 423,          /* set_block_alloc  */
  YYSYMBOL_set_block = 424,                /* set_block  */
  YYSYMBOL_set_block_expr = 425,           /* set_block_expr  */
  YYSYMBOL_set_flag_list = 426,            /* set_flag_list  */
  YYSYMBOL_set_flag = 427,                 /* set_flag  */
  YYSYMBOL_map_block_alloc = 428,          /* map_block_alloc  */
  YYSYMBOL_map_block_obj_type = 429,       /* map_block_obj_type  */
  YYSYMBOL_map_block = 430,                /* map_block  */
  YYSYMBOL_set_mechanism = 431,            /* set_mechanism  */
  YYSYMBOL_set_policy_spec = 432,          /* set_policy_spec  */
  YYSYMBOL_flowtable_block_alloc = 433,    /* flowtable_block_alloc  */
  YYSYMBOL_flowtable_block = 434,          /* flowtable_block  */
  YYSYMBOL_flowtable_expr = 435,           /* flowtable_expr  */
  YYSYMBOL_flowtable_list_expr = 436,      /* flowtable_list_expr  */
  YYSYMBOL_flowtable_expr_member = 437,    /* flowtable_expr_member  */
  YYSYMBOL_data_type_atom_expr = 438,      /* data_type_atom_expr  */
  YYSYMBOL_data_type_expr = 439,           /* data_type_expr  */
  YYSYMBOL_obj_block_alloc = 440,          /* obj_block_alloc  */
  YYSYMBOL_counter_block = 441,            /* counter_block  */
  YYSYMBOL_quota_block = 442,              /* quota_block  */
  YYSYMBOL_ct_helper_block = 443,          /* ct_helper_block  */
  YYSYMBOL_ct_timeout_block = 444,         /* ct_timeout_block  */
  YYSYMBOL_ct_expect_block = 445,          /* ct_expect_block  */
  YYSYMBOL_limit_block = 446,              /* limit_block  */
  YYSYMBOL_secmark_block = 447,            /* secmark_block  */
  YYSYMBOL_synproxy_block = 448,           /* synproxy_block  */
  YYSYMBOL_type_identifier = 449,          /* type_identifier  */
  YYSYMBOL_hook_spec = 450,                /* hook_spec  */
  YYSYMBOL_prio_spec = 451,                /* prio_spec  */
  YYSYMBOL_extended_prio_name = 452,       /* extended_prio_name  */
  YYSYMBOL_extended_prio_spec = 453,       /* extended_prio_spec  */
  YYSYMBOL_int_num = 454,                  /* int_num  */
  YYSYMBOL_dev_spec = 455,                 /* dev_spec  */
  YYSYMBOL_flags_spec = 456,               /* flags_spec  */
  YYSYMBOL_policy_spec = 457,              /* policy_spec  */
  YYSYMBOL_policy_expr = 458,              /* policy_expr  */
  YYSYMBOL_chain_policy = 459,             /* chain_policy  */
  YYSYMBOL_identifier = 460,               /* identifier  */
  YYSYMBOL_string = 461,                   /* string  */
  YYSYMBOL_time_spec = 462,                /* time_spec  */
  YYSYMBOL_family_spec = 463,              /* family_spec  */
  YYSYMBOL_family_spec_explicit = 464,     /* family_spec_explicit  */
  YYSYMBOL_table_spec = 465,               /* table_spec  */
  YYSYMBOL_tableid_spec = 466,             /* tableid_spec  */
  YYSYMBOL_chain_spec = 467,               /* chain_spec  */
  YYSYMBOL_chainid_spec = 468,             /* chainid_spec  */
  YYSYMBOL_chain_identifier = 469,         /* chain_identifier  */
  YYSYMBOL_set_spec = 470,                 /* set_spec  */
  YYSYMBOL_setid_spec = 471,               /* setid_spec  */
  YYSYMBOL_set_identifier = 472,           /* set_identifier  */
  YYSYMBOL_flowtable_spec = 473,           /* flowtable_spec  */
  YYSYMBOL_flowtableid_spec = 474,         /* flowtableid_spec  */
  YYSYMBOL_flowtable_identifier = 475,     /* flowtable_identifier  */
  YYSYMBOL_obj_spec = 476,                 /* obj_spec  */
  YYSYMBOL_objid_spec = 477,               /* objid_spec  */
  YYSYMBOL_obj_identifier = 478,           /* obj_identifier  */
  YYSYMBOL_handle_spec = 479,              /* handle_spec  */
  YYSYMBOL_position_spec = 480,            /* position_spec  */
  YYSYMBOL_index_spec = 481,               /* index_spec  */
  YYSYMBOL_rule_position = 482,            /* rule_position  */
  YYSYMBOL_ruleid_spec = 483,              /* ruleid_spec  */
  YYSYMBOL_comment_spec = 484,             /* comment_spec  */
  YYSYMBOL_ruleset_spec = 485,             /* ruleset_spec  */
  YYSYMBOL_rule = 486,                     /* rule  */
  YYSYMBOL_rule_alloc = 487,               /* rule_alloc  */
  YYSYMBOL_stmt_list = 488,                /* stmt_list  */
  YYSYMBOL_stateful_stmt_list = 489,       /* stateful_stmt_list  */
  YYSYMBOL_stateful_stmt = 490,            /* stateful_stmt  */
  YYSYMBOL_stmt = 491,                     /* stmt  */
  YYSYMBOL_chain_stmt_type = 492,          /* chain_stmt_type  */
  YYSYMBOL_chain_stmt = 493,               /* chain_stmt  */
  YYSYMBOL_verdict_stmt = 494,             /* verdict_stmt  */
  YYSYMBOL_verdict_map_stmt = 495,         /* verdict_map_stmt  */
  YYSYMBOL_verdict_map_expr = 496,         /* verdict_map_expr  */
  YYSYMBOL_verdict_map_list_expr = 497,    /* verdict_map_list_expr  */
  YYSYMBOL_verdict_map_list_member_expr = 498, /* verdict_map_list_member_expr  */
  YYSYMBOL_connlimit_stmt = 499,           /* connlimit_stmt  */
  YYSYMBOL_counter_stmt = 500,             /* counter_stmt  */
  YYSYMBOL_counter_stmt_alloc = 501,       /* counter_stmt_alloc  */
  YYSYMBOL_counter_args = 502,             /* counter_args  */
  YYSYMBOL_counter_arg = 503,              /* counter_arg  */
  YYSYMBOL_log_stmt = 504,                 /* log_stmt  */
  YYSYMBOL_log_stmt_alloc = 505,           /* log_stmt_alloc  */
  YYSYMBOL_log_args = 506,                 /* log_args  */
  YYSYMBOL_log_arg = 507,                  /* log_arg  */
  YYSYMBOL_level_type = 508,               /* level_type  */
  YYSYMBOL_log_flags = 509,                /* log_flags  */
  YYSYMBOL_log_flags_tcp = 510,            /* log_flags_tcp  */
  YYSYMBOL_log_flag_tcp = 511,             /* log_flag_tcp  */
  YYSYMBOL_limit_stmt = 512,               /* limit_stmt  */
  YYSYMBOL_quota_mode = 513,               /* quota_mode  */
  YYSYMBOL_quota_unit = 514,               /* quota_unit  */
  YYSYMBOL_quota_used = 515,               /* quota_used  */
  YYSYMBOL_quota_stmt = 516,               /* quota_stmt  */
  YYSYMBOL_limit_mode = 517,               /* limit_mode  */
  YYSYMBOL_limit_burst_pkts = 518,         /* limit_burst_pkts  */
  YYSYMBOL_limit_rate_pkts = 519,          /* limit_rate_pkts  */
  YYSYMBOL_limit_burst_bytes = 520,        /* limit_burst_bytes  */
  YYSYMBOL_limit_rate_bytes = 521,         /* limit_rate_bytes  */
  YYSYMBOL_limit_bytes = 522,              /* limit_bytes  */
  YYSYMBOL_time_unit = 523,                /* time_unit  */
  YYSYMBOL_reject_stmt = 524,              /* reject_stmt  */
  YYSYMBOL_reject_stmt_alloc = 525,        /* reject_stmt_alloc  */
  YYSYMBOL_reject_with_expr = 526,         /* reject_with_expr  */
  YYSYMBOL_reject_opts = 527,              /* reject_opts  */
  YYSYMBOL_nat_stmt = 528,                 /* nat_stmt  */
  YYSYMBOL_nat_stmt_alloc = 529,           /* nat_stmt_alloc  */
  YYSYMBOL_tproxy_stmt = 530,              /* tproxy_stmt  */
  YYSYMBOL_synproxy_stmt = 531,            /* synproxy_stmt  */
  YYSYMBOL_synproxy_stmt_alloc = 532,      /* synproxy_stmt_alloc  */
  YYSYMBOL_synproxy_args = 533,            /* synproxy_args  */
  YYSYMBOL_synproxy_arg = 534,             /* synproxy_arg  */
  YYSYMBOL_synproxy_config = 535,          /* synproxy_config  */
  YYSYMBOL_synproxy_obj = 536,             /* synproxy_obj  */
  YYSYMBOL_synproxy_ts = 537,              /* synproxy_ts  */
  YYSYMBOL_synproxy_sack = 538,            /* synproxy_sack  */
  YYSYMBOL_primary_stmt_expr = 539,        /* primary_stmt_expr  */
  YYSYMBOL_shift_stmt_expr = 540,          /* shift_stmt_expr  */
  YYSYMBOL_and_stmt_expr = 541,            /* and_stmt_expr  */
  YYSYMBOL_exclusive_or_stmt_expr = 542,   /* exclusive_or_stmt_expr  */
  YYSYMBOL_inclusive_or_stmt_expr = 543,   /* inclusive_or_stmt_expr  */
  YYSYMBOL_basic_stmt_expr = 544,          /* basic_stmt_expr  */
  YYSYMBOL_concat_stmt_expr = 545,         /* concat_stmt_expr  */
  YYSYMBOL_map_stmt_expr_set = 546,        /* map_stmt_expr_set  */
  YYSYMBOL_map_stmt_expr = 547,            /* map_stmt_expr  */
  YYSYMBOL_prefix_stmt_expr = 548,         /* prefix_stmt_expr  */
  YYSYMBOL_range_stmt_expr = 549,          /* range_stmt_expr  */
  YYSYMBOL_multiton_stmt_expr = 550,       /* multiton_stmt_expr  */
  YYSYMBOL_stmt_expr = 551,                /* stmt_expr  */
  YYSYMBOL_nat_stmt_args = 552,            /* nat_stmt_args  */
  YYSYMBOL_masq_stmt = 553,                /* masq_stmt  */
  YYSYMBOL_masq_stmt_alloc = 554,          /* masq_stmt_alloc  */
  YYSYMBOL_masq_stmt_args = 555,           /* masq_stmt_args  */
  YYSYMBOL_redir_stmt = 556,               /* redir_stmt  */
  YYSYMBOL_redir_stmt_alloc = 557,         /* redir_stmt_alloc  */
  YYSYMBOL_redir_stmt_arg = 558,           /* redir_stmt_arg  */
  YYSYMBOL_dup_stmt = 559,                 /* dup_stmt  */
  YYSYMBOL_fwd_stmt = 560,                 /* fwd_stmt  */
  YYSYMBOL_nf_nat_flags = 561,             /* nf_nat_flags  */
  YYSYMBOL_nf_nat_flag = 562,              /* nf_nat_flag  */
  YYSYMBOL_queue_stmt = 563,               /* queue_stmt  */
  YYSYMBOL_queue_stmt_compat = 564,        /* queue_stmt_compat  */
  YYSYMBOL_queue_stmt_alloc = 565,         /* queue_stmt_alloc  */
  YYSYMBOL_queue_stmt_args = 566,          /* queue_stmt_args  */
  YYSYMBOL_queue_stmt_arg = 567,           /* queue_stmt_arg  */
  YYSYMBOL_queue_expr = 568,               /* queue_expr  */
  YYSYMBOL_queue_stmt_expr_simple = 569,   /* queue_stmt_expr_simple  */
  YYSYMBOL_queue_stmt_expr = 570,          /* queue_stmt_expr  */
  YYSYMBOL_queue_stmt_flags = 571,         /* queue_stmt_flags  */
  YYSYMBOL_queue_stmt_flag = 572,          /* queue_stmt_flag  */
  YYSYMBOL_set_elem_expr_stmt = 573,       /* set_elem_expr_stmt  */
  YYSYMBOL_set_elem_expr_stmt_alloc = 574, /* set_elem_expr_stmt_alloc  */
  YYSYMBOL_set_stmt = 575,                 /* set_stmt  */
  YYSYMBOL_set_stmt_op = 576,              /* set_stmt_op  */
  YYSYMBOL_map_stmt = 577,                 /* map_stmt  */
  YYSYMBOL_meter_stmt = 578,               /* meter_stmt  */
  YYSYMBOL_flow_stmt_legacy_alloc = 579,   /* flow_stmt_legacy_alloc  */
  YYSYMBOL_flow_stmt_opts = 580,           /* flow_stmt_opts  */
  YYSYMBOL_flow_stmt_opt = 581,            /* flow_stmt_opt  */
  YYSYMBOL_meter_stmt_alloc = 582,         /* meter_stmt_alloc  */
  YYSYMBOL_match_stmt = 583,               /* match_stmt  */
  YYSYMBOL_variable_expr = 584,            /* variable_expr  */
  YYSYMBOL_symbol_expr = 585,              /* symbol_expr  */
  YYSYMBOL_set_ref_expr = 586,             /* set_ref_expr  */
  YYSYMBOL_set_ref_symbol_expr = 587,      /* set_ref_symbol_expr  */
  YYSYMBOL_integer_expr = 588,             /* integer_expr  */
  YYSYMBOL_primary_expr = 589,             /* primary_expr  */
  YYSYMBOL_fib_expr = 590,                 /* fib_expr  */
  YYSYMBOL_fib_result = 591,               /* fib_result  */
  YYSYMBOL_fib_flag = 592,                 /* fib_flag  */
  YYSYMBOL_fib_tuple = 593,                /* fib_tuple  */
  YYSYMBOL_osf_expr = 594,                 /* osf_expr  */
  YYSYMBOL_osf_ttl = 595,                  /* osf_ttl  */
  YYSYMBOL_shift_expr = 596,               /* shift_expr  */
  YYSYMBOL_and_expr = 597,                 /* and_expr  */
  YYSYMBOL_exclusive_or_expr = 598,        /* exclusive_or_expr  */
  YYSYMBOL_inclusive_or_expr = 599,        /* inclusive_or_expr  */
  YYSYMBOL_basic_expr = 600,               /* basic_expr  */
  YYSYMBOL_concat_expr = 601,              /* concat_expr  */
  YYSYMBOL_prefix_rhs_expr = 602,          /* prefix_rhs_expr  */
  YYSYMBOL_range_rhs_expr = 603,           /* range_rhs_expr  */
  YYSYMBOL_multiton_rhs_expr = 604,        /* multiton_rhs_expr  */
  YYSYMBOL_map_expr = 605,                 /* map_expr  */
  YYSYMBOL_expr = 606,                     /* expr  */
  YYSYMBOL_set_expr = 607,                 /* set_expr  */
  YYSYMBOL_set_list_expr = 608,            /* set_list_expr  */
  YYSYMBOL_set_list_member_expr = 609,     /* set_list_member_expr  */
  YYSYMBOL_meter_key_expr = 610,           /* meter_key_expr  */
  YYSYMBOL_meter_key_expr_alloc = 611,     /* meter_key_expr_alloc  */
  YYSYMBOL_set_elem_expr = 612,            /* set_elem_expr  */
  YYSYMBOL_set_elem_key_expr = 613,        /* set_elem_key_expr  */
  YYSYMBOL_set_elem_expr_alloc = 614,      /* set_elem_expr_alloc  */
  YYSYMBOL_set_elem_options = 615,         /* set_elem_options  */
  YYSYMBOL_set_elem_option = 616,          /* set_elem_option  */
  YYSYMBOL_set_elem_expr_options = 617,    /* set_elem_expr_options  */
  YYSYMBOL_set_elem_stmt_list = 618,       /* set_elem_stmt_list  */
  YYSYMBOL_set_elem_stmt = 619,            /* set_elem_stmt  */
  YYSYMBOL_set_elem_expr_option = 620,     /* set_elem_expr_option  */
  YYSYMBOL_set_lhs_expr = 621,             /* set_lhs_expr  */
  YYSYMBOL_set_rhs_expr = 622,             /* set_rhs_expr  */
  YYSYMBOL_initializer_expr = 623,         /* initializer_expr  */
  YYSYMBOL_counter_config = 624,           /* counter_config  */
  YYSYMBOL_counter_obj = 625,              /* counter_obj  */
  YYSYMBOL_quota_config = 626,             /* quota_config  */
  YYSYMBOL_quota_obj = 627,                /* quota_obj  */
  YYSYMBOL_secmark_config = 628,           /* secmark_config  */
  YYSYMBOL_secmark_obj = 629,              /* secmark_obj  */
  YYSYMBOL_ct_obj_type = 630,              /* ct_obj_type  */
  YYSYMBOL_ct_cmd_type = 631,              /* ct_cmd_type  */
  YYSYMBOL_ct_l4protoname = 632,           /* ct_l4protoname  */
  YYSYMBOL_ct_helper_config = 633,         /* ct_helper_config  */
  YYSYMBOL_timeout_states = 634,           /* timeout_states  */
  YYSYMBOL_timeout_state = 635,            /* timeout_state  */
  YYSYMBOL_ct_timeout_config = 636,        /* ct_timeout_config  */
  YYSYMBOL_ct_expect_config = 637,         /* ct_expect_config  */
  YYSYMBOL_ct_obj_alloc = 638,             /* ct_obj_alloc  */
  YYSYMBOL_limit_config = 639,             /* limit_config  */
  YYSYMBOL_limit_obj = 640,                /* limit_obj  */
  YYSYMBOL_relational_expr = 641,          /* relational_expr  */
  YYSYMBOL_list_rhs_expr = 642,            /* list_rhs_expr  */
  YYSYMBOL_rhs_expr = 643,                 /* rhs_expr  */
  YYSYMBOL_shift_rhs_expr = 644,           /* shift_rhs_expr  */
  YYSYMBOL_and_rhs_expr = 645,             /* and_rhs_expr  */
  YYSYMBOL_exclusive_or_rhs_expr = 646,    /* exclusive_or_rhs_expr  */
  YYSYMBOL_inclusive_or_rhs_expr = 647,    /* inclusive_or_rhs_expr  */
  YYSYMBOL_basic_rhs_expr = 648,           /* basic_rhs_expr  */
  YYSYMBOL_concat_rhs_expr = 649,          /* concat_rhs_expr  */
  YYSYMBOL_boolean_keys = 650,             /* boolean_keys  */
  YYSYMBOL_boolean_expr = 651,             /* boolean_expr  */
  YYSYMBOL_keyword_expr = 652,             /* keyword_expr  */
  YYSYMBOL_primary_rhs_expr = 653,         /* primary_rhs_expr  */
  YYSYMBOL_relational_op = 654,            /* relational_op  */
  YYSYMBOL_verdict_expr = 655,             /* verdict_expr  */
  YYSYMBOL_chain_expr = 656,               /* chain_expr  */
  YYSYMBOL_meta_expr = 657,                /* meta_expr  */
  YYSYMBOL_meta_key = 658,                 /* meta_key  */
  YYSYMBOL_meta_key_qualified = 659,       /* meta_key_qualified  */
  YYSYMBOL_meta_key_unqualified = 660,     /* meta_key_unqualified  */
  YYSYMBOL_meta_stmt = 661,                /* meta_stmt  */
  YYSYMBOL_socket_expr = 662,              /* socket_expr  */
  YYSYMBOL_socket_key = 663,               /* socket_key  */
  YYSYMBOL_offset_opt = 664,               /* offset_opt  */
  YYSYMBOL_numgen_type = 665,              /* numgen_type  */
  YYSYMBOL_numgen_expr = 666,              /* numgen_expr  */
  YYSYMBOL_xfrm_spnum = 667,               /* xfrm_spnum  */
  YYSYMBOL_xfrm_dir = 668,                 /* xfrm_dir  */
  YYSYMBOL_xfrm_state_key = 669,           /* xfrm_state_key  */
  YYSYMBOL_xfrm_state_proto_key = 670,     /* xfrm_state_proto_key  */
  YYSYMBOL_xfrm_expr = 671,                /* xfrm_expr  */
  YYSYMBOL_hash_expr = 672,                /* hash_expr  */
  YYSYMBOL_nf_key_proto = 673,             /* nf_key_proto  */
  YYSYMBOL_rt_expr = 674,                  /* rt_expr  */
  YYSYMBOL_rt_key = 675,                   /* rt_key  */
  YYSYMBOL_ct_expr = 676,                  /* ct_expr  */
  YYSYMBOL_ct_dir = 677,                   /* ct_dir  */
  YYSYMBOL_ct_key = 678,                   /* ct_key  */
  YYSYMBOL_ct_key_dir = 679,               /* ct_key_dir  */
  YYSYMBOL_ct_key_proto_field = 680,       /* ct_key_proto_field  */
  YYSYMBOL_ct_key_dir_optional = 681,      /* ct_key_dir_optional  */
  YYSYMBOL_symbol_stmt_expr = 682,         /* symbol_stmt_expr  */
  YYSYMBOL_list_stmt_expr = 683,           /* list_stmt_expr  */
  YYSYMBOL_ct_stmt = 684,                  /* ct_stmt  */
  YYSYMBOL_payload_stmt = 685,             /* payload_stmt  */
  YYSYMBOL_payload_expr = 686,             /* payload_expr  */
  YYSYMBOL_payload_raw_expr = 687,         /* payload_raw_expr  */
  YYSYMBOL_payload_base_spec = 688,        /* payload_base_spec  */
  YYSYMBOL_eth_hdr_expr = 689,             /* eth_hdr_expr  */
  YYSYMBOL_eth_hdr_field = 690,            /* eth_hdr_field  */
  YYSYMBOL_vlan_hdr_expr = 691,            /* vlan_hdr_expr  */
  YYSYMBOL_vlan_hdr_field = 692,           /* vlan_hdr_field  */
  YYSYMBOL_arp_hdr_expr = 693,             /* arp_hdr_expr  */
  YYSYMBOL_arp_hdr_field = 694,            /* arp_hdr_field  */
  YYSYMBOL_ip_hdr_expr = 695,              /* ip_hdr_expr  */
  YYSYMBOL_ip_hdr_field = 696,             /* ip_hdr_field  */
  YYSYMBOL_ip_option_type = 697,           /* ip_option_type  */
  YYSYMBOL_ip_option_field = 698,          /* ip_option_field  */
  YYSYMBOL_icmp_hdr_expr = 699,            /* icmp_hdr_expr  */
  YYSYMBOL_icmp_hdr_field = 700,           /* icmp_hdr_field  */
  YYSYMBOL_igmp_hdr_expr = 701,            /* igmp_hdr_expr  */
  YYSYMBOL_igmp_hdr_field = 702,           /* igmp_hdr_field  */
  YYSYMBOL_ip6_hdr_expr = 703,             /* ip6_hdr_expr  */
  YYSYMBOL_ip6_hdr_field = 704,            /* ip6_hdr_field  */
  YYSYMBOL_icmp6_hdr_expr = 705,           /* icmp6_hdr_expr  */
  YYSYMBOL_icmp6_hdr_field = 706,          /* icmp6_hdr_field  */
  YYSYMBOL_auth_hdr_expr = 707,            /* auth_hdr_expr  */
  YYSYMBOL_auth_hdr_field = 708,           /* auth_hdr_field  */
  YYSYMBOL_esp_hdr_expr = 709,             /* esp_hdr_expr  */
  YYSYMBOL_esp_hdr_field = 710,            /* esp_hdr_field  */
  YYSYMBOL_comp_hdr_expr = 711,            /* comp_hdr_expr  */
  YYSYMBOL_comp_hdr_field = 712,           /* comp_hdr_field  */
  YYSYMBOL_udp_hdr_expr = 713,             /* udp_hdr_expr  */
  YYSYMBOL_udp_hdr_field = 714,            /* udp_hdr_field  */
  YYSYMBOL_udplite_hdr_expr = 715,         /* udplite_hdr_expr  */
  YYSYMBOL_udplite_hdr_field = 716,        /* udplite_hdr_field  */
  YYSYMBOL_tcp_hdr_expr = 717,             /* tcp_hdr_expr  */
  YYSYMBOL_tcp_hdr_field = 718,            /* tcp_hdr_field  */
  YYSYMBOL_tcp_hdr_option_kind_and_field = 719, /* tcp_hdr_option_kind_and_field  */
  YYSYMBOL_tcp_hdr_option_sack = 720,      /* tcp_hdr_option_sack  */
  YYSYMBOL_tcp_hdr_option_type = 721,      /* tcp_hdr_option_type  */
  YYSYMBOL_tcpopt_field_sack = 722,        /* tcpopt_field_sack  */
  YYSYMBOL_tcpopt_field_window = 723,      /* tcpopt_field_window  */
  YYSYMBOL_tcpopt_field_tsopt = 724,       /* tcpopt_field_tsopt  */
  YYSYMBOL_tcpopt_field_maxseg = 725,      /* tcpopt_field_maxseg  */
  YYSYMBOL_tcpopt_field_mptcp = 726,       /* tcpopt_field_mptcp  */
  YYSYMBOL_dccp_hdr_expr = 727,            /* dccp_hdr_expr  */
  YYSYMBOL_dccp_hdr_field = 728,           /* dccp_hdr_field  */
  YYSYMBOL_sctp_chunk_type = 729,          /* sctp_chunk_type  */
  YYSYMBOL_sctp_chunk_common_field = 730,  /* sctp_chunk_common_field  */
  YYSYMBOL_sctp_chunk_data_field = 731,    /* sctp_chunk_data_field  */
  YYSYMBOL_sctp_chunk_init_field = 732,    /* sctp_chunk_init_field  */
  YYSYMBOL_sctp_chunk_sack_field = 733,    /* sctp_chunk_sack_field  */
  YYSYMBOL_sctp_chunk_alloc = 734,         /* sctp_chunk_alloc  */
  YYSYMBOL_sctp_hdr_expr = 735,            /* sctp_hdr_expr  */
  YYSYMBOL_sctp_hdr_field = 736,           /* sctp_hdr_field  */
  YYSYMBOL_th_hdr_expr = 737,              /* th_hdr_expr  */
  YYSYMBOL_th_hdr_field = 738,             /* th_hdr_field  */
  YYSYMBOL_exthdr_expr = 739,              /* exthdr_expr  */
  YYSYMBOL_hbh_hdr_expr = 740,             /* hbh_hdr_expr  */
  YYSYMBOL_hbh_hdr_field = 741,            /* hbh_hdr_field  */
  YYSYMBOL_rt_hdr_expr = 742,              /* rt_hdr_expr  */
  YYSYMBOL_rt_hdr_field = 743,             /* rt_hdr_field  */
  YYSYMBOL_rt0_hdr_expr = 744,             /* rt0_hdr_expr  */
  YYSYMBOL_rt0_hdr_field = 745,            /* rt0_hdr_field  */
  YYSYMBOL_rt2_hdr_expr = 746,             /* rt2_hdr_expr  */
  YYSYMBOL_rt2_hdr_field = 747,            /* rt2_hdr_field  */
  YYSYMBOL_rt4_hdr_expr = 748,             /* rt4_hdr_expr  */
  YYSYMBOL_rt4_hdr_field = 749,            /* rt4_hdr_field  */
  YYSYMBOL_frag_hdr_expr = 750,            /* frag_hdr_expr  */
  YYSYMBOL_frag_hdr_field = 751,           /* frag_hdr_field  */
  YYSYMBOL_dst_hdr_expr = 752,             /* dst_hdr_expr  */
  YYSYMBOL_dst_hdr_field = 753,            /* dst_hdr_field  */
  YYSYMBOL_mh_hdr_expr = 754,              /* mh_hdr_expr  */
  YYSYMBOL_mh_hdr_field = 755,             /* mh_hdr_field  */
  YYSYMBOL_exthdr_exists_expr = 756,       /* exthdr_exists_expr  */
  YYSYMBOL_exthdr_key = 757                /* exthdr_key  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int16 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                            \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if 1

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* 1 */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL \
             && defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
  YYLTYPE yyls_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE) \
             + YYSIZEOF (YYLTYPE)) \
      + 2 * YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   8010

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  362
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  396
/* YYNRULES -- Number of rules.  */
#define YYNRULES  1248
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  2101

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   607


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int16 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,   359,     2,     2,     2,
     356,   357,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   353,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   360,     2,   361,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   354,   358,   355,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,   176,   177,   178,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   196,   197,   198,   199,   200,   201,   202,   203,   204,
     205,   206,   207,   208,   209,   210,   211,   212,   213,   214,
     215,   216,   217,   218,   219,   220,   221,   222,   223,   224,
     225,   226,   227,   228,   229,   230,   231,   232,   233,   234,
     235,   236,   237,   238,   239,   240,   241,   242,   243,   244,
     245,   246,   247,   248,   249,   250,   251,   252,   253,   254,
     255,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   911,   911,   912,   921,   922,   925,   926,   929,   930,
     931,   932,   933,   934,   935,   936,   937,   938,   939,   940,
     941,   942,   943,   944,   945,   946,   947,   948,   949,   951,
     953,   961,   976,   983,   995,  1003,  1004,  1005,  1006,  1026,
    1027,  1028,  1029,  1030,  1031,  1032,  1033,  1034,  1035,  1036,
    1037,  1038,  1039,  1040,  1043,  1047,  1054,  1058,  1066,  1070,
    1074,  1081,  1088,  1092,  1099,  1108,  1112,  1116,  1120,  1124,
    1128,  1132,  1136,  1140,  1144,  1148,  1152,  1156,  1162,  1168,
    1172,  1179,  1183,  1191,  1198,  1205,  1209,  1216,  1225,  1229,
    1233,  1237,  1241,  1245,  1249,  1253,  1259,  1265,  1266,  1269,
    1270,  1273,  1274,  1277,  1278,  1281,  1285,  1289,  1293,  1297,
    1301,  1305,  1309,  1313,  1320,  1324,  1328,  1334,  1338,  1342,
    1348,  1354,  1358,  1362,  1366,  1370,  1374,  1378,  1382,  1386,
    1390,  1394,  1398,  1402,  1406,  1410,  1414,  1418,  1422,  1426,
    1430,  1434,  1438,  1442,  1446,  1450,  1454,  1458,  1462,  1466,
    1470,  1474,  1478,  1482,  1486,  1492,  1498,  1502,  1512,  1516,
    1520,  1524,  1528,  1532,  1538,  1542,  1546,  1550,  1554,  1558,
    1562,  1568,  1575,  1581,  1589,  1595,  1603,  1612,  1613,  1616,
    1617,  1618,  1619,  1620,  1621,  1622,  1623,  1626,  1627,  1630,
    1631,  1632,  1635,  1644,  1650,  1665,  1675,  1676,  1677,  1678,
    1679,  1690,  1700,  1711,  1721,  1732,  1743,  1752,  1761,  1770,
    1781,  1792,  1806,  1812,  1813,  1814,  1815,  1816,  1817,  1818,
    1823,  1833,  1834,  1835,  1842,  1863,  1874,  1885,  1898,  1903,
    1904,  1905,  1906,  1911,  1917,  1922,  1927,  1932,  1938,  1943,
    1948,  1949,  1960,  1961,  1964,  1968,  1971,  1972,  1973,  1974,
    1978,  1983,  1984,  1985,  1986,  1987,  1990,  1991,  1992,  1993,
    1998,  2008,  2019,  2030,  2042,  2051,  2056,  2062,  2067,  2076,
    2079,  2083,  2089,  2090,  2094,  2099,  2100,  2101,  2102,  2116,
    2120,  2124,  2130,  2135,  2142,  2147,  2152,  2155,  2162,  2169,
    2176,  2189,  2196,  2197,  2209,  2214,  2215,  2216,  2217,  2221,
    2231,  2232,  2233,  2234,  2238,  2248,  2249,  2250,  2251,  2255,
    2266,  2270,  2271,  2272,  2276,  2286,  2287,  2288,  2289,  2293,
    2303,  2304,  2305,  2306,  2310,  2320,  2321,  2322,  2323,  2327,
    2337,  2338,  2339,  2340,  2344,  2354,  2355,  2356,  2357,  2358,
    2361,  2392,  2399,  2403,  2406,  2416,  2423,  2434,  2447,  2462,
    2463,  2466,  2478,  2484,  2488,  2491,  2497,  2510,  2515,  2524,
    2525,  2528,  2531,  2532,  2533,  2536,  2551,  2552,  2555,  2556,
    2557,  2558,  2559,  2560,  2563,  2572,  2581,  2589,  2597,  2605,
    2613,  2621,  2629,  2637,  2645,  2653,  2661,  2669,  2677,  2685,
    2693,  2701,  2705,  2710,  2718,  2725,  2732,  2746,  2750,  2757,
    2761,  2767,  2779,  2785,  2792,  2798,  2805,  2806,  2807,  2808,
    2811,  2812,  2813,  2814,  2815,  2816,  2817,  2818,  2819,  2820,
    2821,  2822,  2823,  2824,  2825,  2826,  2827,  2828,  2829,  2830,
    2833,  2834,  2837,  2846,  2850,  2856,  2862,  2867,  2870,  2875,
    2880,  2883,  2889,  2894,  2902,  2903,  2905,  2909,  2917,  2921,
    2924,  2928,  2934,  2935,  2938,  2944,  2948,  2951,  3076,  3081,
    3086,  3091,  3096,  3102,  3132,  3136,  3140,  3144,  3148,  3154,
    3158,  3161,  3165,  3171,  3185,  3199,  3207,  3208,  3209,  3212,
    3213,  3216,  3217,  3232,  3248,  3256,  3257,  3258,  3261,  3262,
    3265,  3272,  3273,  3276,  3290,  3297,  3298,  3313,  3314,  3315,
    3316,  3317,  3320,  3323,  3329,  3335,  3339,  3343,  3350,  3357,
    3364,  3371,  3377,  3383,  3389,  3392,  3393,  3396,  3402,  3408,
    3414,  3421,  3428,  3436,  3437,  3440,  3444,  3452,  3456,  3459,
    3464,  3469,  3473,  3479,  3495,  3514,  3520,  3521,  3527,  3528,
    3534,  3535,  3536,  3537,  3538,  3539,  3540,  3541,  3542,  3543,
    3544,  3545,  3546,  3549,  3550,  3554,  3560,  3561,  3567,  3568,
    3574,  3575,  3581,  3584,  3585,  3596,  3597,  3600,  3604,  3607,
    3613,  3619,  3620,  3623,  3624,  3625,  3628,  3632,  3636,  3641,
    3646,  3651,  3657,  3661,  3665,  3669,  3675,  3680,  3684,  3692,
    3701,  3702,  3705,  3708,  3712,  3717,  3723,  3724,  3727,  3730,
    3734,  3738,  3742,  3747,  3754,  3759,  3767,  3772,  3781,  3782,
    3788,  3789,  3790,  3793,  3794,  3798,  3802,  3808,  3809,  3812,
    3818,  3822,  3825,  3830,  3836,  3837,  3840,  3841,  3842,  3848,
    3849,  3850,  3851,  3854,  3855,  3861,  3862,  3865,  3866,  3869,
    3875,  3882,  3889,  3900,  3901,  3902,  3905,  3913,  3925,  3932,
    3935,  3941,  3945,  3948,  3954,  3963,  3974,  3980,  4006,  4007,
    4016,  4017,  4020,  4029,  4040,  4041,  4042,  4043,  4044,  4045,
    4046,  4047,  4048,  4049,  4050,  4051,  4052,  4053,  4054,  4057,
    4080,  4081,  4082,  4085,  4086,  4087,  4088,  4089,  4092,  4096,
    4099,  4103,  4110,  4113,  4129,  4130,  4134,  4140,  4141,  4147,
    4148,  4154,  4155,  4161,  4164,  4165,  4176,  4182,  4188,  4189,
    4192,  4198,  4199,  4200,  4203,  4210,  4215,  4220,  4223,  4227,
    4231,  4237,  4238,  4245,  4251,  4252,  4255,  4256,  4259,  4265,
    4271,  4275,  4278,  4282,  4286,  4296,  4300,  4303,  4309,  4316,
    4320,  4326,  4340,  4354,  4359,  4367,  4371,  4375,  4385,  4388,
    4389,  4392,  4393,  4394,  4395,  4406,  4417,  4423,  4444,  4450,
    4467,  4473,  4474,  4475,  4478,  4479,  4480,  4483,  4484,  4487,
    4503,  4509,  4515,  4522,  4536,  4544,  4552,  4558,  4562,  4566,
    4570,  4574,  4581,  4586,  4597,  4611,  4617,  4621,  4625,  4629,
    4633,  4637,  4641,  4645,  4651,  4657,  4665,  4666,  4667,  4670,
    4671,  4675,  4681,  4682,  4688,  4689,  4695,  4696,  4702,  4705,
    4706,  4707,  4716,  4727,  4728,  4731,  4739,  4740,  4741,  4742,
    4743,  4744,  4745,  4746,  4747,  4748,  4749,  4750,  4753,  4754,
    4755,  4756,  4757,  4764,  4771,  4778,  4785,  4792,  4799,  4806,
    4813,  4820,  4827,  4834,  4841,  4844,  4845,  4846,  4847,  4848,
    4849,  4850,  4853,  4857,  4861,  4865,  4869,  4873,  4879,  4880,
    4890,  4894,  4898,  4914,  4915,  4918,  4919,  4920,  4921,  4922,
    4925,  4926,  4927,  4928,  4929,  4930,  4931,  4932,  4933,  4934,
    4935,  4936,  4937,  4938,  4939,  4940,  4941,  4942,  4943,  4944,
    4945,  4946,  4947,  4948,  4951,  4971,  4975,  4989,  4993,  4997,
    5003,  5007,  5013,  5014,  5015,  5018,  5019,  5022,  5023,  5026,
    5032,  5033,  5036,  5037,  5040,  5041,  5044,  5045,  5048,  5056,
    5083,  5088,  5093,  5099,  5100,  5103,  5107,  5127,  5128,  5129,
    5130,  5133,  5137,  5141,  5147,  5148,  5151,  5152,  5153,  5154,
    5155,  5156,  5157,  5158,  5159,  5160,  5161,  5162,  5163,  5164,
    5165,  5166,  5167,  5170,  5171,  5172,  5173,  5174,  5175,  5176,
    5179,  5180,  5181,  5182,  5185,  5186,  5187,  5188,  5191,  5192,
    5195,  5201,  5209,  5222,  5229,  5235,  5241,  5250,  5251,  5252,
    5253,  5254,  5255,  5256,  5257,  5258,  5259,  5260,  5261,  5262,
    5263,  5264,  5265,  5266,  5267,  5270,  5279,  5280,  5281,  5282,
    5295,  5301,  5302,  5303,  5306,  5312,  5313,  5314,  5315,  5316,
    5319,  5325,  5326,  5327,  5328,  5329,  5330,  5331,  5332,  5333,
    5336,  5340,  5348,  5355,  5356,  5357,  5358,  5359,  5360,  5361,
    5362,  5363,  5364,  5365,  5366,  5369,  5370,  5371,  5372,  5375,
    5376,  5377,  5378,  5379,  5382,  5388,  5389,  5390,  5391,  5392,
    5393,  5394,  5397,  5403,  5404,  5405,  5406,  5409,  5415,  5416,
    5417,  5418,  5419,  5420,  5421,  5422,  5423,  5425,  5431,  5432,
    5433,  5434,  5435,  5436,  5437,  5438,  5441,  5447,  5448,  5449,
    5450,  5451,  5454,  5460,  5461,  5464,  5470,  5471,  5472,  5475,
    5481,  5482,  5483,  5484,  5487,  5493,  5494,  5495,  5496,  5499,
    5503,  5508,  5512,  5519,  5520,  5521,  5522,  5523,  5524,  5525,
    5526,  5527,  5528,  5531,  5536,  5541,  5546,  5551,  5556,  5563,
    5564,  5565,  5566,  5567,  5570,  5571,  5572,  5573,  5574,  5575,
    5576,  5577,  5578,  5579,  5580,  5581,  5590,  5591,  5594,  5597,
    5598,  5601,  5604,  5607,  5613,  5614,  5615,  5618,  5619,  5620,
    5621,  5622,  5623,  5624,  5625,  5626,  5627,  5628,  5629,  5630,
    5631,  5632,  5633,  5634,  5635,  5638,  5639,  5640,  5643,  5644,
    5645,  5646,  5649,  5650,  5651,  5652,  5653,  5656,  5657,  5658,
    5659,  5662,  5667,  5671,  5675,  5679,  5683,  5687,  5692,  5697,
    5702,  5707,  5712,  5719,  5723,  5729,  5730,  5731,  5732,  5735,
    5743,  5744,  5747,  5748,  5749,  5750,  5751,  5752,  5753,  5754,
    5757,  5763,  5764,  5767,  5773,  5774,  5775,  5776,  5779,  5785,
    5791,  5797,  5800,  5806,  5807,  5808,  5809,  5815,  5821,  5822,
    5823,  5824,  5825,  5826,  5829,  5835,  5836,  5839,  5845,  5846,
    5847,  5848,  5849,  5852,  5866,  5867,  5868,  5869,  5870
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if 1
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "\"junk\"",
  "\"newline\"", "\"colon\"", "\"semicolon\"", "\"comma\"", "\".\"",
  "\"==\"", "\"!=\"", "\"<\"", "\">\"", "\">=\"", "\"<=\"", "\"<<\"",
  "\">>\"", "\"&\"", "\"^\"", "\"!\"", "\"/\"", "\"*\"", "\"-\"", "\"@\"",
  "\"vmap\"", "\"+\"", "\"include\"", "\"define\"", "\"redefine\"",
  "\"undefine\"", "\"fib\"", "\"socket\"", "\"transparent\"",
  "\"wildcard\"", "\"cgroupv2\"", "\"tproxy\"", "\"osf\"", "\"synproxy\"",
  "\"mss\"", "\"wscale\"", "\"typeof\"", "\"hook\"", "\"hooks\"",
  "\"device\"", "\"devices\"", "\"table\"", "\"tables\"", "\"chain\"",
  "\"chains\"", "\"rule\"", "\"rules\"", "\"sets\"", "\"set\"",
  "\"element\"", "\"map\"", "\"maps\"", "\"flowtable\"", "\"handle\"",
  "\"ruleset\"", "\"trace\"", "\"inet\"", "\"netdev\"", "\"add\"",
  "\"update\"", "\"replace\"", "\"create\"", "\"insert\"", "\"delete\"",
  "\"get\"", "\"list\"", "\"reset\"", "\"flush\"", "\"rename\"",
  "\"describe\"", "\"import\"", "\"export\"", "\"monitor\"", "\"all\"",
  "\"accept\"", "\"drop\"", "\"continue\"", "\"jump\"", "\"goto\"",
  "\"return\"", "\"to\"", "\"constant\"", "\"interval\"", "\"dynamic\"",
  "\"auto-merge\"", "\"timeout\"", "\"gc-interval\"", "\"elements\"",
  "\"expires\"", "\"policy\"", "\"memory\"", "\"performance\"", "\"size\"",
  "\"flow\"", "\"offload\"", "\"meter\"", "\"meters\"", "\"flowtables\"",
  "\"number\"", "\"string\"", "\"quoted string\"",
  "\"string with a trailing asterisk\"", "\"ll\"", "\"nh\"", "\"th\"",
  "\"bridge\"", "\"ether\"", "\"saddr\"", "\"daddr\"", "\"type\"",
  "\"vlan\"", "\"id\"", "\"cfi\"", "\"dei\"", "\"pcp\"", "\"arp\"",
  "\"htype\"", "\"ptype\"", "\"hlen\"", "\"plen\"", "\"operation\"",
  "\"ip\"", "\"version\"", "\"hdrlength\"", "\"dscp\"", "\"ecn\"",
  "\"length\"", "\"frag-off\"", "\"ttl\"", "\"protocol\"", "\"checksum\"",
  "\"ptr\"", "\"value\"", "\"lsrr\"", "\"rr\"", "\"ssrr\"", "\"ra\"",
  "\"icmp\"", "\"code\"", "\"seq\"", "\"gateway\"", "\"mtu\"", "\"igmp\"",
  "\"mrt\"", "\"options\"", "\"ip6\"", "\"priority\"", "\"flowlabel\"",
  "\"nexthdr\"", "\"hoplimit\"", "\"icmpv6\"", "\"param-problem\"",
  "\"max-delay\"", "\"ah\"", "\"reserved\"", "\"spi\"", "\"esp\"",
  "\"comp\"", "\"flags\"", "\"cpi\"", "\"port\"", "\"udp\"", "\"sport\"",
  "\"dport\"", "\"udplite\"", "\"csumcov\"", "\"tcp\"", "\"ackseq\"",
  "\"doff\"", "\"window\"", "\"urgptr\"", "\"option\"", "\"echo\"",
  "\"eol\"", "\"mptcp\"", "\"nop\"", "\"sack\"", "\"sack0\"", "\"sack1\"",
  "\"sack2\"", "\"sack3\"", "\"sack-permitted\"", "\"fastopen\"",
  "\"md5sig\"", "\"timestamp\"", "\"count\"", "\"left\"", "\"right\"",
  "\"tsval\"", "\"tsecr\"", "\"subtype\"", "\"dccp\"", "\"sctp\"",
  "\"chunk\"", "\"data\"", "\"init\"", "\"init-ack\"", "\"heartbeat\"",
  "\"heartbeat-ack\"", "\"abort\"", "\"shutdown\"", "\"shutdown-ack\"",
  "\"error\"", "\"cookie-echo\"", "\"cookie-ack\"", "\"ecne\"", "\"cwr\"",
  "\"shutdown-complete\"", "\"asconf-ack\"", "\"forward-tsn\"",
  "\"asconf\"", "\"tsn\"", "\"stream\"", "\"ssn\"", "\"ppid\"",
  "\"init-tag\"", "\"a-rwnd\"", "\"num-outbound-streams\"",
  "\"num-inbound-streams\"", "\"initial-tsn\"", "\"cum-tsn-ack\"",
  "\"num-gap-ack-blocks\"", "\"num-dup-tsns\"", "\"lowest-tsn\"",
  "\"seqno\"", "\"new-cum-tsn\"", "\"vtag\"", "\"rt\"", "\"rt0\"",
  "\"rt2\"", "\"srh\"", "\"seg-left\"", "\"addr\"", "\"last-entry\"",
  "\"tag\"", "\"sid\"", "\"hbh\"", "\"frag\"", "\"reserved2\"",
  "\"more-fragments\"", "\"dst\"", "\"mh\"", "\"meta\"", "\"mark\"",
  "\"iif\"", "\"iifname\"", "\"iiftype\"", "\"oif\"", "\"oifname\"",
  "\"oiftype\"", "\"skuid\"", "\"skgid\"", "\"nftrace\"", "\"rtclassid\"",
  "\"ibriport\"", "\"obriport\"", "\"ibrname\"", "\"obrname\"",
  "\"pkttype\"", "\"cpu\"", "\"iifgroup\"", "\"oifgroup\"", "\"cgroup\"",
  "\"time\"", "\"classid\"", "\"nexthop\"", "\"ct\"", "\"l3proto\"",
  "\"proto-src\"", "\"proto-dst\"", "\"zone\"", "\"direction\"",
  "\"event\"", "\"expectation\"", "\"expiration\"", "\"helper\"",
  "\"label\"", "\"state\"", "\"status\"", "\"original\"", "\"reply\"",
  "\"counter\"", "\"name\"", "\"packets\"", "\"bytes\"", "\"avgpkt\"",
  "\"counters\"", "\"quotas\"", "\"limits\"", "\"synproxys\"",
  "\"helpers\"", "\"log\"", "\"prefix\"", "\"group\"", "\"snaplen\"",
  "\"queue-threshold\"", "\"level\"", "\"limit\"", "\"rate\"", "\"burst\"",
  "\"over\"", "\"until\"", "\"quota\"", "\"used\"", "\"secmark\"",
  "\"secmarks\"", "\"second\"", "\"minute\"", "\"hour\"", "\"day\"",
  "\"week\"", "\"reject\"", "\"with\"", "\"icmpx\"", "\"snat\"",
  "\"dnat\"", "\"masquerade\"", "\"redirect\"", "\"random\"",
  "\"fully-random\"", "\"persistent\"", "\"queue\"", "\"num\"",
  "\"bypass\"", "\"fanout\"", "\"dup\"", "\"fwd\"", "\"numgen\"",
  "\"inc\"", "\"mod\"", "\"offset\"", "\"jhash\"", "\"symhash\"",
  "\"seed\"", "\"position\"", "\"index\"", "\"comment\"", "\"xml\"",
  "\"json\"", "\"vm\"", "\"notrack\"", "\"exists\"", "\"missing\"",
  "\"exthdr\"", "\"ipsec\"", "\"reqid\"", "\"spnum\"", "\"in\"", "\"out\"",
  "'='", "'{'", "'}'", "'('", "')'", "'|'", "'$'", "'['", "']'", "$accept",
  "input", "stmt_separator", "opt_newline", "close_scope_arp",
  "close_scope_ct", "close_scope_counter", "close_scope_eth",
  "close_scope_fib", "close_scope_hash", "close_scope_ip",
  "close_scope_ip6", "close_scope_vlan", "close_scope_ipsec",
  "close_scope_list", "close_scope_limit", "close_scope_numgen",
  "close_scope_quota", "close_scope_tcp", "close_scope_queue",
  "close_scope_rt", "close_scope_sctp", "close_scope_sctp_chunk",
  "close_scope_secmark", "close_scope_socket", "close_scope_log",
  "common_block", "line", "base_cmd", "add_cmd", "replace_cmd",
  "create_cmd", "insert_cmd", "table_or_id_spec", "chain_or_id_spec",
  "set_or_id_spec", "obj_or_id_spec", "delete_cmd", "get_cmd", "list_cmd",
  "basehook_device_name", "basehook_spec", "reset_cmd", "flush_cmd",
  "rename_cmd", "import_cmd", "export_cmd", "monitor_cmd", "monitor_event",
  "monitor_object", "monitor_format", "markup_format", "describe_cmd",
  "table_block_alloc", "table_options", "table_block", "chain_block_alloc",
  "chain_block", "subchain_block", "typeof_data_expr", "typeof_expr",
  "set_block_alloc", "set_block", "set_block_expr", "set_flag_list",
  "set_flag", "map_block_alloc", "map_block_obj_type", "map_block",
  "set_mechanism", "set_policy_spec", "flowtable_block_alloc",
  "flowtable_block", "flowtable_expr", "flowtable_list_expr",
  "flowtable_expr_member", "data_type_atom_expr", "data_type_expr",
  "obj_block_alloc", "counter_block", "quota_block", "ct_helper_block",
  "ct_timeout_block", "ct_expect_block", "limit_block", "secmark_block",
  "synproxy_block", "type_identifier", "hook_spec", "prio_spec",
  "extended_prio_name", "extended_prio_spec", "int_num", "dev_spec",
  "flags_spec", "policy_spec", "policy_expr", "chain_policy", "identifier",
  "string", "time_spec", "family_spec", "family_spec_explicit",
  "table_spec", "tableid_spec", "chain_spec", "chainid_spec",
  "chain_identifier", "set_spec", "setid_spec", "set_identifier",
  "flowtable_spec", "flowtableid_spec", "flowtable_identifier", "obj_spec",
  "objid_spec", "obj_identifier", "handle_spec", "position_spec",
  "index_spec", "rule_position", "ruleid_spec", "comment_spec",
  "ruleset_spec", "rule", "rule_alloc", "stmt_list", "stateful_stmt_list",
  "stateful_stmt", "stmt", "chain_stmt_type", "chain_stmt", "verdict_stmt",
  "verdict_map_stmt", "verdict_map_expr", "verdict_map_list_expr",
  "verdict_map_list_member_expr", "connlimit_stmt", "counter_stmt",
  "counter_stmt_alloc", "counter_args", "counter_arg", "log_stmt",
  "log_stmt_alloc", "log_args", "log_arg", "level_type", "log_flags",
  "log_flags_tcp", "log_flag_tcp", "limit_stmt", "quota_mode",
  "quota_unit", "quota_used", "quota_stmt", "limit_mode",
  "limit_burst_pkts", "limit_rate_pkts", "limit_burst_bytes",
  "limit_rate_bytes", "limit_bytes", "time_unit", "reject_stmt",
  "reject_stmt_alloc", "reject_with_expr", "reject_opts", "nat_stmt",
  "nat_stmt_alloc", "tproxy_stmt", "synproxy_stmt", "synproxy_stmt_alloc",
  "synproxy_args", "synproxy_arg", "synproxy_config", "synproxy_obj",
  "synproxy_ts", "synproxy_sack", "primary_stmt_expr", "shift_stmt_expr",
  "and_stmt_expr", "exclusive_or_stmt_expr", "inclusive_or_stmt_expr",
  "basic_stmt_expr", "concat_stmt_expr", "map_stmt_expr_set",
  "map_stmt_expr", "prefix_stmt_expr", "range_stmt_expr",
  "multiton_stmt_expr", "stmt_expr", "nat_stmt_args", "masq_stmt",
  "masq_stmt_alloc", "masq_stmt_args", "redir_stmt", "redir_stmt_alloc",
  "redir_stmt_arg", "dup_stmt", "fwd_stmt", "nf_nat_flags", "nf_nat_flag",
  "queue_stmt", "queue_stmt_compat", "queue_stmt_alloc", "queue_stmt_args",
  "queue_stmt_arg", "queue_expr", "queue_stmt_expr_simple",
  "queue_stmt_expr", "queue_stmt_flags", "queue_stmt_flag",
  "set_elem_expr_stmt", "set_elem_expr_stmt_alloc", "set_stmt",
  "set_stmt_op", "map_stmt", "meter_stmt", "flow_stmt_legacy_alloc",
  "flow_stmt_opts", "flow_stmt_opt", "meter_stmt_alloc", "match_stmt",
  "variable_expr", "symbol_expr", "set_ref_expr", "set_ref_symbol_expr",
  "integer_expr", "primary_expr", "fib_expr", "fib_result", "fib_flag",
  "fib_tuple", "osf_expr", "osf_ttl", "shift_expr", "and_expr",
  "exclusive_or_expr", "inclusive_or_expr", "basic_expr", "concat_expr",
  "prefix_rhs_expr", "range_rhs_expr", "multiton_rhs_expr", "map_expr",
  "expr", "set_expr", "set_list_expr", "set_list_member_expr",
  "meter_key_expr", "meter_key_expr_alloc", "set_elem_expr",
  "set_elem_key_expr", "set_elem_expr_alloc", "set_elem_options",
  "set_elem_option", "set_elem_expr_options", "set_elem_stmt_list",
  "set_elem_stmt", "set_elem_expr_option", "set_lhs_expr", "set_rhs_expr",
  "initializer_expr", "counter_config", "counter_obj", "quota_config",
  "quota_obj", "secmark_config", "secmark_obj", "ct_obj_type",
  "ct_cmd_type", "ct_l4protoname", "ct_helper_config", "timeout_states",
  "timeout_state", "ct_timeout_config", "ct_expect_config", "ct_obj_alloc",
  "limit_config", "limit_obj", "relational_expr", "list_rhs_expr",
  "rhs_expr", "shift_rhs_expr", "and_rhs_expr", "exclusive_or_rhs_expr",
  "inclusive_or_rhs_expr", "basic_rhs_expr", "concat_rhs_expr",
  "boolean_keys", "boolean_expr", "keyword_expr", "primary_rhs_expr",
  "relational_op", "verdict_expr", "chain_expr", "meta_expr", "meta_key",
  "meta_key_qualified", "meta_key_unqualified", "meta_stmt", "socket_expr",
  "socket_key", "offset_opt", "numgen_type", "numgen_expr", "xfrm_spnum",
  "xfrm_dir", "xfrm_state_key", "xfrm_state_proto_key", "xfrm_expr",
  "hash_expr", "nf_key_proto", "rt_expr", "rt_key", "ct_expr", "ct_dir",
  "ct_key", "ct_key_dir", "ct_key_proto_field", "ct_key_dir_optional",
  "symbol_stmt_expr", "list_stmt_expr", "ct_stmt", "payload_stmt",
  "payload_expr", "payload_raw_expr", "payload_base_spec", "eth_hdr_expr",
  "eth_hdr_field", "vlan_hdr_expr", "vlan_hdr_field", "arp_hdr_expr",
  "arp_hdr_field", "ip_hdr_expr", "ip_hdr_field", "ip_option_type",
  "ip_option_field", "icmp_hdr_expr", "icmp_hdr_field", "igmp_hdr_expr",
  "igmp_hdr_field", "ip6_hdr_expr", "ip6_hdr_field", "icmp6_hdr_expr",
  "icmp6_hdr_field", "auth_hdr_expr", "auth_hdr_field", "esp_hdr_expr",
  "esp_hdr_field", "comp_hdr_expr", "comp_hdr_field", "udp_hdr_expr",
  "udp_hdr_field", "udplite_hdr_expr", "udplite_hdr_field", "tcp_hdr_expr",
  "tcp_hdr_field", "tcp_hdr_option_kind_and_field", "tcp_hdr_option_sack",
  "tcp_hdr_option_type", "tcpopt_field_sack", "tcpopt_field_window",
  "tcpopt_field_tsopt", "tcpopt_field_maxseg", "tcpopt_field_mptcp",
  "dccp_hdr_expr", "dccp_hdr_field", "sctp_chunk_type",
  "sctp_chunk_common_field", "sctp_chunk_data_field",
  "sctp_chunk_init_field", "sctp_chunk_sack_field", "sctp_chunk_alloc",
  "sctp_hdr_expr", "sctp_hdr_field", "th_hdr_expr", "th_hdr_field",
  "exthdr_expr", "hbh_hdr_expr", "hbh_hdr_field", "rt_hdr_expr",
  "rt_hdr_field", "rt0_hdr_expr", "rt0_hdr_field", "rt2_hdr_expr",
  "rt2_hdr_field", "rt4_hdr_expr", "rt4_hdr_field", "frag_hdr_expr",
  "frag_hdr_field", "dst_hdr_expr", "dst_hdr_field", "mh_hdr_expr",
  "mh_hdr_field", "exthdr_exists_expr", "exthdr_key", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_int16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,   378,   379,   380,   381,   382,   383,   384,
     385,   386,   387,   388,   389,   390,   391,   392,   393,   394,
     395,   396,   397,   398,   399,   400,   401,   402,   403,   404,
     405,   406,   407,   408,   409,   410,   411,   412,   413,   414,
     415,   416,   417,   418,   419,   420,   421,   422,   423,   424,
     425,   426,   427,   428,   429,   430,   431,   432,   433,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   464,
     465,   466,   467,   468,   469,   470,   471,   472,   473,   474,
     475,   476,   477,   478,   479,   480,   481,   482,   483,   484,
     485,   486,   487,   488,   489,   490,   491,   492,   493,   494,
     495,   496,   497,   498,   499,   500,   501,   502,   503,   504,
     505,   506,   507,   508,   509,   510,   511,   512,   513,   514,
     515,   516,   517,   518,   519,   520,   521,   522,   523,   524,
     525,   526,   527,   528,   529,   530,   531,   532,   533,   534,
     535,   536,   537,   538,   539,   540,   541,   542,   543,   544,
     545,   546,   547,   548,   549,   550,   551,   552,   553,   554,
     555,   556,   557,   558,   559,   560,   561,   562,   563,   564,
     565,   566,   567,   568,   569,   570,   571,   572,   573,   574,
     575,   576,   577,   578,   579,   580,   581,   582,   583,   584,
     585,   586,   587,   588,   589,   590,   591,   592,   593,   594,
     595,   596,   597,   598,   599,   600,   601,   602,   603,   604,
     605,   606,   607,    61,   123,   125,    40,    41,   124,    36,
      91,    93
};
#endif

#define YYPACT_NINF (-1598)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-970)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
   -1598,  7440, -1598,   696, -1598, -1598,   109,   130,   130,   130,
    1247,  1247,  1247,  1247,  1247,  1247,  1247,  1247, -1598, -1598,
    3177,   232,  1685,   238,  1385,   263,  5327,   692,  1150,   281,
    6907,    82,   269,   242, -1598, -1598, -1598, -1598,    93,  1247,
    1247,  1247,  1247, -1598, -1598, -1598,   621, -1598,   130, -1598,
     130,   100,  6288, -1598,   696, -1598,    -2,   115,   696,   130,
   -1598,   264,   309,  6288,   130, -1598,  -117, -1598,   130, -1598,
   -1598,  1247, -1598,  1247,  1247,  1247,  1247,  1247,  1247,  1247,
     337,  1247,  1247,  1247,  1247, -1598,  1247, -1598,  1247,  1247,
    1247,  1247,  1247,  1247,  1247,  1247,   382,  1247,  1247,  1247,
    1247, -1598,  1247, -1598,  1247,  1247,  1247,  1247,  1247,  1247,
    1617,  1247,  1247,  1247,  1247,  1247,   262,  1247,  1247,  1247,
     290,  1247,  1640,  2053,  2256,  2346,  1247,  1247,  1247,  2378,
   -1598,  1247,  2438,  2603,  1247, -1598,  1247,  1247,  1247,  1247,
    1247,   395,  1247, -1598,  1247, -1598,  1382,   799,   301,   366,
   -1598, -1598, -1598, -1598,   631,   987,  1209,  1372,  2665,  1744,
     622,  1545,  1331,   954,   152,   703,   808,   652,  2711,   177,
     479,   788,   359,   416,   570,   174,   897,   256,   997,  4289,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598,  3086, -1598, -1598,   188,  6546,   346,   834,   543,  6907,
     130, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598,   864, -1598, -1598,   347,
   -1598, -1598,   864, -1598, -1598, -1598, -1598,  1084, -1598, -1598,
   -1598,  1247,  1247,  1247,   -58, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598,   606,   619,   643, -1598, -1598, -1598,   246,   473,
     901, -1598, -1598, -1598, -1598, -1598, -1598,   102,   102, -1598,
     252,   130,  6249,  2648,   502, -1598,   322,   722, -1598, -1598,
   -1598, -1598, -1598,   144,   726,   556, -1598,   821, -1598,   500,
    6288, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,   743,
   -1598,   770, -1598, -1598, -1598,   561, -1598,  4595, -1598, -1598,
     553, -1598,    74, -1598,   306, -1598, -1598, -1598, -1598,   948,
   -1598,   108, -1598, -1598,   807, -1598, -1598, -1598,   994,   852,
     862,   530, -1598,   340, -1598,  5765, -1598, -1598, -1598,   839,
   -1598, -1598, -1598,   848, -1598,  6065,  6065, -1598, -1598,   116,
     548,   569, -1598, -1598,   585, -1598, -1598, -1598,   589, -1598,
     596,   872,  6288, -1598,   264,   309, -1598,  -117, -1598, -1598,
    1247,  1247,  1247,   669, -1598, -1598, -1598,  6288, -1598,   141,
   -1598, -1598, -1598,   154, -1598, -1598, -1598,   450, -1598, -1598,
   -1598, -1598,   528, -1598, -1598,  -117, -1598,   532,   612, -1598,
   -1598, -1598, -1598,  1247, -1598, -1598, -1598, -1598,  -117, -1598,
   -1598, -1598,   928, -1598, -1598, -1598, -1598,  1247, -1598, -1598,
   -1598, -1598, -1598, -1598,  1247,  1247, -1598, -1598, -1598,   936,
     974, -1598,  1247,   988, -1598,  1247, -1598,  1247, -1598,  1247,
   -1598,  1247, -1598, -1598, -1598, -1598,  1247, -1598, -1598, -1598,
    1247, -1598,  1247, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
    1247, -1598,   130, -1598, -1598, -1598, -1598,   966, -1598, -1598,
   -1598, -1598, -1598,   991,   166, -1598, -1598,   739, -1598, -1598,
     942,    81, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598,   406,   420, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598,  1448, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598,  2926, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598,  4303, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598,   405, -1598, -1598,   688, -1598, -1598,
   -1598, -1598, -1598, -1598,   698, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598,  2171, -1598, -1598,
   -1598, -1598,   731,   615,   760,   970, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598,   761,   750, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,   864,
   -1598, -1598, -1598, -1598,   -55,   -77,   603,   151, -1598, -1598,
   -1598,  4796,  1038,  7076,  6907, -1598, -1598, -1598, -1598,  1127,
    1131,    32,  1081,  1111,  1151,    76,  1174,  2171,  1176,  7076,
    7076,   757,  7076, -1598, -1598,  1128,  6907,   762,  7076,  7076,
    1169, -1598,  5843,   122, -1598,  1180, -1598, -1598,   858, -1598,
    1154,  1156,   743, -1598, -1598,   806,  1180,  1179,  1193,  1215,
    1180,   770, -1598,   105, -1598,  7076, -1598,  4997,  1239,   987,
    1209,  1372,  2665, -1598,  1545,   509, -1598, -1598, -1598,  1245,
   -1598, -1598, -1598, -1598,  7076, -1598,  1099,  1243,  1312,   982,
     732,   624, -1598, -1598, -1598, -1598,  1327,   989,  1338, -1598,
   -1598, -1598, -1598,  1350, -1598, -1598, -1598, -1598,   307, -1598,
   -1598,  1351,  1353, -1598,  1265,  1271, -1598, -1598,   553, -1598,
    1370, -1598, -1598, -1598, -1598,  1369, -1598,  5198, -1598,  1369,
   -1598,    46, -1598, -1598,   948, -1598,  1373, -1598,   130, -1598,
    1025, -1598,   130,   104, -1598,  7547,  7547,  7547,  7547,  7547,
    6907,   103,  7277, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598,  7547, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598,   580, -1598,  1110,  1365,  1371,
    1030,  1031,  1386, -1598, -1598, -1598,  7277,  7076,  7076,  1295,
     121,   696,  1394, -1598,  1172,   696,  1301, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598,  1368,  1054,  1056,  1059,
   -1598,  1061,  1065, -1598, -1598, -1598, -1598,  1133,  1119,   824,
    1180, -1598,  1322,  1324,  1325,  1333, -1598,  1341,  1079, -1598,
   -1598, -1598, -1598, -1598, -1598,  1337, -1598, -1598, -1598, -1598,
   -1598,  1247, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598,  1343,   799, -1598,
   -1598, -1598, -1598,  1346, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,   769,
   -1598, -1598,  3079,  1355, -1598,  1260, -1598, -1598,  1258, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,   945, -1598,
     955,  1329,  1118,  1443,  1326,  1326, -1598, -1598, -1598,  1230,
   -1598, -1598, -1598, -1598,  1228,  1240, -1598,  1235,  1242,  1241,
     156, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,  1376,
    1377, -1598, -1598, -1598, -1598,  1046, -1598,  1126, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598,  1395,  1399,  1138, -1598,  1401,
     200, -1598, -1598, -1598,  1152,  1157,  1164,  1403, -1598, -1598,
     757, -1598, -1598, -1598,  1406, -1598, -1598, -1598, -1598,  7076,
    2665,  1545,  1509,  5399, -1598,   108,   240,  1511,  1180,  1180,
    1419,  6907,  7076,  7076,  7076, -1598,  1421,  7076,  1477,  7076,
   -1598, -1598, -1598, -1598,  1428, -1598,    86,  1516, -1598, -1598,
     184,   204,   615, -1598,   448,   510,   143,  1490, -1598,  7076,
   -1598,   821,  1236,   212,   265, -1598,   815,  1386,   821, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598,  1391,   501, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,   671,   833,
   -1598,   922, -1598,  7076,  1546,  7076, -1598, -1598, -1598,   602,
     645,  7076,  1216, -1598, -1598,  7076,  7076,  7076,  7076,  7076,
    1460,  7076,  7076,   136,  7076,  1369,  7076,  1492,  1566,  1493,
    2170,  2170, -1598, -1598, -1598,  7076,   989,  7076,   989, -1598,
    1556,  1568, -1598,   762, -1598,  6907, -1598,  6907, -1598, -1598,
   -1598,  1110,  1365,  1371, -1598,   821, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598,  1248,  7547,  7547,  7547,  7547,  7547,  7547,
    7547,  7547,  7651,  7547,  7547,   670, -1598,  1207, -1598, -1598,
   -1598, -1598, -1598,  1491, -1598,   828,   666,  2969,  3319,  2677,
    4180,   239, -1598, -1598, -1598, -1598, -1598, -1598,  1238,  1246,
    1257, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598,  1590, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598,  1607, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,  1261,  1262,
   -1598, -1598, -1598, -1598, -1598, -1598,  1138,    94,  1517, -1598,
   -1598, -1598, -1598, -1598,  1132, -1598, -1598, -1598,  1339,  1076,
   -1598,  1428,   408, -1598,   415,    86, -1598,   697, -1598, -1598,
    7076,  7076,  1623, -1598,  1531,  1531, -1598,   240, -1598, -1598,
   -1598,  1285,  1511,  6288,   240, -1598, -1598, -1598, -1598, -1598,
   -1598,  7076, -1598, -1598,   157,  1340,  1342,  1620, -1598, -1598,
   -1598,  1356,    46, -1598,  6907,    46,  7076,  1603, -1598,  7499,
   -1598,  1461,  1393,  1362,   212, -1598,  1531,  1531, -1598,   265,
   -1598,  5843, -1598,  4328, -1598, -1598, -1598, -1598,  1675, -1598,
   -1598,  1160, -1598, -1598,  1160, -1598,  1618,  1160, -1598, -1598,
    7076, -1598, -1598, -1598, -1598, -1598,  1099,  1243,  1312, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598,  1682,  7076,  1528,  7076,
   -1598, -1598, -1598, -1598,   989, -1598,   989,  1369, -1598,   298,
    6288,  5948,   129, -1598, -1598, -1598,  1394,  1688, -1598, -1598,
    1110,  1365,  1371, -1598,   127,  1394, -1598, -1598,   815,  7547,
    7651, -1598,  1597,  1663, -1598, -1598, -1598, -1598, -1598,   130,
     130,   130,   130,   130,  1600,   483,   130,   130,   130,   130,
   -1598, -1598, -1598,   696, -1598,    54,  1604,  1608, -1598, -1598,
   -1598,   696,   696,   696,   696,   696,  6907, -1598,  1531,  1531,
    1357,  1205,  1606,   536,  1266,  1520, -1598, -1598, -1598,   696,
     696,   296, -1598,  6907,  1531,  1359,   536,  1266, -1598, -1598,
   -1598,   696,   696,   296,  1610,  1361,  1626, -1598, -1598, -1598,
   -1598,  5546,  3656,  2729,  5581,   311, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598,   786, -1598, -1598,  1613, -1598, -1598,  1614,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,  1616, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598,   816,   189,  1251,  1619,
   -1598, -1598, -1598, -1598, -1598,  1340,  1342, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598,  1356, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598,  7076, -1598, -1598, -1598, -1598,
    6907,  1374,   240, -1598, -1598, -1598, -1598, -1598,  1255,  1703,
   -1598,  1631, -1598,  1633, -1598,  1255,  1641, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598,  7076,   102,   102,   821,  1386, -1598,
     147,  1644, -1598,   757, -1598, -1598, -1598, -1598, -1598, -1598,
     696, -1598,   501, -1598, -1598, -1598, -1598, -1598, -1598,  7076,
   -1598,  1643, -1598,  1369,  1369,  6907, -1598,   316,  1409,  1720,
     821, -1598,  1394,  1394,  1540,  1656, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598,   130,   130,   130, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,  1727,
   -1598, -1598, -1598, -1598, -1598, -1598,   916, -1598,   696,   696,
    -117, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598,  1185, -1598, -1598, -1598, -1598, -1598,  1010, -1598,
   -1598, -1598, -1598, -1598,   550,   696,  -117,   759,  1010, -1598,
   -1598, -1598,  1621,   363,   696, -1598, -1598, -1598, -1598, -1598,
   -1598,   961,   235,  1292, -1598, -1598,  1762, -1598,  1138, -1598,
   -1598,  1417,   526,  1247, -1598, -1598, -1598, -1598, -1598,  1531,
    1671,   526,  1674,  1247, -1598, -1598, -1598, -1598, -1598,  1676,
    1247, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598,  6288, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598,  1488, -1598,    88, -1598, -1598, -1598,
      86, -1598, -1598, -1598, -1598, -1598, -1598,  1677,  1494,  1428,
   -1598, -1598, -1598,  7076,  1426,  6907, -1598, -1598,  1673,  5948,
   -1598, -1598,  1599,   696,  1431,  1432,  1434,  1439,  1440, -1598,
   -1598, -1598,  1441,  1442,  1444,  1445,  1694,  6907, -1598, -1598,
   -1598, -1598,   536, -1598,  1266, -1598,  6738, -1598, -1598,  2110,
   -1598,   149,   696,    61,   696, -1598, -1598, -1598, -1598, -1598,
    1699, -1598,  1453, -1598, -1598,   696,   696, -1598,   696,   696,
     696,   696,   696, -1598,  1687,   696, -1598,  1455, -1598, -1598,
   -1598, -1598, -1598,  1706,  1340,  1342, -1598, -1598,  1467,   821,
   -1598, -1598,  1540, -1598, -1598, -1598, -1598, -1598,  1470,  1471,
    1472, -1598, -1598, -1598, -1598,  1259, -1598, -1598, -1598,  6907,
     696,  1819,  1820, -1598,   536, -1598, -1598, -1598, -1598,   696,
    1185,  1729, -1598, -1598, -1598,   515, -1598, -1598, -1598, -1598,
   -1598, -1598,   131, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598,  1726, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
     526, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,  1599,
    1498,  3993,  3839,  5674,   835, -1598, -1598, -1598,  1244,  1625,
     656,  1014,    70,  1479,  1621,   916, -1598,  6907,  1185, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598,  1731,  1732,   120, -1598,
    1830,   132, -1598,   696, -1598, -1598, -1598, -1598,   696,   696,
     696,   696,   696,  1158,   426,  1364,   696,   696,   696,   696,
   -1598, -1598,   363, -1598, -1598,  1833, -1598, -1598, -1598, -1598,
   -1598,  1740,  1726,   696, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598,   696,   696,   696, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_int16 yydefact[] =
{
       2,     0,     1,     0,     4,     5,     0,     0,     0,     0,
     366,   366,   366,   366,   366,   366,   366,   366,   370,   373,
     366,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   177,   372,     8,    14,    15,     0,   366,
     366,   366,   366,    36,    35,     3,     0,    39,     0,   367,
       0,   391,     0,    34,     0,   361,     0,     0,     0,     0,
     535,    54,    56,     0,     0,   228,     0,   250,     0,   274,
      40,   366,    41,   366,   366,   366,   366,   366,   366,   366,
       0,   366,   366,   366,   366,    42,   366,    43,   366,   366,
     366,   366,   366,   366,   366,   366,     0,   366,   366,   366,
     366,    44,   366,    45,   366,   397,   366,   397,   366,   397,
     397,   366,   366,   397,   366,   397,     0,   366,   397,   397,
       0,   366,   397,   397,   397,   397,   366,   366,   366,   397,
      18,   366,   397,   397,   366,    47,   366,   366,   366,   366,
     397,     0,   366,    48,   366,    49,     0,     0,     0,   692,
     663,   362,   363,   364,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     870,   871,   872,   873,   874,   875,   876,   877,   878,   879,
     880,   881,   882,   883,   884,   885,   886,   887,   888,   889,
     891,     0,   893,   892,     0,     0,     0,     0,    17,     0,
       0,    53,   659,   658,   664,   665,   192,   675,   676,   669,
     861,   670,   673,   677,   674,   671,   672,   666,   977,   978,
     979,   980,   981,   982,   983,   984,   985,   986,   987,   988,
     989,   990,    22,   992,   993,   994,   667,  1202,  1203,  1204,
    1205,  1206,  1207,  1208,  1209,   668,     0,   189,   190,     0,
      50,   173,     0,    51,   175,   178,    52,   179,   371,   368,
     369,   366,   366,   366,    10,   785,   758,   760,    38,    37,
     374,   376,     0,     0,     0,   393,   392,   394,     0,   525,
       0,   643,   644,   645,   852,   853,   854,   430,   431,   857,
     650,     0,     0,     0,   446,   454,     0,   478,   503,   515,
     516,   592,   598,   619,     0,     0,   897,     7,    59,   399,
     401,   414,   402,   212,   429,   410,   434,   409,    10,   444,
      29,   452,   407,   408,   417,   506,   418,     0,   419,   428,
     523,   422,   591,   423,   597,   424,   425,   420,    23,   617,
     426,     0,   427,   412,     0,   649,   411,   694,   697,   699,
     701,   703,   704,   711,   713,     0,   712,   656,   433,   861,
     415,   421,   413,   666,    30,     0,     0,    33,   385,     0,
       0,     0,    58,   379,     0,    62,   243,   242,     0,   382,
       0,     0,     0,   535,    79,    81,   228,     0,   250,   274,
     366,   366,   366,    10,   785,   758,   760,     0,   119,     0,
     103,   104,   105,     0,    97,    98,   106,     0,    99,   100,
     107,   108,     0,   101,   102,     0,   109,     0,   111,   112,
     762,   763,   761,   366,    10,    19,    21,    27,     0,   142,
     154,   398,   156,   121,   122,   123,   124,   366,   125,   127,
     151,   150,   149,   143,   366,   397,   147,   146,   148,   762,
     763,   764,   366,     0,    10,   366,   128,   366,   131,   366,
     134,   366,   140,    19,    21,    27,   366,   137,    46,    10,
     366,   158,   366,   161,    21,   164,   165,   166,   167,   170,
     366,   169,     0,   999,   996,   997,   998,     0,   683,   684,
     685,   686,   687,   689,     0,   902,   904,     0,   903,    28,
       0,     0,  1200,  1201,  1199,  1001,  1002,  1003,    11,  1009,
    1005,  1006,  1007,  1008,    16,     0,     0,  1011,  1012,  1013,
    1014,  1015,     8,  1033,  1034,  1028,  1023,  1024,  1025,  1026,
    1027,  1029,  1030,  1031,  1032,     0,    14,  1045,  1048,  1047,
    1046,  1049,  1050,  1051,  1044,  1053,  1054,  1055,  1056,  1052,
    1065,  1066,  1058,  1059,  1060,  1062,  1061,  1063,  1064,    15,
    1068,  1073,  1070,  1069,  1074,  1072,  1071,  1075,  1067,  1078,
    1081,  1077,  1079,  1080,  1076,  1084,  1083,  1082,  1086,  1087,
    1088,  1085,  1092,  1093,  1090,  1091,  1089,  1098,  1095,  1096,
    1097,  1094,  1111,  1105,  1108,  1109,  1103,  1104,  1106,  1107,
    1110,  1112,     0,  1099,  1146,  1144,  1145,  1143,  1198,  1195,
    1196,     0,  1197,    25,  1216,    14,  1215,   929,    15,  1214,
    1217,   927,   928,    17,     0,    24,    24,     0,  1218,  1221,
    1220,  1224,  1223,  1225,     0,  1222,  1212,  1211,  1210,  1233,
    1230,  1228,  1229,  1231,  1232,  1227,  1236,  1235,  1234,  1240,
    1239,  1242,  1238,  1241,  1237,   862,   865,   866,   867,    27,
     868,    17,   860,   863,   864,   944,   945,   951,   937,   938,
     936,   946,   947,   967,   940,   949,   942,   943,   948,   939,
     941,   934,   935,   965,   964,   966,    27,     0,     9,   952,
     908,   907,     0,   711,     0,     0,    24,  1244,  1246,  1247,
    1248,  1243,   912,   913,   890,   911,     0,   657,   991,   172,
     191,   174,   180,   181,   183,   182,   185,   186,   184,   187,
     782,   782,   782,    64,     0,     0,   478,     0,   388,   389,
     390,     0,     0,     0,     0,   859,   858,   855,   856,     0,
       0,     0,   862,   860,     0,     0,     0,     0,     9,     0,
       0,   487,     0,   476,   477,     0,     0,     0,     0,     0,
       0,     6,     0,     0,   715,     0,   400,   403,     0,   406,
       0,     0,   445,   448,   416,     0,     0,     0,     0,     0,
       0,   453,   455,     0,   502,     0,   824,     0,     0,    11,
      16,     8,    14,   823,    15,     0,   827,   825,   826,     0,
     822,   821,   813,   814,     0,   553,   556,   558,   560,   562,
     563,   568,   573,   571,   572,   574,   576,   514,   540,   541,
     551,   815,   542,   549,   543,   550,   546,   547,     0,   544,
     545,     0,   575,   548,     0,     0,   532,   531,   524,   527,
       0,   610,   611,   612,   590,   595,   608,     0,   596,   601,
     613,     0,   635,   636,   618,   620,   623,   633,     0,   661,
       0,   660,     0,     0,   651,     0,     0,     0,     0,     0,
       0,     0,     0,   845,   846,   847,   848,   849,   850,   851,
      11,    16,     8,    14,   837,   838,    15,   839,   836,   835,
     840,   833,   834,    22,   841,    25,   843,     0,   828,   798,
     829,   708,   709,   810,   797,   787,   786,   802,   804,   806,
     808,   809,   796,   830,   831,   799,     0,     0,     0,     0,
       7,     0,   752,   751,   809,     0,     0,   330,    76,   196,
     213,   229,   256,   275,   395,    78,     0,     0,     0,     0,
      85,     0,     0,   782,   782,   782,    87,     0,     0,   478,
       0,    96,     0,     0,     0,     0,   110,     0,     0,   782,
     114,   117,   115,   118,   120,     0,   157,   126,   145,   144,
       9,   366,   130,   129,   132,   135,   141,   136,   133,   139,
     138,   160,   159,   162,   163,   168,   171,     0,     0,   682,
     680,   681,    12,     0,   900,   693,   690,   691,  1000,  1004,
      11,    14,    11,    14,  1010,  1035,  1036,  1037,  1038,    14,
    1020,  1057,     0,  1129,  1135,  1133,  1124,  1125,  1128,  1130,
    1119,  1120,  1121,  1122,  1123,  1131,  1126,  1127,  1132,  1101,
    1134,  1100,  1150,  1147,  1148,  1149,  1151,  1152,  1153,  1154,
    1155,  1156,  1157,  1158,  1159,  1160,  1161,  1162,  1163,  1164,
    1181,    26,  1193,   923,   924,   930,    24,   925,  1213,     0,
       0,   869,   950,   953,   954,     0,   956,     0,   955,   957,
     958,     9,     9,   959,   931,     0,     0,   905,  1245,     0,
       0,   678,   176,   188,     0,     0,     0,     0,   295,    10,
     487,   320,    19,   300,     0,    21,   325,   759,    27,     0,
      14,    15,   517,     0,   526,     0,   637,   639,     0,     0,
       0,     0,     0,     0,     0,     9,     0,     0,   959,     0,
     447,    19,   485,   486,     0,    21,     0,     0,   632,    23,
     627,   626,     0,   631,   629,   630,     0,   604,   606,     0,
     727,     7,     7,   729,   724,   726,   809,   748,     7,   714,
     396,   221,   450,   451,   449,   468,    11,     0,     0,   466,
     462,   457,   458,   459,   460,   463,   461,   456,     0,     0,
      22,     0,   582,     0,   577,     0,   816,   819,   820,   817,
     818,     0,     0,   540,   549,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   584,     0,     0,     0,     0,
       0,     0,   529,   530,   528,     0,     0,     0,   599,   622,
     627,   626,   621,     0,   662,     0,   653,     0,   652,   695,
     696,   698,   700,   702,   705,     7,   435,   437,   710,   817,
     818,   832,   842,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   793,   792,   809,   895,   976,
     754,   753,    31,     0,    32,     0,     0,     0,     0,     0,
       0,     0,    95,   196,   213,   229,   256,   275,     0,     0,
       0,    10,    19,    21,    27,   386,   375,   377,   380,   383,
     275,     9,   155,   152,     9,     0,   688,   679,    28,  1016,
    1018,  1017,  1019,  1039,  1040,  1042,  1041,  1043,  1022,    14,
    1129,  1133,  1128,  1132,  1134,     0,  1141,  1113,  1138,  1115,
    1142,  1118,  1139,  1140,  1116,  1136,  1137,  1114,  1117,  1178,
    1177,  1179,  1180,  1186,  1168,  1169,  1170,  1171,  1183,  1172,
    1173,  1174,  1175,  1176,  1184,  1185,  1187,  1188,  1189,  1190,
    1191,  1192,  1165,  1167,  1166,  1182,    25,   926,     0,     0,
      14,    14,    15,    15,   932,   933,   905,   905,     0,    13,
     910,   914,   915,    17,     0,   310,   315,   305,     0,     0,
      65,     0,     0,    72,     0,     0,    67,     0,    74,   519,
       0,     0,   518,   640,     0,     0,   734,   638,   730,   899,
     898,     0,   723,     0,   721,   896,   894,     9,   442,     9,
       9,     0,     9,   475,     0,   488,   491,     0,   484,   480,
     479,   481,     0,   614,     0,     0,     0,     0,   718,     0,
     719,     0,    10,     0,   728,   737,     0,     0,   747,   725,
     735,   717,   716,     0,   467,    14,   471,   472,    22,   470,
     504,     0,   508,   505,     0,   510,     0,     0,   512,   583,
       0,   587,   589,   552,   554,   555,   557,   559,   561,   569,
     570,   564,   567,   566,   565,   579,   578,     0,     0,     0,
     968,   969,   970,   971,   593,   609,   600,   602,   634,     0,
       0,     0,     0,   438,   844,   795,   789,     0,   800,   801,
     803,   805,   807,   794,   706,   788,   707,   811,   812,     0,
       0,   706,     0,     0,    77,   332,   331,   334,   333,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      55,   198,   197,     0,   195,     0,     0,     0,    57,   215,
     214,     0,     0,     0,     0,     0,     0,   239,     0,     0,
       0,     0,     0,     0,     0,     0,    60,   231,   230,     0,
       0,     0,   404,     0,     0,     0,     0,     0,    61,   258,
     257,     0,     0,     0,     0,     0,     0,    10,    63,   277,
     276,     0,     0,     0,     0,     0,   310,   315,   305,    88,
      93,    89,    94,     0,   116,   153,     0,   901,  1021,     0,
    1194,  1219,  1226,   960,   961,   962,   963,    20,     0,    13,
     906,   922,   918,   917,   916,    17,     0,     0,     0,     0,
      10,   297,   296,   299,   298,   488,   491,    19,   322,   321,
     324,   323,    21,   302,   301,   304,   303,   481,    27,   327,
     326,   329,   328,   520,   522,     0,   365,   732,   733,   731,
       0,     0,   722,   973,   443,   974,     9,   972,     0,   493,
     495,     0,    19,     0,    19,     0,     0,    21,   628,   624,
     625,    23,    23,   605,     0,     0,     0,     7,   749,   750,
       0,     0,   739,   487,   738,   745,   746,   736,   432,   222,
       0,   465,     0,   464,   507,   509,   513,   511,   580,     0,
     586,     0,   588,   594,   603,     0,   641,     0,     0,     0,
       7,   436,   791,   790,   536,     0,   387,   294,   378,   212,
     381,   228,   250,   384,   274,   194,     0,     0,     0,   294,
     294,   294,   294,   199,   359,   360,   356,   358,   357,     0,
     355,   216,   218,   217,   220,   219,     0,   226,     0,     0,
       0,   273,   272,   270,   271,   335,   337,   338,   336,   291,
     339,   292,     0,   290,   246,   247,   249,   248,     0,   245,
     240,   241,   237,   405,     0,     0,     0,     0,     0,   269,
     268,   266,     0,     0,     0,   280,    80,    82,    83,    84,
      86,     0,     0,     0,   113,   995,     0,   909,   905,   921,
     919,     0,     0,     0,     9,   312,   311,   314,   313,     0,
       0,     0,     0,     0,     9,   317,   316,   319,   318,     0,
       0,     9,   307,   306,   309,   308,   755,    66,   783,   784,
      73,    68,   757,    75,   521,     0,   654,   975,   497,   498,
     499,   500,   501,   490,     0,   473,     0,   492,   474,   494,
       0,   483,   615,   616,   607,   720,     9,     0,     0,     0,
     223,   469,   581,     0,     0,     0,   642,   648,     0,   440,
     439,   537,   538,     0,     0,     0,     0,     0,     0,   294,
     294,   294,     0,     0,     0,     0,     0,     0,   233,   235,
     236,   238,     0,   232,     0,   234,     0,   259,   267,     0,
     265,     0,     0,     0,     0,   283,   281,     9,     9,     9,
       0,    13,     0,   768,    22,     0,     0,    70,     0,     0,
       0,     0,     0,    71,     0,     0,    69,     0,   489,   496,
     482,   743,     9,     0,   488,   491,   585,   646,     0,     7,
     539,   533,   536,   330,   213,   229,   256,   275,     0,     0,
       0,   295,   320,   300,   325,   354,   227,   293,   244,     0,
       0,     0,   224,   255,     0,    10,    19,    21,    27,     0,
       0,     0,   349,   343,   342,   346,   341,   344,   345,   278,
     288,   287,     0,   284,   289,   279,    91,    92,    90,  1102,
     920,     0,   767,   774,   776,   779,   780,   777,   778,   781,
       0,   770,   655,   744,    10,    19,    19,   647,   441,   538,
       0,     0,     0,     0,     0,   310,   315,   305,     0,     0,
       0,     0,     0,     0,     0,     0,   262,     0,     0,   251,
     253,   252,   254,   264,   260,   350,     0,     0,     7,   282,
       0,     0,   771,     0,   740,   741,   742,   534,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     351,   352,     0,   340,   263,   225,   261,   348,   347,   286,
     285,     0,     0,     0,   769,   211,   200,   201,   202,   203,
       9,     9,     9,    10,    19,    21,    27,   353,   773,   772,
     775,     0,     0,     0,   204,   209,   205,   210,   207,   208,
     206
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
   -1598, -1598,    -1, -1068,    56,  -929,  -323,  -436, -1598, -1412,
     -27,   -13,  1319,  -593, -1598,  -451, -1598,  -467,  -870, -1052,
    -534,  -804, -1598,  -461,   546, -1598,    20, -1598, -1598,  1825,
   -1598, -1598, -1598, -1598, -1598, -1598,  1569, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598,    36, -1598,  1458, -1598,   582,  -296, -1210, -1598, -1598,
   -1448,  -385, -1232,  -389,   289,   -31,  -383, -1598, -1204, -1231,
   -1598,  -396, -1219,  -202, -1598,  -176,   -28, -1452,  -646,   -85,
     -84, -1482, -1477, -1475,   -81,   -86,   -70, -1598, -1598,  -150,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,    87,  -712,
   -1275,  1786,   -63,  3066, -1598,  1504, -1598, -1598,    92, -1598,
     355,   710, -1598, -1598,  2427, -1598,  -733,  1489, -1598, -1598,
     237,  1790,  1040,  2214,   -34, -1598, -1598, -1242, -1184,  -307,
   -1598, -1598, -1598, -1598, -1598, -1598,   172, -1598, -1598, -1598,
   -1598,  1101, -1598, -1598, -1598,  1093, -1598, -1598, -1598,   198,
   -1598,  1585, -1287,   257, -1598, -1027, -1462, -1289, -1460, -1288,
     230,   231, -1598, -1598,  -897, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598,  1047,  -291,  1506,   -45,  -109,  -445,   707,   712,
     706, -1598,  -698, -1598, -1598, -1598, -1598, -1598, -1598,  1858,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,  -306,
     691, -1598, -1598, -1598, -1598,  1048,   491,  -782,   492,  1155,
     700, -1158, -1598, -1598,  1635, -1598, -1598, -1598, -1598,  1053,
   -1598, -1598,   575,   -29,  -754,  -316,   939,   -11, -1598, -1598,
   -1598,   930,   -26, -1598, -1598, -1598, -1598, -1598,  -168,  -193,
   -1598, -1598,   675,  -718,  1730,   -56, -1598,   773, -1117, -1598,
   -1378, -1598, -1598,   533, -1237, -1598, -1598,   504,   503, -1598,
   -1598,  1563,  -553,  1537,  -549,  1539,  -527,  1541,  1831, -1598,
   -1597, -1598, -1598,  -127, -1598, -1598,   -95,  -547,  1549, -1598,
    -349,  -276,  -756,  -755,  -757, -1598,  -300,  -742, -1598,   972,
    1660,  -758, -1598, -1329,  -292,    67,  1648, -1598,   -32, -1598,
     241, -1598, -1262, -1598,   681, -1598, -1598, -1598, -1598, -1598,
     684,  -234,   709,  1323,   716,  1653,  1655, -1598, -1598,  -444,
      95, -1598, -1598, -1598,   854, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,   938,   940,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
     919, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598, -1598,
   -1598, -1598, -1598, -1598, -1598, -1598
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
       0,     1,  1579,   772,  1188,  1084,   733,  1186,  1297,  1611,
    1239,  1240,  1187,   714,   478,   971,  1797,   972,   718,   860,
    1067,  1062,  1356,   973,  1004,   784,  1580,    45,    46,    47,
      72,    85,    87,   412,   416,   421,   408,   101,   103,   130,
     976,   440,   135,   143,   145,   260,   263,   266,   267,   729,
    1092,   261,   211,   380,  1533,  1267,   381,  1268,  1443,  1960,
    1746,   384,  1269,   385,  1768,  1769,   388,  1969,  1270,  1559,
    1753,   390,  1271,  1904,  1982,  1983,  1761,  1762,  1874,  1379,
    1384,  1618,  1616,  1617,  1382,  1387,  1266,  1763,  1541,  1902,
    1975,  1976,  1977,  2024,  1542,  1543,  1736,  1737,  1716,   212,
    1647,    48,    49,    59,   415,    51,   419,  1719,    65,   424,
    1721,    69,   429,  1724,   410,   411,  1717,   285,   286,   287,
      52,   392,  1396,   442,  1545,   319,   320,  1561,   321,   322,
     323,   324,   325,   326,  1236,  1492,  1493,   327,   328,   329,
     782,   783,   330,   331,   791,   792,  1176,  1170,  1448,  1449,
     332,  1104,  1421,  1667,   333,  1134,  1662,  1415,  1664,  1416,
    1417,  1843,   334,   335,  1452,   794,   336,   337,   338,   339,
     340,   848,   849,  1518,   379,  1872,  1941,   815,   816,   817,
     818,   819,   820,   821,  1472,   822,   823,   824,   825,   826,
     827,   341,   342,   854,   343,   344,   858,   345,   346,   855,
     856,   347,   348,   349,   864,   865,  1137,  1138,  1139,   866,
     867,  1115,  1116,   350,   351,   352,   353,   354,   873,   874,
     355,   356,   213,   828,   870,   909,   829,   357,   217,  1002,
     503,   504,   830,   511,   358,   359,   360,   361,   362,   363,
     911,   912,   913,   364,   365,   366,   773,   774,  1403,  1404,
    1152,  1153,  1154,  1397,  1398,  1439,  1434,  1435,  1440,  1155,
    1677,   931,  1624,   734,  1636,   736,  1642,   737,   433,   463,
    1915,  1825,  2041,  2042,  1808,  1818,  1094,  1631,   735,   367,
     932,   933,   917,   918,   919,   920,  1156,   922,   831,   832,
     833,   925,   926,   368,   747,   834,   672,   673,   220,   370,
     835,   509,  1369,   702,   836,  1090,   715,  1373,  1615,   223,
     837,   634,   839,   635,   840,   697,   698,  1081,  1082,   699,
     841,   842,   371,   372,   843,   228,   497,   229,   518,   230,
     524,   231,   532,   232,   546,  1019,  1309,   233,   554,   234,
     559,   235,   569,   236,   578,   237,   584,   238,   587,   239,
     591,   240,   596,   241,   601,   242,   613,  1039,  1040,  1041,
    1327,  1319,  1324,  1317,  1321,   243,   617,  1060,  1355,  1338,
    1344,  1333,  1061,   244,   623,   245,   514,   246,   247,   648,
     248,   636,   249,   638,   250,   640,   251,   645,   252,   655,
     253,   658,   254,   664,   255,   711
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      43,   214,    53,   952,   218,   779,   748,   988,   950,   269,
     387,   949,   703,   777,   989,   951,   915,   994,   318,   216,
     369,    44,   987,   214,   270,  1107,   218,   778,  1573,   382,
    1157,   369,   968,  1241,   214,   871,   966,   218,   859,  1571,
    1065,   716,   441,  1583,   441,   279,   441,   441,  1143,   974,
     441,  1293,   441,   374,   742,   441,   441,   377,  1585,   441,
     441,   441,   441,  1160,  1582,   921,   441,  1489,   264,   441,
     441,  1593,  1584,  1381,  1171,   934,   934,   441,  1175,  1219,
     956,   770,  1008,  1428,  1430,  1562,  1562,  1423,   938,   916,
    1441,   268,  1625,  1626,    56,    57,    58,   219,  1637,   948,
    1679,  1242,  1068,   838,  1607,  1609,  1793,    66,    67,  1791,
    1490,   970,  1792,  1709,  1777,  1774,  1192,  1229,  1230,   219,
    1648,  1231,  1233,  1232,   771,   771,   868,  1237,  1120,  1158,
     219,   868,  1734,  1735,  -663,   280,  1710,   281,  2038,  2072,
     256,   982,  -663,  -663,  -663,  -663,   378,   674,   150,   872,
    1223,   383,  1364,  1365,   936,   389,   991,   282,   850,   868,
    1649,  1685,  1686,  1828,  1980,  1981,  1829,  1491,   396,   397,
     398,  1971,  1088,   151,   152,   153,   214,  1658,  1125,   218,
     214,  1099,   271,   218,   423,   425,   426,  1105,  1102,  1419,
       3,  1929,  -658,     4,   438,     5,  1408,  1799,   962,  -658,
    -658,  -658,  -658,   449,   450,    55,  -624,  1006,  1071,   456,
    1108,   963,  -665,    54,  1920,     6,     7,     8,     9,  -665,
    -665,  -665,  -665,  1980,  1981,  1100,  -625,  1424,   766,  -756,
     487,   488,  1097,    55,   491,  1072,     3,   317,  -658,     4,
       3,     5,   210,     4,    55,     5,  1178,  1707,  1107,  1856,
      63,  1972,  1973,  1083,   151,   152,   153,    55,  -665,  1179,
    1659,     6,     7,     8,     9,     6,     7,     8,     9,  1352,
     674,   221,   219,  1748,  1749,  1180,   219,  1101,  1809,   999,
    1574,    71,  1455,  1575,  1458,  1810,  1353,    86,   369,  1775,
     614,   214,   719,   221,   218,   585,  -756,   717,   721,  1098,
       4,   646,     5,  1705,   221,  1562,   767,   454,   455,   914,
    1456,   586,     3,  1128,   749,     4,   102,     5,  1354,   914,
     914,  1865,  1811,   407,  1809,   625,   647,   262,   144,  1394,
     741,  1810,  1395,   505,   506,   507,   908,     6,     7,     8,
       9,   387,  1573,   615,   616,   265,   908,   908,   880,   628,
     750,   375,  1574,  1571,  1436,  1575,  1812,  1437,   945,  1371,
     369,  1393,  1594,   214,   881,  1595,   218,  1007,  1811,   387,
     272,   625,   273,   961,  1420,   369,  1660,  1773,   214,   459,
    1126,   218,   387,   656,   745,   745,  1121,   219,   751,  1773,
     857,  1206,   441,  1207,   882,   628,   851,   852,   853,  1562,
    1562,  1576,  1812,  2043,  1281,   210,  1399,  1400,   657,     3,
    1283,  1282,     4,   210,     5,  1649,     3,  1000,  1001,     4,
     210,     5,  1181,   257,   258,   259,   400,     3,  1368,   210,
       4,  1608,     5,  1284,     6,     7,     8,     9,   283,   284,
     490,     6,     7,     8,     9,  1660,   221,  1970,  1961,  1473,
     221,  1857,     6,     7,     8,     9,  -673,  1235,  1227,   219,
    1813,   210,   210,  -673,  -673,  -673,  -673,   210,   376,  1425,
     937,   430,  2005,  1576,   219,  2006,  1261,  1159,  1653,   210,
    1654,  1655,  1431,  1657,  1711,  -663,  2039,  2073,  1498,  1499,
     317,  1709,  1500,  1502,  1501,   210,   378,  1432,   510,  1990,
     280,  1974,  -673,  1470,   281,  1106,  1813,   964,   210,   383,
     700,  2025,  2028,  1433,   389,  1809,  1010,  -478,  -674,  1020,
     701,  1205,  1810,  1773,  1577,  -674,  -674,  -674,  -674,   775,
    1012,  1011,  1357,  1835,  1918,  2055,  1911,  2036,  2053,  1939,
    2037,  2054,  -658,  1208,  1814,  1013,   978,  1864,   508,  1372,
     627,  1117,  1600,    55,  1694,  1896,  1021,  1695,  1887,  1811,
    1697,   221,  -665,  1930,  -674,   871,  1555,   460,  1555,   432,
    1934,  1935,  1726,  1142,  1299,   775,  1301,  1255,  1693,   996,
     775,   304,   995,   304,   461,   965,  1555,  1244,  1014,   967,
    1908,   844,   845,  1812,  1578,   637,  1577,   306,  1063,   306,
    1245,   304,   307,  1209,   307,   775,  1238,  1243,   760,  1855,
     257,   258,   259,   618,   401,  1064,   402,   306,  -193,  1852,
    1853,   278,   307,   880,   761,     4,  1257,     5,   851,   852,
     853,    55,  1202,   221,   625,    55,  1095,  1096,  1386,  1755,
     769,   386,  1869,  1672,  1446,   619,   620,  1388,   221,  1447,
    1256,  1383,   639,  1706,   627,  1272,  1859,     3,   628,   431,
       4,   432,     5,  -212,  1756,  1757,  1790,     3,  1418,   882,
       4,  1866,     5,   631,   632,  1107,   621,  1244,  1203,   705,
    1413,   625,     6,     7,     8,     9,  -923,  1678,  -923,   720,
    1509,  1913,     6,     7,     8,     9,  1914,  1813,     3,  1157,
       4,     4,     5,     5,   936,   628,  1143,  1938,   738,   622,
    1100,   222,  1234,  2012,   224,   214,  1151,  1903,   218,   763,
     764,   739,   210,     6,     7,     8,     9,  1837,  2014,  -924,
    1444,  -924,   641,   222,  2011,   555,   224,   214,   846,   225,
     218,   847,  2013,   908,   222,   740,   226,   224,   775,  1157,
    1464,  1465,  1200,   633,  1201,   775,   556,  1471,  -478,   743,
    1727,   225,  1728,  1627,  1899,  1093,   775,  1892,   226,   557,
    1632,  1573,   225,   150,  1450,  1189,  1380,   631,   632,   226,
    1612,  2081,  1571,  1758,  1451,  1193,   597,     3,   759,   399,
       4,  1190,     5,  1729,  1730,  1731,  1732,   512,   513,   871,
     151,   152,   153,  1759,  1760,   428,  -673,   642,   643,   644,
     768,   219,     6,     7,     8,     9,  1591,     3,   598,   599,
       4,   600,     5,  1592,   452,   771,   914,  1574,  1562,  1562,
    1575,  1590,     4,   219,     5,  1263,     3,  1253,  -923,     4,
     775,     5,     6,     7,     8,     9,   908,   908,   908,   908,
     908,   214,   872,   908,   218,   588,  1374,   633,  1278,  1279,
    1280,     6,     7,     8,     9,   589,   590,  1512,  -674,   877,
     914,  2008,   746,   746,  1291,  1917,  1574,   793,   908,  1575,
     878,  -924,  1303,  1165,   227,  1923,   222,   871,   879,   224,
     222,   927,  1926,   224,   712,   713,  1496,   908,  -923,  1304,
     928,   624,   939,  1505,  1305,  1306,   373,   763,   764,  1801,
     498,   499,  1487,   625,   225,   626,  1166,   373,   225,   558,
       4,   226,     5,   940,  1887,   226,   869,  1931,  1402,   282,
    1262,  1167,   785,   627,  1264,   150,  1450,   628,   592,   941,
     629,  -924,   593,   942,  1495,  1497,  1454,   219,  1576,  1802,
     943,  1503,  1497,  1506,  1508,  1224,  -756,  1103,  1589,  1226,
     763,   764,     3,   291,   292,     4,  -274,     5,   293,   215,
    2069,   975,   386,   997,   594,   595,  1168,   131,  1986,  1987,
    1988,  -765,   132,   133,  1300,   221,  1302,     6,     7,     8,
       9,   215,  1308,  1879,  1880,  1881,   775,  1576,   134,   998,
     386,   222,   215,  2003,   224,  1307,   775,   221,   762,   875,
     876,  2058,   649,   386,     4,     3,     5,  1894,     4,  -766,
       5,  1514,  1800,   630,   150,  1450,   763,   764,   650,   225,
     780,   781,  1117,   981,  1402,  1457,   226,   775,  1251,  1003,
       6,     7,     8,     9,  1992,  1005,   500,   501,  1069,   651,
     502,  1252,  1638,  1253,  1801,   652,   631,   632,  1070,   227,
    1169,  1132,  1133,   227,  1085,   706,   786,   787,   788,   789,
     790,  1577,  1087,   222,   707,   708,   224,     3,   709,   710,
       4,   579,     5,  1882,  1883,  1884,  1885,  1803,   222,   862,
     863,   224,   214,  1086,  1802,   218,  1651,   580,   515,   516,
     517,   225,     6,     7,     8,     9,   581,  1091,   226,  1682,
     659,  1089,   582,   583,  1195,  1196,   225,   151,   152,   153,
    1577,   221,  1113,   226,   660,  1246,  1247,  1157,   763,   764,
     722,   661,   723,  1122,   724,   725,   633,  1322,  1323,   653,
     654,  1794,   726,   727,   215,  1325,  1326,  1474,   215,   662,
    1118,  2091,  2092,  2093,  1119,   663,   775,  1360,  1361,     3,
    1712,  1713,     4,  1123,     5,  1831,  1193,  1193,  1193,  1193,
    1193,  1804,  1193,  1193,   373,   728,  1830,  1833,  1703,  1251,
    1704,  1480,  1480,  1708,     6,     7,     8,     9,   219,     4,
    2052,     5,  1263,  1892,  1253,   136,   214,   137,   214,   218,
    1851,   218,   138,  1124,   139,   257,   258,   259,   140,  1497,
    1497,  1845,  1161,  1848,  1251,   908,   908,   908,   908,   908,
     908,   908,   908,   908,   908,   908,  1127,  1510,  1129,  1253,
    1136,  1142,  1803,  1948,  1949,  1950,   369,  1362,  1363,   214,
     771,  1429,   218,  1613,  1614,     3,   373,   141,     4,   142,
       5,  1801,     3,  1149,  1785,     4,  1162,     5,  1163,   215,
    1197,   373,   150,  1450,  1513,  1515,  1531,  1539,  1557,  1569,
       6,     7,     8,     9,   861,   862,   863,     6,     7,     8,
       9,  1172,  1598,   151,   152,   153,  1516,  1532,  1540,  1558,
    1570,  1802,   219,     3,   219,  1173,     4,  1827,     5,  1751,
    1752,   775,  2022,  2023,   910,  1482,  1483,    18,    19,  1107,
    2060,   851,   852,   853,   910,   910,  1907,  1174,     6,     7,
       8,     9,   519,  1185,   520,   521,   522,   523,  1878,  1191,
    1198,   215,  1204,  1603,  1604,   219,  1876,   923,  1329,  1877,
    1199,  1140,  1330,  1331,  1332,  -968,   215,   923,   923,  1605,
    1606,  1764,  1765,  1766,   775,  1767,    34,  -969,  1210,   776,
    1211,  1891,   221,  1097,  1819,     3,    35,  1212,     4,  2059,
       5,   369,    36,  1213,   214,  1215,  1216,   218,  1621,  1225,
    1223,  1628,  1248,  1633,   748,  1151,  1639,  1898,  1250,  1249,
       6,     7,     8,     9,  1254,   214,    37,  1260,   218,  1622,
     908,  1244,  1629,  1265,  1634,  1819,   936,  1640,  1273,  1690,
    1274,   369,   908,  1275,   214,  1276,   775,   218,  1691,  1277,
    1097,  1100,    88,  1875,  1285,   222,  1286,  1287,   224,  1803,
      89,  1620,    90,  1290,    91,  1288,  1220,    92,    93,    94,
    1292,    95,  1689,  1289,   570,  1295,   571,  1144,  1298,  1318,
    1145,  1316,  1320,   225,  1346,  1347,   869,  1402,   369,  1328,
     226,   214,   908,  1349,   218,   572,   221,  1348,   221,  1351,
     219,  1350,  1368,   573,   574,   225,   575,  1819,  1358,  1359,
     908,   908,   226,   525,   526,   493,   576,   577,   494,   495,
     496,   219,   527,   528,   529,   530,   531,  1366,   775,     3,
    2031,  1367,     4,  1370,     5,  1378,  1375,  2032,  1385,   221,
     219,  1376,  1117,  2080,  1390,  2030,    62,   214,  1377,   880,
     218,  1401,  1820,  1409,     6,     7,     8,     9,  1927,  1411,
    1414,  1097,  1733,  1426,   214,  1747,   936,   218,  1422,  1445,
    1741,  1742,  1743,  1744,  1745,  1339,  1340,  1341,  1342,  1343,
     369,  1460,  1747,   214,  2045,  2046,   218,   219,  1770,  1771,
    1772,   222,  1469,  1820,   224,  1838,  1839,  1840,  1841,  1842,
    1779,  1780,  1781,  1463,  1478,   391,  1477,  1479,  -624,   395,
    1531,  1539,  1557,  1569,   775,  1015,  1016,  1017,  1018,   225,
    -625,   775,  1586,  1511,   418,   391,   226,  1596,   227,  2056,
    1587,  1532,  1540,  1558,  1570,  1494,  1821,  1718,  1720,  1720,
    1723,  1588,   445,   219,  1599,  1805,  1815,  1822,  2096,  1610,
     227,   214,  1601,  1602,   218,  2097,     3,  1619,  1645,     4,
     219,     5,   775,  2095,  1646,  1820,  1806,  1816,  1823,  1650,
    1665,   486,  2029,  1661,   221,  1663,  1674,  1909,   492,   219,
    1680,     6,     7,     8,     9,    96,   560,   561,  1334,  1335,
    1336,  1337,   447,  1666,  1683,   221,   434,   435,   436,   437,
      97,   562,  1117,   563,   564,   565,   214,    18,    19,   218,
    1681,  2044,  1692,   215,   221,   465,    98,  1699,  1696,  1860,
     869,    99,  1701,   100,   387,  1251,   566,   567,   568,  1714,
      18,    19,  1715,  1725,   775,  1141,  1740,  1739,  1754,   755,
    1750,   910,  1776,  1782,  1783,  1795,  1796,   219,  1798,  2082,
     387,  1826,    73,  -496,  1784,  1868,    34,  1863,  1871,  1836,
      74,   221,    75,  1844,   227,  1846,    35,    76,    77,    78,
    1916,    79,    36,  1850,   923,  1888,  1858,  1889,  1890,    34,
    1922,   294,   295,   296,  1675,  1676,   299,  1925,  1873,    35,
    2094,  1893,   745,   745,  1867,    36,    37,  1895,  1886,  1910,
    1912,  1901,   219,  1919,  1897,  1928,  1921,  1900,   869,  1932,
    1924,  1937,  1933,  1906,  1940,  1943,  1944,   221,  1945,    37,
    1805,  1815,  1822,  1946,  1947,  1951,  1952,  1955,  1953,  1954,
    1221,  1989,   222,   369,   221,   224,   214,  1991,  2004,   218,
    2002,  1806,  1816,  1823,   910,   910,   910,   910,   910,   215,
    2000,   910,  2007,   221,  2015,  2016,  2017,  2027,  -226,  2040,
     225,  2035,  2062,  2067,  2068,  2071,   214,   226,   775,   218,
     908,  -227,  2088,  1009,  1597,    70,   910,   923,   923,   923,
     923,   923,   947,  2048,   923,  1581,  1778,   547,   214,   548,
    2087,   218,  2070,  1958,  1957,   910,  2018,   214,  2021,  2020,
     218,  2019,  1942,  2010,  2063,   413,  1956,  1722,   549,   923,
     944,   420,  1870,  1164,  1177,  1962,   550,   551,   552,   553,
    1861,   221,   765,  1847,  1832,  1214,  1849,  2009,   923,   946,
    2047,  1979,   219,  1985,  1466,  1468,   222,  1485,   222,   224,
    1467,   224,  1222,  1668,  1993,  1994,  1671,  1995,  1996,  1997,
    1998,  1999,  1146,  1488,  2001,   744,  1228,  1100,  1296,  1507,
     214,  1442,   219,   218,   225,   704,   225,  1652,  1684,   935,
     957,   226,  1687,   226,   959,  2089,   221,   960,  1747,   222,
     753,   462,   224,   958,   219,    80,   757,  1066,   758,  2026,
    1314,     0,  1315,   219,  1345,   775,     0,     0,  2033,  2034,
      81,     0,     0,     0,     0,   227,     0,   225,     0,   369,
    2057,     0,   214,     0,   226,   218,    82,     0,     0,     0,
       0,    83,     0,    84,     0,     0,     0,  1669,   214,  1140,
    1220,   218,     0,     0,     0,     0,     0,     0,     0,  1515,
    1539,  1557,  1569,     0,     0,     0,  2065,  1621,  1628,  1633,
    1639,     0,     0,     0,  2064,   924,   219,  2066,     0,     0,
    1516,  1540,  1558,  1570,     0,   924,   924,     0,  1622,  1629,
    1634,  1640,  2074,     0,     0,     0,     0,  2075,  2076,  2077,
    2078,  2079,  1805,  1815,  1822,  2083,  2084,  2085,  2086,     0,
     215,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,  2090,  1806,  1816,  1823,   221,     0,   219,   227,
       0,   227,     0,     0,   222,     0,     0,   224,     0,     0,
    2098,  2099,  2100,     0,   219,     0,     0,     0,   467,     0,
       0,     0,     0,     0,     0,  1144,   221,     0,  1145,     0,
    1738,     0,   225,    18,    19,     0,     0,  1453,  1453,   226,
    1453,     0,   373,     0,   222,     0,     0,   224,   221,     0,
       0,     0,     0,   225,     0,     0,     0,   221,     0,     0,
     226,     0,     0,     0,     0,     0,     0,  1963,     0,     0,
       0,     0,   225,     0,     0,     0,     0,     0,     0,   226,
       0,     0,    34,     0,   215,     0,   215,     0,     0,     0,
       0,   222,    35,     0,   224,     0,     0,     0,    36,     0,
       0,     0,     0,   910,   910,   910,   910,   910,   910,   910,
     910,   910,   910,   910,  1438,     0,  1964,     0,     0,   225,
     221,     0,    37,     0,     0,     0,   226,   215,     0,     0,
       0,     0,     0,  1755,     0,     0,   923,   923,   923,   923,
     923,   923,   923,   923,   923,   923,   923,   222,     0,     0,
     224,     0,     0,     0,     0,     0,     0,     0,  1756,  1757,
     796,     0,     0,     0,   222,     0,     0,   224,     0,     0,
     746,   746,   221,     0,     0,   225,     0,   373,     0,     0,
       0,     0,   226,   222,     0,     0,   224,     0,   221,     0,
       0,     0,   225,   151,   152,   153,     0,     0,   227,   226,
     890,     0,  1073,  1074,   891,     0,     0,     0,     0,   892,
       0,   225,     0,     0,     0,   893,  1075,   373,   226,   803,
       0,   469,     0,     0,  1076,     0,  1517,  1534,  1544,  1560,
    1572,     0,     0,     0,     0,     0,    18,    19,     0,   896,
    1077,   444,     0,   446,   448,   386,     0,   451,     0,   453,
       0,   222,   457,   458,   224,     0,   466,   468,   470,   472,
       0,     0,   215,   477,   373,     0,   481,   483,     0,     0,
       0,   386,     0,     0,   489,     0,     0,  1758,  1905,   225,
       0,  1670,     0,  1141,  1221,    34,   226,     0,   910,     0,
       0,     0,     0,     0,     0,    35,     0,  1759,  1760,     0,
     910,    36,   215,     0,     0,     0,   222,     0,     0,   224,
    1453,   471,     0,  1453,     0,  1965,  1453,     0,     0,     0,
     227,   923,     0,     0,     0,    37,    18,    19,     0,     0,
       0,  1966,     0,   923,   225,     0,  1967,   227,  1968,  1623,
       0,   226,  1630,   476,  1635,     0,     0,  1641,     0,   215,
     910,     0,   924,     0,     0,     0,   373,    60,    18,    19,
       0,     0,  1078,  1079,  1080,   683,     0,     0,   910,   910,
     806,     0,     0,   807,   808,    34,     0,     0,   693,   694,
     695,     0,     0,   923,     0,    35,   274,   275,   276,   277,
       0,    36,     0,     0,  1194,     0,  1978,     0,  1984,  1438,
       0,   923,   923,   480,     0,   215,     0,    34,   810,   811,
       0,     0,     0,     0,     0,    37,     0,    35,    18,    19,
     393,     0,   215,    36,   227,     0,     0,     0,   403,   404,
     405,   406,     0,     0,     0,     0,   222,     0,     0,   224,
       0,   215,     0,     0,     0,     0,     0,    37,     0,   210,
       0,   439,     0,     0,     0,   924,   924,   924,   924,   924,
       0,     0,   924,     0,   225,     0,   222,    34,   464,   224,
       0,   226,     0,   473,   474,   475,     0,    35,   479,   227,
       0,   484,     0,    36,     0,     0,     0,   924,   222,     0,
       0,   224,     0,     0,   225,     0,     0,   222,     0,     0,
     224,   226,     0,     0,     0,     0,   924,    37,     0,   215,
       0,     0,     0,     0,     0,     0,   225,  2061,     0,  1112,
       0,  1114,     0,   226,     0,   225,     0,     0,     0,     0,
       0,     0,   226,  1984,     0,     0,     0,  1130,  1131,     0,
    1135,  1534,  1544,  1560,  1572,     0,  1147,  1148,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  1905,     0,     0,
     222,     0,     0,   224,   215,     0,     0,     0,   482,     0,
       0,     0,     0,  1182,     0,  1184,  1807,  1817,  1824,     0,
       0,     0,     0,    18,    19,     0,     0,     0,   225,   979,
       0,     0,     0,     0,     0,   226,     0,     0,     3,     0,
       0,     4,     0,     5,     0,     0,     0,     0,     0,   373,
       0,     0,   222,     0,     0,   224,     0,     0,   730,   731,
     732,     0,     0,     6,     7,     8,     9,     0,   222,     0,
       0,   224,    34,     0,     0,  1218,     0,  1546,     0,   227,
     225,     0,    35,     0,     0,     0,     0,   226,    36,     0,
       3,     0,     0,     4,     0,     5,   225,   754,     0,     0,
       0,   227,     0,   226,     0,     0,     0,     0,     0,     0,
     227,     0,    37,     0,     0,     6,     7,     8,     9,   675,
     676,     0,     0,   677,     0,  1547,  1548,  1549,  1550,  1546,
    1551,     0,     0,  1552,   215,     0,   533,   534,     0,     0,
     535,   678,     0,     0,     0,  1258,  1259,     0,     0,     0,
    1553,   536,   537,   538,   539,   540,   541,   542,   543,   544,
       0,     0,     0,     0,   215,     0,     0,     0,   910,     0,
       0,     0,     0,   227,     0,     0,     0,  1547,  1548,  1549,
    1550,     0,  1551,     0,     0,  1552,   215,   953,   954,   955,
       0,  1807,  1817,  1824,     0,   215,     0,   755,     0,  1554,
     545,   923,  1553,     0,     0,   602,     0,     0,     0,     0,
       0,     0,     0,     0,   603,  1194,  1194,  1194,  1194,  1194,
     969,  1194,  1194,     0,     0,   373,     0,     0,     0,   604,
    1481,  1481,     0,   605,     0,     0,     0,   606,   607,     0,
       0,   227,   608,   609,   610,   611,   612,     0,     0,   980,
       0,  1554,     0,     0,     0,   679,     0,     0,   215,     0,
       0,     0,     0,     0,   924,   924,   924,   924,   924,   924,
     924,   924,   924,   924,   924,     0,     0,     0,     0,   680,
     681,   682,   683,   684,   685,   756,   686,   687,   688,   689,
     690,   691,   692,     0,     0,   693,   694,   695,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  1555,     0,  1022,
     215,     0,     0,     0,     0,     0,   696,     0,     0,     0,
       0,     0,   304,     0,  1023,     0,   215,  1389,     0,     0,
       3,  1392,     0,     4,     0,     5,     0,     0,   306,     0,
    1405,  1406,  1407,   307,     0,  1410,     0,  1412,     0,     0,
       0,     0,     0,     0,     0,     6,     7,     8,     9,  1555,
       0,     0,     0,     0,     0,     0,  1519,  1427,     0,     0,
       0,     0,     0,     0,   304,     0,  1520,   775,     0,     0,
       0,  1521,     0,  1522,     0,  1523,     0,     0,  1024,     0,
     306,     0,  1556,     0,     0,   307,     0,     0,     0,     0,
       0,  1459,     0,  1461,     0,     0,     0,     0,     0,  1462,
    1517,  1544,  1560,  1572,     0,     0,     0,     0,  1623,  1630,
    1635,  1641,  1475,     0,  1476,     0,     0,    50,     0,   775,
       0,     0,     0,  1484,     0,  1486,     0,    61,    50,    50,
      64,    64,    64,    68,  1788,     0,    50,     0,     0,   924,
       0,     0,     0,  1807,  1817,  1824,     0,     0,     0,  1025,
       0,   924,  1026,  1027,  1028,  1029,  1030,  1031,  1032,  1033,
    1034,  1035,  1036,  1037,  1038,     0,     0,  1310,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  1524,     0,     0,     0,     0,     0,    50,     0,     0,
     394,    50,    64,    64,    64,    68,     0,     0,     0,     0,
       0,   924,    50,     0,   409,   414,   417,    50,   422,    64,
      64,   427,     0,   409,   409,   409,   409,     0,    64,   924,
     924,     0,   443,     0,    50,     0,     0,    64,    64,     0,
      68,  1024,     0,    64,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   675,   676,     0,
       0,   677,   485,    50,    64,    64,     0,     0,    64,     0,
      50,     0,     0,     0,    10,     0,     0,     0,     0,   678,
       0,     0,    11,     0,    12,     0,    13,     0,     0,    14,
      15,    16,     0,    17,     0,     0,     0,    18,    19,  1525,
       0,     0,     0,     0,     0,     0,     0,     0,  1643,  1644,
       0,     0,  1311,     0,  1526,  1026,  1027,  1312,  1029,  1030,
    1031,  1032,  1033,  1034,  1035,  1036,  1037,  1313,     0,  1656,
    1527,     0,     0,     0,     0,  1528,     0,  1529,     0,     0,
       0,     0,     0,     0,  1673,     0,    34,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    35,     0,     0,     0,
       0,     0,    36,     0,     0,     0,     0,     0,     0,   775,
       0,     0,     0,     0,     0,     0,     0,     0,  1698,     0,
       3,     0,     0,     4,  1530,     5,    37,     0,     0,     0,
       0,     0,     0,   679,     0,  1700,     0,  1702,     0,     0,
       0,     0,   146,     0,     0,     6,     7,     8,     9,   147,
     148,     0,     0,     0,   288,   149,   289,   680,   681,   682,
     683,   684,   685,     0,   686,   687,   688,   689,   690,   691,
     692,   290,     0,   693,   694,   695,     0,     0,     0,     0,
       0,   291,   292,     0,     0,     0,   293,     0,     0,     0,
       0,     0,     0,     0,   696,     0,     0,   294,   295,   296,
     297,   298,   299,     0,     0,     0,     0,     0,     0,     0,
       0,     0,  1535,     0,     0,     0,   300,     0,   301,     0,
       0,   150,   151,   152,   153,     0,     0,   154,     0,   155,
       0,     0,  1536,   156,     0,     0,     0,     0,   157,     0,
       0,     0,     0,     0,   158,     0,     0,    38,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     159,     0,    39,     0,     0,   160,     0,     0,   161,     0,
       0,     0,     0,   162,     0,     0,   163,     0,    40,   164,
     165,  1537,     0,    41,   166,    42,     0,   167,     0,   168,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  1834,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   977,   169,   170,     0,     0,     0,     0,
      64,     0,     0,     0,     0,     0,     0,     0,     0,   924,
       0,   983,  1854,   984,     0,   985,     0,   986,     0,     0,
       0,     0,   990,     0,     0,     0,   992,     0,   993,     0,
     171,   172,   173,   174,     0,     0,    64,  1862,     0,   175,
     176,     0,     0,   177,   178,   302,   180,   181,   182,   183,
     184,   185,   186,   187,   188,   189,   190,   191,   192,   193,
     194,   195,   196,   197,   198,   199,   200,     0,     0,   303,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   304,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   305,     0,     0,     0,     0,     0,
     306,     0,     0,     0,     0,   307,     0,     0,     0,     0,
       0,   202,   203,     0,   308,     0,     0,   309,   310,   311,
     312,     0,     0,     0,   313,     0,     0,     0,   314,   315,
     204,     0,     0,     0,   205,   206,     0,     3,     0,   775,
       4,     0,     5,   316,     0,     0,   207,   208,     0,     0,
       0,     0,     0,   317,  1538,   209,     0,     0,   210,   146,
       0,     0,     6,     7,     8,     9,   147,   148,     0,     0,
       0,   288,   149,   289,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   290,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   291,   292,
       0,  1936,     0,   293,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   294,   295,   296,   297,   298,   299,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  1535,
       0,     0,     0,   300,     0,   301,     0,     0,   150,   151,
     152,   153,     0,     0,   154,     0,   155,     0,     0,  1536,
     156,     0,     0,     0,     0,   157,     0,     0,     0,     0,
       0,   158,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   159,     0,     0,
       0,     0,   160,     0,     0,   161,     0,     0,     0,     0,
     162,     0,     0,   163,     0,     0,   164,   165,  1537,     0,
       0,   166,     0,     0,   167,     0,   168,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       3,     0,     0,     4,     0,     5,     0,     0,     0,     0,
       0,   169,   170,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     6,     7,     8,     9,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  1546,
       0,     0,     0,     0,     0,     0,     0,   171,   172,   173,
     174,     0,     0,     0,     0,     0,   175,   176,     0,     0,
     177,   178,   302,   180,   181,   182,   183,   184,   185,   186,
     187,   188,   189,   190,   191,   192,   193,   194,   195,   196,
     197,   198,   199,   200,     0,     0,   303,  1547,  1548,  1549,
    1550,     0,  1551,     0,     0,  1552,     0,     0,     0,     0,
       0,   304,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   305,  1553,     0,     0,     0,     0,   306,     0,     0,
       0,     0,   307,     0,     0,     0,     0,     0,   202,   203,
       0,   308,     0,     0,   309,   310,   311,   312,     0,     0,
       0,   313,     0,     0,     0,   314,   315,   204,     0,     0,
       0,   205,   206,     0,     3,     0,   775,     4,     0,     5,
     316,  1554,     0,   207,   208,     0,     0,     0,     0,     0,
     317,  1787,   209,     0,     0,   210,   146,     0,     0,     6,
       7,     8,     9,   147,   148,     0,     0,     0,   288,   149,
     289,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   290,     0,  1294,     0,     0,
       0,     0,     0,     0,     0,   291,   292,     0,     0,     0,
     293,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   294,   295,   296,   297,   298,   299,     0,     0,     0,
       0,     0,     0,     0,     0,     0,  1535,     0,     0,     0,
     300,     0,   301,     0,     0,   150,   151,   152,   153,     0,
       0,   154,     0,   155,     0,     0,  1536,   156,     0,  1555,
       0,     0,   157,     0,     0,     0,     0,     0,   158,     0,
       0,     0,     0,     0,   304,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   159,     0,     0,     0,     0,   160,
     306,     0,   161,     0,     0,   307,     0,   162,     0,     0,
     163,     0,     0,   164,   165,  1537,     0,     0,   166,     0,
       0,   167,     0,   168,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   775,
       0,     3,     0,     0,     4,     0,     5,     0,   169,   170,
       0,     0,     0,     0,  2050,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     6,     7,     8,     9,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    1563,     0,     0,     0,   171,   172,   173,   174,     0,     0,
       0,     0,     0,   175,   176,     0,     0,   177,   178,   302,
     180,   181,   182,   183,   184,   185,   186,   187,   188,   189,
     190,   191,   192,   193,   194,   195,   196,   197,   198,   199,
     200,     0,     0,   303,     0,     0,     0,     0,     0,  1564,
       0,  1565,     0,  1551,     0,     0,  1552,     0,   304,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   305,     0,
       0,     0,     0,  1566,   306,     0,     0,     0,     0,   307,
       0,     0,     0,     0,     0,   202,   203,     0,   308,     0,
       0,   309,   310,   311,   312,     0,     0,     0,   313,     0,
       0,     0,   314,   315,   204,     0,     0,     0,   205,   206,
       0,     0,     4,   775,     5,     0,     0,   316,     0,     0,
     207,   208,  1567,     0,     0,     0,     0,   317,  2049,   209,
       0,   146,   210,     0,     0,     0,     0,     0,   147,   148,
       0,     0,     0,   288,   149,   289,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     290,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     291,   292,   665,     0,     0,   293,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   294,   295,   296,   297,
     298,   299,     0,     0,     0,     0,     0,     0,     0,   666,
       0,     0,   667,     0,     0,   300,     0,   301,     0,     0,
     150,   151,   152,   153,     0,     0,   154,     0,   155,   668,
       0,     0,   156,     0,     0,     0,     0,   157,     0,     0,
    1555,     0,     0,   158,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   304,     0,     0,     0,   159,
       0,     0,     0,     0,   160,     0,     0,   161,     0,     0,
       0,   306,   162,  1042,     0,   163,   307,     0,   164,   165,
       0,     0,     0,   166,     0,     0,   167,     0,   168,     0,
       0,  1043,  1044,  1045,  1046,  1047,  1048,  1049,  1050,  1051,
    1052,  1053,  1054,  1055,  1056,  1057,  1058,  1059,     0,     0,
     775,     0,     0,   169,   170,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,  1568,   180,   181,   182,   183,
     184,   185,   186,   187,   188,   189,   190,   191,   192,   193,
     194,   195,   196,   197,   198,   199,   200,     0,     0,   171,
     172,   173,   174,     0,     0,     0,     0,     0,   175,   176,
       0,     0,   177,   178,   302,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   196,   197,   198,   199,   200,     0,   669,   303,     0,
     795,   202,   203,     0,     0,     0,     0,     0,     0,     0,
       0,   670,     0,   304,     0,     0,     0,     0,   146,     0,
       0,     0,     0,   305,     0,     0,   148,     0,     0,   306,
       0,   149,     0,     0,   307,     0,     0,   671,     0,     0,
     202,   203,     0,   308,     0,     0,   309,   310,   311,   312,
       0,     0,     0,   313,     0,     0,     0,   314,   315,   204,
       0,     0,     0,   205,   206,   796,     0,     0,     0,     0,
       0,     0,   316,     0,     0,   207,   208,     0,     0,   797,
       0,   798,   317,  1688,   209,     0,     0,   210,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   150,   151,   152,
     153,     0,     0,   154,     0,   799,     0,     0,     0,   800,
       0,     0,     0,     0,   801,     0,     0,     0,     0,     0,
     802,     0,     0,     0,   803,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   159,     0,     0,     0,
       0,   160,     0,     0,   804,     0,     0,     0,     0,   162,
       0,     0,   163,     0,     0,   164,   165,     0,     0,     0,
     166,     0,     0,   167,     0,   168,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     169,   170,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  1109,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   146,
       0,     0,     0,     0,     0,     0,   805,   148,     0,     0,
       0,     0,   149,     0,     0,     0,     0,     0,     0,     0,
       0,   179,   180,   181,   182,   183,   184,   185,   186,   187,
     188,   189,   190,   191,   192,   193,   194,   195,   196,   197,
     198,   199,   200,     0,     0,   201,   796,     0,     0,     0,
       0,     0,     0,     0,     0,   806,     0,     0,   807,   808,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   809,     0,     0,     0,     0,     0,     0,   150,   151,
     152,   153,     0,     0,   154,     0,   799,   202,   203,     0,
     800,     0,     0,   810,   811,   801,     0,     0,     0,     0,
       0,  1110,     0,     0,     0,   803,   204,     0,     0,     0,
     205,   206,     0,     0,     0,     0,     0,   159,     0,     0,
     812,   813,   160,   671,     0,  1111,     0,     0,     0,     0,
     162,   814,     0,   163,   210,     0,   164,   165,     0,     0,
       0,   166,     0,     0,   167,     0,   168,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   169,   170,     0,     0,     0,     0,     0,     0,     0,
       0,     0,  1183,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     146,     0,     0,     0,     0,     0,     0,   805,   148,     0,
       0,     0,     0,   149,     0,     0,     0,     0,     0,     0,
       0,     0,   179,   180,   181,   182,   183,   184,   185,   186,
     187,   188,   189,   190,   191,   192,   193,   194,   195,   196,
     197,   198,   199,   200,     0,     0,   201,   796,     0,     0,
       0,     0,     0,     0,     0,     0,   806,     0,     0,   807,
     808,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   150,
     151,   152,   153,     0,     0,   154,     0,   799,   202,   203,
       0,   800,     0,     0,   810,   811,   801,     0,     0,     0,
       0,     0,  1110,     0,     0,     0,   803,   204,     0,     0,
       0,   205,   206,     0,     0,     0,     0,     0,   159,     0,
       0,   812,   813,   160,   671,     0,  1111,     0,     0,     0,
       0,   162,   814,     0,   163,   210,     0,   164,   165,     0,
       0,     0,   166,     0,     0,   167,     0,   168,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   169,   170,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  1217,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   146,     0,     0,     0,     0,     0,     0,   805,   148,
       0,     0,     0,     0,   149,     0,     0,     0,     0,     0,
       0,     0,     0,   179,   180,   181,   182,   183,   184,   185,
     186,   187,   188,   189,   190,   191,   192,   193,   194,   195,
     196,   197,   198,   199,   200,     0,     0,   201,   796,     0,
       0,     0,     0,     0,     0,     0,     0,   806,     0,     0,
     807,   808,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     150,   151,   152,   153,     0,     0,   154,     0,   799,   202,
     203,     0,   800,     0,     0,   810,   811,   801,     0,     0,
       0,     0,     0,  1110,     0,     0,     0,   803,   204,     0,
       0,     0,   205,   206,     0,     0,     0,     0,     0,   159,
       0,     0,   812,   813,   160,   671,     0,  1111,     0,     0,
       0,     0,   162,   814,     0,   163,   210,     0,   164,   165,
       0,     0,     0,   166,   104,     0,   167,     0,   168,   105,
       0,     0,   106,   107,   108,   109,     0,     0,   110,   111,
       0,   112,   113,   114,     0,   115,     0,     0,     0,     0,
       0,     0,     0,   169,   170,     0,     0,     0,     0,     0,
       0,     0,     0,     0,  1391,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   146,     0,   116,     0,   117,   118,   119,   805,
     148,     0,     0,     0,     0,   149,     0,     0,     0,     0,
       0,     0,     0,     0,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   196,   197,   198,   199,   200,     0,     0,   201,   796,
       0,     0,     0,     0,     0,     0,     0,     0,   806,     0,
       0,   807,   808,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   150,   151,   152,   153,     0,     0,   154,     0,   799,
     202,   203,     0,   800,     0,     0,   810,   811,   801,     0,
       0,     0,     0,     0,  1110,     0,     0,     0,   803,   204,
       0,     0,     0,   205,   206,     0,     0,     0,     0,     0,
     159,     0,     0,   812,   813,   160,   671,     3,  1111,     0,
       4,     0,     5,   162,   814,     0,   163,   210,     0,   164,
     165,     0,     0,     0,   166,     0,     0,   167,     0,   168,
       0,     0,     6,     7,     8,     9,     0,     0,     0,     0,
       0,     0,     3,  1519,     0,     4,     0,     5,     0,     0,
       0,     0,     0,  1520,   169,   170,     0,   120,  1521,     0,
    1522,     0,  1523,     0,     0,     0,     0,     6,     7,     8,
       9,     0,   121,     0,     0,     0,     0,   122,   123,   124,
     125,  1563,     0,     0,     0,     0,     0,     0,   126,     0,
     805,     0,     0,   127,     0,   128,   129,     0,     0,     0,
       0,     0,     0,     0,     0,   179,   180,   181,   182,   183,
     184,   185,   186,   187,   188,   189,   190,   191,   192,   193,
     194,   195,   196,   197,   198,   199,   200,     0,     0,   201,
    1564,     0,  1565,     0,  1551,     3,     0,  1552,     4,   806,
       5,     0,   807,   808,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,  1566,     0,     0,     0,     0,     0,
       6,     7,     8,     9,     0,     0,     0,     0,  1524,     0,
       0,   202,   203,     0,  1563,     0,     0,   810,   811,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     204,     0,     0,     0,   205,   206,     0,     0,     0,     0,
       0,     0,     0,  1567,   812,   813,     0,   671,     0,     0,
       0,     0,     0,     0,     0,   814,     0,     0,   210,     0,
       0,     0,     0,  1564,     0,  1565,     0,  1551,     0,     0,
    1552,     0,     0,     0,   883,   884,   885,   886,   887,   888,
       0,     0,     0,     0,   889,     0,     0,  1566,   868,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,  1525,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  1526,     0,     0,     0,   796,  1567,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  1527,     0,     0,
       0,  1555,  1528,     0,  1529,     0,     0,     0,     0,     0,
       0,     0,     0,     0,  1150,     0,   304,   150,   151,   152,
     153,     0,     0,     0,     0,   890,     0,     0,     0,   891,
       0,     0,   306,     0,   892,     0,   775,   307,     0,     0,
     893,     0,     0,     0,   803,     0,     0,     0,     0,     0,
       0,  1786,     0,     0,     0,     0,   894,     0,     0,     0,
       0,   895,     0,   796,   896,     0,     0,     0,     0,   897,
       0,   775,   898,     0,     0,   899,   900,     0,     0,     0,
     901,     0,     0,   902,     0,   903,  1789,     0,     0,     0,
       0,     0,     0,     0,  1555,   150,   151,   152,   153,     0,
       0,     0,     0,   890,     0,     0,     0,   891,     0,   304,
     904,   905,   892,     0,     0,     0,     0,     0,   893,  1150,
       0,     0,   803,     0,     0,   306,     0,     0,     0,     0,
     307,     0,     0,     0,   894,     0,     0,     0,     0,   895,
       0,     0,   896,     0,     0,     0,     0,   897,     0,     0,
     898,     0,     0,   899,   900,     0,     0,     0,   901,     0,
       0,   902,     0,   903,   775,     0,     0,     0,   796,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  2051,
       0,     0,     0,     0,     0,     0,     0,     0,   904,   905,
       0,     0,     0,     0,     0,   806,     0,     0,   807,   808,
     150,   151,   152,   153,     0,     0,     0,     0,   890,     0,
       0,     0,   891,     0,     0,     0,     0,   892,     0,     0,
       0,     0,     0,   893,     0,     0,     0,   803,     0,     0,
       0,     0,     0,   810,   811,     0,   906,   929,   868,   894,
       0,     0,     0,     0,   895,     0,     0,   896,     0,     0,
       0,     0,   897,     0,     0,   898,     0,     0,   899,   900,
     812,   813,     0,   901,     0,     0,   902,     0,   903,   317,
       0,   907,     0,   806,   210,     0,   807,   808,     0,     0,
       0,     0,     0,     0,     0,   796,     0,     0,     0,     0,
       0,     0,     0,   904,   905,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   810,   811,     0,   906,     0,     0,   150,   151,   152,
     153,     0,     0,     0,     0,   890,     0,     0,     0,   891,
       0,     0,     0,     0,   892,     0,     0,     0,   812,   813,
     893,     0,     0,     0,   803,     0,     0,   317,     0,   907,
       0,     0,   210,     0,     0,     0,   894,     0,     0,     0,
       0,   895,     0,     0,   896,     0,     0,     0,     0,   897,
       0,     0,   898,     0,     0,   899,   900,     0,   806,     0,
     901,   807,   808,   902,     0,   903,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     904,   905,     0,     0,     0,     0,   810,   811,     0,   906,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   812,   813,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   907,     0,     0,   210,     0,     0,
       0,   146,     0,     0,     0,     0,     0,     0,   147,   148,
       0,     0,     0,   288,   149,   289,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     290,     0,     0,     0,     0,   806,     0,     0,   807,   808,
     291,   292,   752,     0,     0,   293,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   294,   295,   296,   297,
     298,   299,     0,     0,     0,     0,     0,     0,     0,   666,
       0,     0,   667,   810,   811,   300,   906,   301,     0,     0,
     150,   151,   152,   153,     0,     0,   154,     0,   155,   668,
       0,     0,   156,     0,     0,     0,     0,   157,     0,     0,
     812,   813,     0,   158,     0,     0,     0,     0,     0,   930,
       0,   907,     0,     0,   210,     0,     0,     0,     0,   159,
       0,     0,     0,     0,   160,     0,     0,   161,     0,     0,
       0,     0,   162,     0,     0,   163,     0,     0,   164,   165,
       0,     0,     0,   166,     0,     0,   167,     0,   168,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   169,   170,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   180,   181,   182,   183,
     184,   185,   186,   187,   188,   189,   190,   191,   192,   193,
     194,   195,   196,   197,   198,   199,   200,     0,     0,   171,
     172,   173,   174,     0,     0,     0,     0,     0,   175,   176,
       0,     0,   177,   178,   302,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   196,   197,   198,   199,   200,     0,   669,   303,     0,
       0,   202,   203,     0,     0,     0,     0,     0,     0,   146,
       0,   670,     0,   304,     0,     0,   147,   148,     0,     0,
       0,     0,   149,   305,     0,     0,     0,     0,     0,   306,
       0,     0,     0,     0,   307,     0,     0,   671,     0,     0,
     202,   203,     0,   308,     0,     0,   309,   310,   311,   312,
       0,     0,     0,   313,     0,     0,     0,   314,   315,   204,
       0,     0,     0,   205,   206,     0,     0,     0,     0,     0,
       0,     0,   316,     0,     0,   207,   208,     0,     0,     0,
       0,     0,   317,     0,   209,     0,     0,   210,   150,   151,
     152,   153,     0,     0,   154,     0,   155,     0,     0,     0,
     156,     0,     0,     0,     0,   157,     0,     0,     0,     0,
       0,   158,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   159,     0,     0,
       0,     0,   160,     0,     0,   161,     0,     0,     0,     0,
     162,     0,     0,   163,     0,     0,   164,   165,     0,     0,
       0,   166,     0,     0,   167,     0,   168,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   169,   170,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   146,     0,     0,     0,     0,     0,     0,   147,   148,
       0,     0,     0,     0,   149,     0,     0,   171,   172,   173,
     174,     0,     0,     0,     0,     0,   175,   176,     0,     0,
     177,   178,   179,   180,   181,   182,   183,   184,   185,   186,
     187,   188,   189,   190,   191,   192,   193,   194,   195,   196,
     197,   198,   199,   200,     0,     0,   201,     0,     0,     0,
       0,     0,     0,     0,  1959,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     150,   151,   152,   153,     0,     0,   154,     0,   155,     0,
       0,     0,   156,     0,     0,     0,     0,   157,   202,   203,
       0,     0,     0,   158,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   204,     0,   159,
       0,   205,   206,     0,   160,     0,     0,   161,     0,     0,
       0,     0,   162,   207,   208,   163,     0,     0,   164,   165,
     317,     0,   209,   166,     0,   210,   167,     0,   168,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     146,     0,     0,   169,   170,     0,     0,   147,   148,     0,
       0,     0,     0,   149,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   171,
     172,   173,   174,     0,     0,     0,     0,     0,   175,   176,
       0,     0,   177,   178,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   196,   197,   198,   199,   200,     0,     0,   201,   150,
     151,   152,   153,     0,     0,   154,     0,   155,     0,     0,
       0,   156,     0,     0,     0,     0,   157,     0,     0,     0,
       0,     0,   158,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   159,     0,
     202,   203,     0,   160,     0,     0,   161,     0,     0,     0,
       0,   162,     0,     0,   163,     0,     0,   164,   165,   204,
       0,     0,   166,   205,   206,   167,     0,   168,     0,     0,
       0,     0,     0,     0,     0,   207,   208,     0,     0,     0,
       0,     0,     0,     0,   209,     0,     0,   210,     0,   146,
       0,     0,   169,   170,     0,     0,     0,   148,     0,     0,
       0,     0,   149,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   171,   172,
     173,   174,     0,     0,     0,     0,   796,   175,   176,     0,
       0,   177,   178,   179,   180,   181,   182,   183,   184,   185,
     186,   187,   188,   189,   190,   191,   192,   193,   194,   195,
     196,   197,   198,   199,   200,     0,     0,   201,   150,   151,
     152,   153,     0,     0,   154,     0,   799,     0,     0,     0,
     800,     0,     0,     0,     0,   801,     0,     0,     0,     0,
       0,  1110,     0,     0,     0,   803,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   159,     0,   202,
     203,     0,   160,     0,     0,  1111,     0,     0,     0,     0,
     162,     0,     0,   163,     0,     0,   164,   165,   204,     0,
       0,   166,   205,   206,   167,     0,   168,     0,     0,     0,
       0,     0,     0,     0,   207,   208,     0,     0,     0,     0,
       0,     0,     0,   209,     0,     0,   210,     0,     0,     0,
       0,   169,   170,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     868,     0,     0,     0,     0,     0,     0,   805,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   179,   180,   181,   182,   183,   184,   185,   186,
     187,   188,   189,   190,   191,   192,   193,   194,   195,   196,
     197,   198,   199,   200,     0,     0,   201,   796,     0,     0,
       0,     0,     0,     0,     0,     0,   806,     0,     0,   807,
     808,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   150,
     151,   152,   153,     0,     0,     0,     0,   890,   202,   203,
       0,   891,     0,     0,   810,   811,   892,     0,     0,     0,
       0,     0,   893,     0,     0,     0,   803,   204,     0,     0,
       0,   205,   206,     0,     0,     0,     0,     0,   894,     0,
       0,   812,   813,   895,   671,     0,   896,     0,     0,     0,
       0,   897,   814,     0,   898,   210,     0,   899,   900,     0,
       2,     3,   901,     0,     4,   902,     5,   903,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     6,     7,     8,     9,
       0,     0,   904,   905,     0,     0,     0,    10,     0,     0,
       0,     0,     0,     0,     0,    11,     0,    12,     0,    13,
       0,     0,    14,    15,    16,     0,    17,     0,     0,     0,
      18,    19,    20,     0,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  -366,     0,     0,     0,     0,     0,    34,
       0,     0,     0,     0,     0,     0,     0,   806,     0,    35,
     807,   808,     0,     0,     0,    36,     0,     0,     0,   796,
       0,     0,     0,     0,     0,     0,     0,   294,   295,   296,
    1675,  1676,   299,     0,     0,     0,     0,     0,     0,    37,
       0,     0,     0,     0,     0,   810,   811,     0,   906,     0,
       0,   150,   151,   152,   153,     0,     0,     0,     0,   890,
       0,     0,     0,   891,     0,     0,     0,   796,   892,     0,
       0,     0,   812,   813,   893,     0,     0,     0,   803,     0,
       0,   317,     0,   907,     0,     0,   210,     0,     0,     0,
     894,     0,     0,     0,     0,   895,     0,     0,   896,   150,
     151,   152,   153,   897,     0,     0,   898,   890,     0,   899,
     900,   891,     0,     0,   901,     0,   892,   902,     0,   903,
       0,     0,   893,     0,     0,     0,   803,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   894,     0,
       0,     0,     0,   895,   904,   905,   896,     0,     0,     0,
       0,   897,     0,     0,   898,     0,     0,   899,   900,     0,
      38,     0,   901,     0,     0,   902,     0,   903,     0,     0,
       0,   796,     0,     0,     0,    39,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    40,   904,   905,     0,     0,    41,     0,    42,     0,
       0,     0,     0,  1504,   151,   152,   153,     0,     0,     0,
       0,   890,     0,     0,     0,   891,     0,     0,     0,     0,
     892,     0,     0,     0,     0,     0,   893,     0,     0,   806,
     803,     0,   807,   808,     0,     0,     0,     0,     0,     0,
       0,     0,   894,     0,     0,     0,     0,   895,     0,     0,
     896,     0,     0,     0,     0,   897,     0,     0,   898,     0,
       0,   899,   900,     0,     0,     0,   901,   810,   811,   902,
     906,   903,     0,     0,     0,     0,     0,   806,     0,     0,
     807,   808,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   812,   813,   904,   905,     0,     0,
       0,     0,     0,     0,     0,   907,     0,     0,   210,     0,
       0,     0,     0,     0,     0,   810,   811,     0,   906,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   812,   813,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   907,     0,     0,   210,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   806,     0,     0,   807,   808,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   810,
     811,     0,   906,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   812,   813,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   907,     0,     0,
     210
};

static const yytype_int16 yycheck[] =
{
       1,    30,     3,   399,    30,   328,   298,   474,   397,    36,
      66,   396,   205,   320,   475,   398,   365,   484,    52,    30,
      52,     1,   473,    52,    37,   737,    52,   323,  1270,    63,
     772,    63,   428,   903,    63,   351,   425,    63,   344,  1270,
     633,   209,   105,  1275,   107,    46,   109,   110,   766,   438,
     113,   980,   115,    54,   288,   118,   119,    58,  1277,   122,
     123,   124,   125,   775,  1274,   365,   129,  1225,    32,   132,
     133,  1290,  1276,  1100,   786,   375,   376,   140,   790,   861,
     403,   315,   518,  1151,  1152,  1269,  1270,  1139,   379,   365,
    1158,    35,  1381,  1381,     7,     8,     9,    30,  1385,   395,
    1429,   905,   636,   337,  1366,  1367,  1588,    15,    16,  1586,
    1227,   434,  1587,  1491,  1566,  1563,   814,   875,   876,    52,
    1395,   877,   879,   878,     4,     4,    23,   881,    96,     7,
      63,    23,    78,    79,     7,    48,     7,    50,     7,     7,
      58,   464,    15,    16,    17,    18,    59,   179,   102,    45,
       7,    64,  1081,  1082,    38,    68,   479,    57,    84,    23,
    1397,  1436,  1437,  1625,   103,   104,  1626,  1235,    76,    77,
      78,    22,   706,   103,   104,   105,   205,    20,   102,   205,
     209,   734,    89,   209,    92,    93,    94,   736,   735,   103,
       1,   103,     8,     4,   102,     6,  1125,  1609,    57,    15,
      16,    17,    18,   111,   112,   103,    22,   126,   669,   117,
     737,    57,     8,   104,  1811,    26,    27,    28,    29,    15,
      16,    17,    18,   103,   104,   302,    22,    84,    84,   287,
     138,   139,   287,   103,   142,   696,     1,   354,    54,     4,
       1,     6,   359,     4,   103,     6,   141,  1489,   960,   102,
      13,   102,   103,   697,   103,   104,   105,   103,    54,   154,
     103,    26,    27,    28,    29,    26,    27,    28,    29,   113,
     302,    30,   205,  1548,  1549,   170,   209,   354,    89,   113,
      41,    49,  1179,    44,  1181,    96,   130,    49,   320,  1564,
     113,   320,   256,    52,   320,   143,   354,   210,   262,   354,
       4,   127,     6,     5,    63,  1489,   162,    45,    46,   365,
    1180,   159,     1,   757,    62,     4,    53,     6,   162,   375,
     376,     5,   133,    86,    89,   125,   152,    58,    47,    89,
      84,    96,    92,    32,    33,    34,   365,    26,    27,    28,
      29,   397,  1584,   166,   167,   103,   375,   376,     8,   149,
      98,   353,    41,  1584,    89,    44,   167,    92,   392,   159,
     392,  1115,  1291,   392,    24,  1294,   392,   286,   133,   425,
     277,   125,   279,   407,   288,   407,   288,  1561,   407,    89,
     304,   407,   438,   127,   297,   298,   354,   320,   301,  1573,
      84,    84,   455,    86,    54,   149,   322,   323,   324,  1583,
    1584,   162,   167,  2000,   957,   359,  1118,  1119,   152,     1,
     959,   958,     4,   359,     6,  1652,     1,   251,   252,     4,
     359,     6,   317,   341,   342,   343,    89,     1,   334,   359,
       4,   337,     6,   960,    26,    27,    28,    29,   338,   339,
      45,    26,    27,    28,    29,   288,   205,  1899,  1896,  1203,
     209,   304,    26,    27,    28,    29,     8,   354,   354,   392,
     271,   359,   359,    15,    16,    17,    18,   359,   353,   326,
     354,    89,  1934,   162,   407,  1935,   355,   355,  1407,   359,
    1409,  1410,   270,  1412,   355,   358,   355,   355,  1246,  1247,
     354,  1869,  1248,  1250,  1249,   359,   409,   285,   132,  1911,
     413,   352,    54,  1201,   417,   354,   271,    57,   359,   422,
     322,  1959,  1964,   301,   427,    89,   110,   102,     8,   546,
     332,   827,    96,  1707,   285,    15,    16,    17,    18,   340,
     110,   125,  1066,  1650,  1809,  2017,  1798,    22,  2015,  1868,
      25,  2016,   358,   236,   355,   125,   454,  1705,   247,   349,
     145,   744,  1356,   103,  1451,     5,   569,  1454,     8,   133,
    1457,   320,   358,  1850,    54,   881,   270,   277,   270,   279,
    1859,  1859,    89,   766,  1010,   340,  1012,   926,  1448,   492,
     340,   285,   490,   285,   294,    57,   270,     7,   532,    57,
     355,    38,    39,   167,   355,   236,   285,   301,   625,   301,
      20,   285,   306,   296,   306,   340,   882,   907,   286,  1677,
     341,   342,   343,   134,   277,   628,   279,   301,   354,  1671,
    1672,     0,   306,     8,   302,     4,   926,     6,   322,   323,
     324,   103,     8,   392,   125,   103,   731,   732,  1105,   103,
      84,    66,  1710,  1425,   143,   166,   167,  1108,   407,   148,
     926,  1102,   236,   355,   145,   946,  1683,     1,   149,   277,
       4,   279,     6,   354,   128,   129,   355,     1,  1135,    54,
       4,   355,     6,   268,   269,  1387,   197,     7,    54,   333,
    1131,   125,    26,    27,    28,    29,    84,  1429,    86,   342,
      20,   165,    26,    27,    28,    29,   170,   271,     1,  1441,
       4,     4,     6,     6,    38,   149,  1424,  1865,   102,   230,
     302,    30,   880,  1945,    30,   744,   772,   354,   744,   304,
     305,   102,   359,    26,    27,    28,    29,  1656,  1947,    84,
    1166,    86,   162,    52,  1944,   113,    52,   766,   185,    30,
     766,   188,  1946,   772,    63,   102,    30,    63,   340,  1491,
    1195,  1196,    20,   348,    22,   340,   134,  1202,   102,   286,
     277,    52,   279,   355,     5,   729,   340,     8,    52,   147,
     355,  2013,    63,   102,   103,   802,  1099,   268,   269,    63,
    1373,   355,  2013,   247,   113,   814,   134,     1,   286,    79,
       4,   804,     6,  1526,  1527,  1528,  1529,   166,   167,  1115,
     103,   104,   105,   267,   268,    95,   358,   237,   238,   239,
      84,   744,    26,    27,    28,    29,  1283,     1,   166,   167,
       4,   169,     6,  1284,   114,     4,   882,    41,  2012,  2013,
      44,  1282,     4,   766,     6,    20,     1,    22,   236,     4,
     340,     6,    26,    27,    28,    29,   875,   876,   877,   878,
     879,   880,    45,   882,   880,   152,  1090,   348,   953,   954,
     955,    26,    27,    28,    29,   162,   163,    39,   358,    17,
     926,  1939,   297,   298,   969,  1804,    41,   316,   907,    44,
      18,   236,   113,    77,    30,  1814,   205,  1203,   358,   205,
     209,    52,  1821,   209,   351,   352,  1245,   926,   296,   130,
      52,   113,   354,  1252,   135,   136,    52,   304,   305,    93,
     111,   112,  1218,   125,   205,   127,   110,    63,   209,   297,
       4,   205,     6,   354,     8,   209,   351,  1856,  1121,    57,
     931,   125,   162,   145,   935,   102,   103,   149,   130,   354,
     152,   296,   134,   354,  1244,  1245,   113,   880,   162,   133,
     354,  1251,  1252,  1253,  1254,   868,   287,   354,  1281,   872,
     304,   305,     1,    62,    63,     4,   354,     6,    67,    30,
    2038,    43,   397,     7,   166,   167,   170,   285,  1907,  1908,
    1909,    45,   290,   291,  1011,   744,  1013,    26,    27,    28,
      29,    52,  1019,  1726,  1727,  1728,   340,   162,   306,     8,
     425,   320,    63,  1932,   320,   236,   340,   766,   286,    15,
      16,   355,   115,   438,     4,     1,     6,     7,     4,    45,
       6,   355,  1615,   235,   102,   103,   304,   305,   131,   320,
     287,   288,  1225,    45,  1227,   113,   320,   340,     7,   300,
      26,    27,    28,    29,  1914,   103,   247,   248,   360,   152,
     251,    20,   355,    22,    93,   158,   268,   269,   360,   205,
     254,   304,   305,   209,   333,   231,   296,   297,   298,   299,
     300,   285,   102,   392,   240,   241,   392,     1,   244,   245,
       4,   127,     6,  1729,  1730,  1731,  1732,   271,   407,   327,
     328,   407,  1121,   333,   133,  1121,  1403,   143,   111,   112,
     113,   392,    26,    27,    28,    29,   152,   357,   392,  1432,
     113,   350,   158,   159,    15,    16,   407,   103,   104,   105,
     285,   880,    84,   407,   127,    15,    16,  1869,   304,   305,
      46,   134,    48,    52,    50,    51,   348,   192,   193,   242,
     243,   355,    58,    59,   205,   190,   191,  1203,   209,   152,
      23,  2080,  2081,  2082,    23,   158,   340,   111,   112,     1,
    1509,  1510,     4,    52,     6,  1632,  1195,  1196,  1197,  1198,
    1199,   355,  1201,  1202,   320,    91,  1627,  1638,  1484,     7,
    1486,  1210,  1211,  1490,    26,    27,    28,    29,  1121,     4,
     355,     6,    20,     8,    22,    45,  1225,    47,  1227,  1225,
    1667,  1227,    52,    52,    54,   341,   342,   343,    58,  1509,
    1510,  1662,   354,  1664,     7,  1244,  1245,  1246,  1247,  1248,
    1249,  1250,  1251,  1252,  1253,  1254,    52,    20,    52,    22,
     102,  1424,   271,  1879,  1880,  1881,  1268,   111,   112,  1268,
       4,     5,  1268,   111,   112,     1,   392,    97,     4,    99,
       6,    93,     1,    84,  1577,     4,   102,     6,   102,   320,
      17,   407,   102,   103,  1265,  1266,  1267,  1268,  1269,  1270,
      26,    27,    28,    29,   326,   327,   328,    26,    27,    28,
      29,   102,  1309,   103,   104,   105,  1266,  1267,  1268,  1269,
    1270,   133,  1225,     1,  1227,   102,     4,  1620,     6,    94,
      95,   340,    43,    44,   365,  1210,  1211,    60,    61,  2021,
    2022,   322,   323,   324,   375,   376,   355,   102,    26,    27,
      28,    29,   113,    84,   115,   116,   117,   118,  1724,    84,
      18,   392,     5,  1360,  1361,  1268,  1721,   365,   220,  1722,
     358,   766,   224,   225,   226,     7,   407,   375,   376,  1362,
    1363,    85,    86,    87,   340,    89,   109,     7,     7,   319,
       7,  1750,  1121,   287,   113,     1,   119,   102,     4,   355,
       6,  1403,   125,   102,  1403,     5,     7,  1403,  1379,   354,
       7,  1382,    17,  1384,  1676,  1441,  1387,  1776,   358,    18,
      26,    27,    28,    29,     8,  1424,   149,   102,  1424,  1379,
    1429,     7,  1382,   102,  1384,   113,    38,  1387,   354,  1443,
     354,  1443,  1441,   354,  1443,   354,   340,  1443,  1445,   354,
     287,   302,    37,  1719,   102,   744,   102,   102,   744,   271,
      45,   355,    47,   354,    49,   102,   861,    52,    53,    54,
     103,    56,  1443,   102,   113,   102,   115,   766,   102,   189,
     766,    96,   194,   744,   224,   227,   881,  1650,  1490,   130,
     744,  1490,  1491,   228,  1490,   134,  1225,   227,  1227,   228,
    1403,   229,   334,   142,   143,   766,   145,   113,   102,   102,
    1509,  1510,   766,   111,   112,   103,   155,   156,   106,   107,
     108,  1424,   120,   121,   122,   123,   124,   102,   340,     1,
    1967,   102,     4,   102,     6,   102,   354,  1968,   102,  1268,
    1443,   354,  1705,   355,     5,  1966,    12,  1546,   354,     8,
    1546,   102,   271,   102,    26,    27,    28,    29,  1835,    52,
     102,   287,  1533,    43,  1563,  1546,    38,  1563,    22,   148,
    1541,  1542,  1543,  1544,  1545,   219,   220,   221,   222,   223,
    1582,     5,  1563,  1582,  2005,  2006,  1582,  1490,  1559,  1560,
    1561,   880,   102,   271,   880,   310,   311,   312,   313,   314,
    1571,  1572,  1573,   357,     8,    71,    84,    84,    22,    75,
    1581,  1582,  1583,  1584,   340,   137,   138,   139,   140,   880,
      22,   340,   354,   102,    90,    91,   880,     7,   744,   355,
     354,  1581,  1582,  1583,  1584,   357,   355,  1520,  1521,  1522,
    1523,   354,   108,  1546,     7,  1616,  1617,  1618,  2085,   102,
     766,  1650,   361,   361,  1650,  2086,     1,   288,     5,     4,
    1563,     6,   340,  2084,   103,   271,  1616,  1617,  1618,   354,
      20,   137,  1965,   303,  1403,   303,    43,   355,   144,  1582,
     189,    26,    27,    28,    29,   270,   111,   112,   215,   216,
     217,   218,    45,   307,   302,  1424,    97,    98,    99,   100,
     285,   126,  1865,   128,   129,   130,  1705,    60,    61,  1705,
     287,  2004,     7,   744,  1443,    45,   301,     5,    70,  1690,
    1115,   306,   164,   308,  1750,     7,   151,   152,   153,   102,
      60,    61,    39,   103,   340,   766,    98,   103,   102,   189,
     353,   772,   353,   103,   353,   102,   102,  1650,   102,   355,
    1776,   102,    37,    20,    98,     5,   109,    84,   188,   355,
      45,  1490,    47,   102,   880,   102,   119,    52,    53,    54,
    1803,    56,   125,   102,   772,  1746,   102,  1748,  1749,   109,
    1813,    78,    79,    80,    81,    82,    83,  1820,   102,   119,
    2083,  1762,  1675,  1676,   355,   125,   149,  1768,    41,     7,
     353,   150,  1705,   102,  1775,   287,   102,  1778,  1203,   102,
     104,   355,   288,  1784,   185,   354,   354,  1546,   354,   149,
    1791,  1792,  1793,   354,   354,   354,   354,   103,   354,   354,
     861,   102,  1121,  1835,  1563,  1121,  1835,   354,   102,  1835,
     355,  1791,  1792,  1793,   875,   876,   877,   878,   879,   880,
     133,   882,   355,  1582,   354,   354,   354,     8,     8,   103,
    1121,   102,   353,   102,   102,     5,  1865,  1121,   340,  1865,
    1869,     8,   102,   524,  1298,    20,   907,   875,   876,   877,
     878,   879,   394,   355,   882,  1273,  1567,   113,  1887,   115,
    2062,  1887,  2038,  1894,  1892,   926,  1951,  1896,  1954,  1953,
    1896,  1952,  1873,  1943,  2024,    89,  1887,  1522,   134,   907,
     391,    91,  1710,   782,   791,  1896,   142,   143,   144,   145,
    1692,  1650,   307,  1663,  1637,   848,  1665,  1942,   926,   393,
    2009,  1902,  1835,  1904,  1197,  1199,  1225,  1216,  1227,  1225,
    1198,  1227,   864,  1422,  1915,  1916,  1424,  1918,  1919,  1920,
    1921,  1922,   767,  1223,  1925,   290,   873,   302,   998,  1254,
    1959,  1158,  1865,  1959,  1225,   205,  1227,  1404,  1434,   376,
     403,  1225,  1439,  1227,   405,  2072,  1705,   406,  1959,  1268,
     302,   120,  1268,   404,  1887,   270,   303,   634,   303,  1960,
    1022,    -1,  1022,  1896,  1045,   340,    -1,    -1,  1969,  1970,
     285,    -1,    -1,    -1,    -1,  1121,    -1,  1268,    -1,  2011,
     355,    -1,  2011,    -1,  1268,  2011,   301,    -1,    -1,    -1,
      -1,   306,    -1,   308,    -1,    -1,    -1,  1422,  2027,  1424,
    1425,  2027,    -1,    -1,    -1,    -1,    -1,    -1,    -1,  2010,
    2011,  2012,  2013,    -1,    -1,    -1,  2027,  2018,  2019,  2020,
    2021,    -1,    -1,    -1,  2025,   365,  1959,  2028,    -1,    -1,
    2010,  2011,  2012,  2013,    -1,   375,   376,    -1,  2018,  2019,
    2020,  2021,  2043,    -1,    -1,    -1,    -1,  2048,  2049,  2050,
    2051,  2052,  2053,  2054,  2055,  2056,  2057,  2058,  2059,    -1,
    1121,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,  2073,  2053,  2054,  2055,  1835,    -1,  2011,  1225,
      -1,  1227,    -1,    -1,  1403,    -1,    -1,  1403,    -1,    -1,
    2091,  2092,  2093,    -1,  2027,    -1,    -1,    -1,    45,    -1,
      -1,    -1,    -1,    -1,    -1,  1424,  1865,    -1,  1424,    -1,
    1535,    -1,  1403,    60,    61,    -1,    -1,  1178,  1179,  1403,
    1181,    -1,  1268,    -1,  1443,    -1,    -1,  1443,  1887,    -1,
      -1,    -1,    -1,  1424,    -1,    -1,    -1,  1896,    -1,    -1,
    1424,    -1,    -1,    -1,    -1,    -1,    -1,    37,    -1,    -1,
      -1,    -1,  1443,    -1,    -1,    -1,    -1,    -1,    -1,  1443,
      -1,    -1,   109,    -1,  1225,    -1,  1227,    -1,    -1,    -1,
      -1,  1490,   119,    -1,  1490,    -1,    -1,    -1,   125,    -1,
      -1,    -1,    -1,  1244,  1245,  1246,  1247,  1248,  1249,  1250,
    1251,  1252,  1253,  1254,  1154,    -1,    86,    -1,    -1,  1490,
    1959,    -1,   149,    -1,    -1,    -1,  1490,  1268,    -1,    -1,
      -1,    -1,    -1,   103,    -1,    -1,  1244,  1245,  1246,  1247,
    1248,  1249,  1250,  1251,  1252,  1253,  1254,  1546,    -1,    -1,
    1546,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   128,   129,
      70,    -1,    -1,    -1,  1563,    -1,    -1,  1563,    -1,    -1,
    1675,  1676,  2011,    -1,    -1,  1546,    -1,  1403,    -1,    -1,
      -1,    -1,  1546,  1582,    -1,    -1,  1582,    -1,  2027,    -1,
      -1,    -1,  1563,   103,   104,   105,    -1,    -1,  1424,  1563,
     110,    -1,   111,   112,   114,    -1,    -1,    -1,    -1,   119,
      -1,  1582,    -1,    -1,    -1,   125,   125,  1443,  1582,   129,
      -1,    45,    -1,    -1,   133,    -1,  1266,  1267,  1268,  1269,
    1270,    -1,    -1,    -1,    -1,    -1,    60,    61,    -1,   149,
     149,   107,    -1,   109,   110,  1750,    -1,   113,    -1,   115,
      -1,  1650,   118,   119,  1650,    -1,   122,   123,   124,   125,
      -1,    -1,  1403,   129,  1490,    -1,   132,   133,    -1,    -1,
      -1,  1776,    -1,    -1,   140,    -1,    -1,   247,  1783,  1650,
      -1,  1422,    -1,  1424,  1425,   109,  1650,    -1,  1429,    -1,
      -1,    -1,    -1,    -1,    -1,   119,    -1,   267,   268,    -1,
    1441,   125,  1443,    -1,    -1,    -1,  1705,    -1,    -1,  1705,
    1451,    45,    -1,  1454,    -1,   285,  1457,    -1,    -1,    -1,
    1546,  1429,    -1,    -1,    -1,   149,    60,    61,    -1,    -1,
      -1,   301,    -1,  1441,  1705,    -1,   306,  1563,   308,  1379,
      -1,  1705,  1382,    45,  1384,    -1,    -1,  1387,    -1,  1490,
    1491,    -1,   772,    -1,    -1,    -1,  1582,    10,    60,    61,
      -1,    -1,   271,   272,   273,   274,    -1,    -1,  1509,  1510,
     280,    -1,    -1,   283,   284,   109,    -1,    -1,   287,   288,
     289,    -1,    -1,  1491,    -1,   119,    39,    40,    41,    42,
      -1,   125,    -1,    -1,   814,    -1,  1901,    -1,  1903,  1439,
      -1,  1509,  1510,    45,    -1,  1546,    -1,   109,   318,   319,
      -1,    -1,    -1,    -1,    -1,   149,    -1,   119,    60,    61,
      73,    -1,  1563,   125,  1650,    -1,    -1,    -1,    81,    82,
      83,    84,    -1,    -1,    -1,    -1,  1835,    -1,    -1,  1835,
      -1,  1582,    -1,    -1,    -1,    -1,    -1,   149,    -1,   359,
      -1,   104,    -1,    -1,    -1,   875,   876,   877,   878,   879,
      -1,    -1,   882,    -1,  1835,    -1,  1865,   109,   121,  1865,
      -1,  1835,    -1,   126,   127,   128,    -1,   119,   131,  1705,
      -1,   134,    -1,   125,    -1,    -1,    -1,   907,  1887,    -1,
      -1,  1887,    -1,    -1,  1865,    -1,    -1,  1896,    -1,    -1,
    1896,  1865,    -1,    -1,    -1,    -1,   926,   149,    -1,  1650,
      -1,    -1,    -1,    -1,    -1,    -1,  1887,  2022,    -1,   741,
      -1,   743,    -1,  1887,    -1,  1896,    -1,    -1,    -1,    -1,
      -1,    -1,  1896,  2038,    -1,    -1,    -1,   759,   760,    -1,
     762,  1581,  1582,  1583,  1584,    -1,   768,   769,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,  2062,    -1,    -1,
    1959,    -1,    -1,  1959,  1705,    -1,    -1,    -1,    45,    -1,
      -1,    -1,    -1,   795,    -1,   797,  1616,  1617,  1618,    -1,
      -1,    -1,    -1,    60,    61,    -1,    -1,    -1,  1959,   455,
      -1,    -1,    -1,    -1,    -1,  1959,    -1,    -1,     1,    -1,
      -1,     4,    -1,     6,    -1,    -1,    -1,    -1,    -1,  1835,
      -1,    -1,  2011,    -1,    -1,  2011,    -1,    -1,   271,   272,
     273,    -1,    -1,    26,    27,    28,    29,    -1,  2027,    -1,
      -1,  2027,   109,    -1,    -1,   857,    -1,    40,    -1,  1865,
    2011,    -1,   119,    -1,    -1,    -1,    -1,  2011,   125,    -1,
       1,    -1,    -1,     4,    -1,     6,  2027,    89,    -1,    -1,
      -1,  1887,    -1,  2027,    -1,    -1,    -1,    -1,    -1,    -1,
    1896,    -1,   149,    -1,    -1,    26,    27,    28,    29,   111,
     112,    -1,    -1,   115,    -1,    88,    89,    90,    91,    40,
      93,    -1,    -1,    96,  1835,    -1,   111,   112,    -1,    -1,
     115,   133,    -1,    -1,    -1,   927,   928,    -1,    -1,    -1,
     113,   126,   127,   128,   129,   130,   131,   132,   133,   134,
      -1,    -1,    -1,    -1,  1865,    -1,    -1,    -1,  1869,    -1,
      -1,    -1,    -1,  1959,    -1,    -1,    -1,    88,    89,    90,
      91,    -1,    93,    -1,    -1,    96,  1887,   400,   401,   402,
      -1,  1791,  1792,  1793,    -1,  1896,    -1,   189,    -1,   162,
     175,  1869,   113,    -1,    -1,   134,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   143,  1195,  1196,  1197,  1198,  1199,
     433,  1201,  1202,    -1,    -1,  2011,    -1,    -1,    -1,   158,
    1210,  1211,    -1,   162,    -1,    -1,    -1,   166,   167,    -1,
      -1,  2027,   171,   172,   173,   174,   175,    -1,    -1,   462,
      -1,   162,    -1,    -1,    -1,   247,    -1,    -1,  1959,    -1,
      -1,    -1,    -1,    -1,  1244,  1245,  1246,  1247,  1248,  1249,
    1250,  1251,  1252,  1253,  1254,    -1,    -1,    -1,    -1,   271,
     272,   273,   274,   275,   276,   277,   278,   279,   280,   281,
     282,   283,   284,    -1,    -1,   287,   288,   289,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   270,    -1,    23,
    2011,    -1,    -1,    -1,    -1,    -1,   308,    -1,    -1,    -1,
      -1,    -1,   285,    -1,    38,    -1,  2027,  1109,    -1,    -1,
       1,  1113,    -1,     4,    -1,     6,    -1,    -1,   301,    -1,
    1122,  1123,  1124,   306,    -1,  1127,    -1,  1129,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    26,    27,    28,    29,   270,
      -1,    -1,    -1,    -1,    -1,    -1,    37,  1149,    -1,    -1,
      -1,    -1,    -1,    -1,   285,    -1,    47,   340,    -1,    -1,
      -1,    52,    -1,    54,    -1,    56,    -1,    -1,   102,    -1,
     301,    -1,   355,    -1,    -1,   306,    -1,    -1,    -1,    -1,
      -1,  1183,    -1,  1185,    -1,    -1,    -1,    -1,    -1,  1191,
    2010,  2011,  2012,  2013,    -1,    -1,    -1,    -1,  2018,  2019,
    2020,  2021,  1204,    -1,  1206,    -1,    -1,     1,    -1,   340,
      -1,    -1,    -1,  1215,    -1,  1217,    -1,    11,    12,    13,
      14,    15,    16,    17,   355,    -1,    20,    -1,    -1,  1429,
      -1,    -1,    -1,  2053,  2054,  2055,    -1,    -1,    -1,   173,
      -1,  1441,   176,   177,   178,   179,   180,   181,   182,   183,
     184,   185,   186,   187,   188,    -1,    -1,    38,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   162,    -1,    -1,    -1,    -1,    -1,    71,    -1,    -1,
      74,    75,    76,    77,    78,    79,    -1,    -1,    -1,    -1,
      -1,  1491,    86,    -1,    88,    89,    90,    91,    92,    93,
      94,    95,    -1,    97,    98,    99,   100,    -1,   102,  1509,
    1510,    -1,   106,    -1,   108,    -1,    -1,   111,   112,    -1,
     114,   102,    -1,   117,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   111,   112,    -1,
      -1,   115,   136,   137,   138,   139,    -1,    -1,   142,    -1,
     144,    -1,    -1,    -1,    37,    -1,    -1,    -1,    -1,   133,
      -1,    -1,    45,    -1,    47,    -1,    49,    -1,    -1,    52,
      53,    54,    -1,    56,    -1,    -1,    -1,    60,    61,   270,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,  1390,  1391,
      -1,    -1,   173,    -1,   285,   176,   177,   178,   179,   180,
     181,   182,   183,   184,   185,   186,   187,   188,    -1,  1411,
     301,    -1,    -1,    -1,    -1,   306,    -1,   308,    -1,    -1,
      -1,    -1,    -1,    -1,  1426,    -1,   109,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   119,    -1,    -1,    -1,
      -1,    -1,   125,    -1,    -1,    -1,    -1,    -1,    -1,   340,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,  1460,    -1,
       1,    -1,    -1,     4,   355,     6,   149,    -1,    -1,    -1,
      -1,    -1,    -1,   247,    -1,  1477,    -1,  1479,    -1,    -1,
      -1,    -1,    23,    -1,    -1,    26,    27,    28,    29,    30,
      31,    -1,    -1,    -1,    35,    36,    37,   271,   272,   273,
     274,   275,   276,    -1,   278,   279,   280,   281,   282,   283,
     284,    52,    -1,   287,   288,   289,    -1,    -1,    -1,    -1,
      -1,    62,    63,    -1,    -1,    -1,    67,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   308,    -1,    -1,    78,    79,    80,
      81,    82,    83,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    93,    -1,    -1,    -1,    97,    -1,    99,    -1,
      -1,   102,   103,   104,   105,    -1,    -1,   108,    -1,   110,
      -1,    -1,   113,   114,    -1,    -1,    -1,    -1,   119,    -1,
      -1,    -1,    -1,    -1,   125,    -1,    -1,   270,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     141,    -1,   285,    -1,    -1,   146,    -1,    -1,   149,    -1,
      -1,    -1,    -1,   154,    -1,    -1,   157,    -1,   301,   160,
     161,   162,    -1,   306,   165,   308,    -1,   168,    -1,   170,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,  1645,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   447,   195,   196,    -1,    -1,    -1,    -1,
     454,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,  1869,
      -1,   465,  1674,   467,    -1,   469,    -1,   471,    -1,    -1,
      -1,    -1,   476,    -1,    -1,    -1,   480,    -1,   482,    -1,
     231,   232,   233,   234,    -1,    -1,   490,  1699,    -1,   240,
     241,    -1,    -1,   244,   245,   246,   247,   248,   249,   250,
     251,   252,   253,   254,   255,   256,   257,   258,   259,   260,
     261,   262,   263,   264,   265,   266,   267,    -1,    -1,   270,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   285,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   295,    -1,    -1,    -1,    -1,    -1,
     301,    -1,    -1,    -1,    -1,   306,    -1,    -1,    -1,    -1,
      -1,   312,   313,    -1,   315,    -1,    -1,   318,   319,   320,
     321,    -1,    -1,    -1,   325,    -1,    -1,    -1,   329,   330,
     331,    -1,    -1,    -1,   335,   336,    -1,     1,    -1,   340,
       4,    -1,     6,   344,    -1,    -1,   347,   348,    -1,    -1,
      -1,    -1,    -1,   354,   355,   356,    -1,    -1,   359,    23,
      -1,    -1,    26,    27,    28,    29,    30,    31,    -1,    -1,
      -1,    35,    36,    37,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    52,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    62,    63,
      -1,  1863,    -1,    67,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    78,    79,    80,    81,    82,    83,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    93,
      -1,    -1,    -1,    97,    -1,    99,    -1,    -1,   102,   103,
     104,   105,    -1,    -1,   108,    -1,   110,    -1,    -1,   113,
     114,    -1,    -1,    -1,    -1,   119,    -1,    -1,    -1,    -1,
      -1,   125,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   141,    -1,    -1,
      -1,    -1,   146,    -1,    -1,   149,    -1,    -1,    -1,    -1,
     154,    -1,    -1,   157,    -1,    -1,   160,   161,   162,    -1,
      -1,   165,    -1,    -1,   168,    -1,   170,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
       1,    -1,    -1,     4,    -1,     6,    -1,    -1,    -1,    -1,
      -1,   195,   196,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    26,    27,    28,    29,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    40,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   231,   232,   233,
     234,    -1,    -1,    -1,    -1,    -1,   240,   241,    -1,    -1,
     244,   245,   246,   247,   248,   249,   250,   251,   252,   253,
     254,   255,   256,   257,   258,   259,   260,   261,   262,   263,
     264,   265,   266,   267,    -1,    -1,   270,    88,    89,    90,
      91,    -1,    93,    -1,    -1,    96,    -1,    -1,    -1,    -1,
      -1,   285,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   295,   113,    -1,    -1,    -1,    -1,   301,    -1,    -1,
      -1,    -1,   306,    -1,    -1,    -1,    -1,    -1,   312,   313,
      -1,   315,    -1,    -1,   318,   319,   320,   321,    -1,    -1,
      -1,   325,    -1,    -1,    -1,   329,   330,   331,    -1,    -1,
      -1,   335,   336,    -1,     1,    -1,   340,     4,    -1,     6,
     344,   162,    -1,   347,   348,    -1,    -1,    -1,    -1,    -1,
     354,   355,   356,    -1,    -1,   359,    23,    -1,    -1,    26,
      27,    28,    29,    30,    31,    -1,    -1,    -1,    35,    36,
      37,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    52,    -1,   981,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    62,    63,    -1,    -1,    -1,
      67,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    78,    79,    80,    81,    82,    83,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    93,    -1,    -1,    -1,
      97,    -1,    99,    -1,    -1,   102,   103,   104,   105,    -1,
      -1,   108,    -1,   110,    -1,    -1,   113,   114,    -1,   270,
      -1,    -1,   119,    -1,    -1,    -1,    -1,    -1,   125,    -1,
      -1,    -1,    -1,    -1,   285,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   141,    -1,    -1,    -1,    -1,   146,
     301,    -1,   149,    -1,    -1,   306,    -1,   154,    -1,    -1,
     157,    -1,    -1,   160,   161,   162,    -1,    -1,   165,    -1,
      -1,   168,    -1,   170,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   340,
      -1,     1,    -1,    -1,     4,    -1,     6,    -1,   195,   196,
      -1,    -1,    -1,    -1,   355,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    26,    27,    28,    29,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      40,    -1,    -1,    -1,   231,   232,   233,   234,    -1,    -1,
      -1,    -1,    -1,   240,   241,    -1,    -1,   244,   245,   246,
     247,   248,   249,   250,   251,   252,   253,   254,   255,   256,
     257,   258,   259,   260,   261,   262,   263,   264,   265,   266,
     267,    -1,    -1,   270,    -1,    -1,    -1,    -1,    -1,    89,
      -1,    91,    -1,    93,    -1,    -1,    96,    -1,   285,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   295,    -1,
      -1,    -1,    -1,   113,   301,    -1,    -1,    -1,    -1,   306,
      -1,    -1,    -1,    -1,    -1,   312,   313,    -1,   315,    -1,
      -1,   318,   319,   320,   321,    -1,    -1,    -1,   325,    -1,
      -1,    -1,   329,   330,   331,    -1,    -1,    -1,   335,   336,
      -1,    -1,     4,   340,     6,    -1,    -1,   344,    -1,    -1,
     347,   348,   162,    -1,    -1,    -1,    -1,   354,   355,   356,
      -1,    23,   359,    -1,    -1,    -1,    -1,    -1,    30,    31,
      -1,    -1,    -1,    35,    36,    37,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      52,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      62,    63,   103,    -1,    -1,    67,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    78,    79,    80,    81,
      82,    83,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   130,
      -1,    -1,   133,    -1,    -1,    97,    -1,    99,    -1,    -1,
     102,   103,   104,   105,    -1,    -1,   108,    -1,   110,   150,
      -1,    -1,   114,    -1,    -1,    -1,    -1,   119,    -1,    -1,
     270,    -1,    -1,   125,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   285,    -1,    -1,    -1,   141,
      -1,    -1,    -1,    -1,   146,    -1,    -1,   149,    -1,    -1,
      -1,   301,   154,   180,    -1,   157,   306,    -1,   160,   161,
      -1,    -1,    -1,   165,    -1,    -1,   168,    -1,   170,    -1,
      -1,   198,   199,   200,   201,   202,   203,   204,   205,   206,
     207,   208,   209,   210,   211,   212,   213,   214,    -1,    -1,
     340,    -1,    -1,   195,   196,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   355,   247,   248,   249,   250,
     251,   252,   253,   254,   255,   256,   257,   258,   259,   260,
     261,   262,   263,   264,   265,   266,   267,    -1,    -1,   231,
     232,   233,   234,    -1,    -1,    -1,    -1,    -1,   240,   241,
      -1,    -1,   244,   245,   246,   247,   248,   249,   250,   251,
     252,   253,   254,   255,   256,   257,   258,   259,   260,   261,
     262,   263,   264,   265,   266,   267,    -1,   308,   270,    -1,
       5,   312,   313,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   322,    -1,   285,    -1,    -1,    -1,    -1,    23,    -1,
      -1,    -1,    -1,   295,    -1,    -1,    31,    -1,    -1,   301,
      -1,    36,    -1,    -1,   306,    -1,    -1,   348,    -1,    -1,
     312,   313,    -1,   315,    -1,    -1,   318,   319,   320,   321,
      -1,    -1,    -1,   325,    -1,    -1,    -1,   329,   330,   331,
      -1,    -1,    -1,   335,   336,    70,    -1,    -1,    -1,    -1,
      -1,    -1,   344,    -1,    -1,   347,   348,    -1,    -1,    84,
      -1,    86,   354,   355,   356,    -1,    -1,   359,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   102,   103,   104,
     105,    -1,    -1,   108,    -1,   110,    -1,    -1,    -1,   114,
      -1,    -1,    -1,    -1,   119,    -1,    -1,    -1,    -1,    -1,
     125,    -1,    -1,    -1,   129,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   141,    -1,    -1,    -1,
      -1,   146,    -1,    -1,   149,    -1,    -1,    -1,    -1,   154,
      -1,    -1,   157,    -1,    -1,   160,   161,    -1,    -1,    -1,
     165,    -1,    -1,   168,    -1,   170,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     195,   196,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,     5,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    23,
      -1,    -1,    -1,    -1,    -1,    -1,   231,    31,    -1,    -1,
      -1,    -1,    36,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   246,   247,   248,   249,   250,   251,   252,   253,   254,
     255,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,    -1,    -1,   270,    70,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   280,    -1,    -1,   283,   284,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   296,    -1,    -1,    -1,    -1,    -1,    -1,   102,   103,
     104,   105,    -1,    -1,   108,    -1,   110,   312,   313,    -1,
     114,    -1,    -1,   318,   319,   119,    -1,    -1,    -1,    -1,
      -1,   125,    -1,    -1,    -1,   129,   331,    -1,    -1,    -1,
     335,   336,    -1,    -1,    -1,    -1,    -1,   141,    -1,    -1,
     345,   346,   146,   348,    -1,   149,    -1,    -1,    -1,    -1,
     154,   356,    -1,   157,   359,    -1,   160,   161,    -1,    -1,
      -1,   165,    -1,    -1,   168,    -1,   170,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   195,   196,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,     5,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      23,    -1,    -1,    -1,    -1,    -1,    -1,   231,    31,    -1,
      -1,    -1,    -1,    36,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   246,   247,   248,   249,   250,   251,   252,   253,
     254,   255,   256,   257,   258,   259,   260,   261,   262,   263,
     264,   265,   266,   267,    -1,    -1,   270,    70,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   280,    -1,    -1,   283,
     284,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   102,
     103,   104,   105,    -1,    -1,   108,    -1,   110,   312,   313,
      -1,   114,    -1,    -1,   318,   319,   119,    -1,    -1,    -1,
      -1,    -1,   125,    -1,    -1,    -1,   129,   331,    -1,    -1,
      -1,   335,   336,    -1,    -1,    -1,    -1,    -1,   141,    -1,
      -1,   345,   346,   146,   348,    -1,   149,    -1,    -1,    -1,
      -1,   154,   356,    -1,   157,   359,    -1,   160,   161,    -1,
      -1,    -1,   165,    -1,    -1,   168,    -1,   170,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   195,   196,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,     5,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    23,    -1,    -1,    -1,    -1,    -1,    -1,   231,    31,
      -1,    -1,    -1,    -1,    36,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   246,   247,   248,   249,   250,   251,   252,
     253,   254,   255,   256,   257,   258,   259,   260,   261,   262,
     263,   264,   265,   266,   267,    -1,    -1,   270,    70,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   280,    -1,    -1,
     283,   284,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     102,   103,   104,   105,    -1,    -1,   108,    -1,   110,   312,
     313,    -1,   114,    -1,    -1,   318,   319,   119,    -1,    -1,
      -1,    -1,    -1,   125,    -1,    -1,    -1,   129,   331,    -1,
      -1,    -1,   335,   336,    -1,    -1,    -1,    -1,    -1,   141,
      -1,    -1,   345,   346,   146,   348,    -1,   149,    -1,    -1,
      -1,    -1,   154,   356,    -1,   157,   359,    -1,   160,   161,
      -1,    -1,    -1,   165,    37,    -1,   168,    -1,   170,    42,
      -1,    -1,    45,    46,    47,    48,    -1,    -1,    51,    52,
      -1,    54,    55,    56,    -1,    58,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   195,   196,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,     5,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    23,    -1,    97,    -1,    99,   100,   101,   231,
      31,    -1,    -1,    -1,    -1,    36,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   246,   247,   248,   249,   250,   251,
     252,   253,   254,   255,   256,   257,   258,   259,   260,   261,
     262,   263,   264,   265,   266,   267,    -1,    -1,   270,    70,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   280,    -1,
      -1,   283,   284,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   102,   103,   104,   105,    -1,    -1,   108,    -1,   110,
     312,   313,    -1,   114,    -1,    -1,   318,   319,   119,    -1,
      -1,    -1,    -1,    -1,   125,    -1,    -1,    -1,   129,   331,
      -1,    -1,    -1,   335,   336,    -1,    -1,    -1,    -1,    -1,
     141,    -1,    -1,   345,   346,   146,   348,     1,   149,    -1,
       4,    -1,     6,   154,   356,    -1,   157,   359,    -1,   160,
     161,    -1,    -1,    -1,   165,    -1,    -1,   168,    -1,   170,
      -1,    -1,    26,    27,    28,    29,    -1,    -1,    -1,    -1,
      -1,    -1,     1,    37,    -1,     4,    -1,     6,    -1,    -1,
      -1,    -1,    -1,    47,   195,   196,    -1,   270,    52,    -1,
      54,    -1,    56,    -1,    -1,    -1,    -1,    26,    27,    28,
      29,    -1,   285,    -1,    -1,    -1,    -1,   290,   291,   292,
     293,    40,    -1,    -1,    -1,    -1,    -1,    -1,   301,    -1,
     231,    -1,    -1,   306,    -1,   308,   309,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   246,   247,   248,   249,   250,
     251,   252,   253,   254,   255,   256,   257,   258,   259,   260,
     261,   262,   263,   264,   265,   266,   267,    -1,    -1,   270,
      89,    -1,    91,    -1,    93,     1,    -1,    96,     4,   280,
       6,    -1,   283,   284,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   113,    -1,    -1,    -1,    -1,    -1,
      26,    27,    28,    29,    -1,    -1,    -1,    -1,   162,    -1,
      -1,   312,   313,    -1,    40,    -1,    -1,   318,   319,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     331,    -1,    -1,    -1,   335,   336,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   162,   345,   346,    -1,   348,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   356,    -1,    -1,   359,    -1,
      -1,    -1,    -1,    89,    -1,    91,    -1,    93,    -1,    -1,
      96,    -1,    -1,    -1,     9,    10,    11,    12,    13,    14,
      -1,    -1,    -1,    -1,    19,    -1,    -1,   113,    23,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   270,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   285,    -1,    -1,    -1,    70,   162,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   301,    -1,    -1,
      -1,   270,   306,    -1,   308,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    21,    -1,   285,   102,   103,   104,
     105,    -1,    -1,    -1,    -1,   110,    -1,    -1,    -1,   114,
      -1,    -1,   301,    -1,   119,    -1,   340,   306,    -1,    -1,
     125,    -1,    -1,    -1,   129,    -1,    -1,    -1,    -1,    -1,
      -1,   355,    -1,    -1,    -1,    -1,   141,    -1,    -1,    -1,
      -1,   146,    -1,    70,   149,    -1,    -1,    -1,    -1,   154,
      -1,   340,   157,    -1,    -1,   160,   161,    -1,    -1,    -1,
     165,    -1,    -1,   168,    -1,   170,   355,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   270,   102,   103,   104,   105,    -1,
      -1,    -1,    -1,   110,    -1,    -1,    -1,   114,    -1,   285,
     195,   196,   119,    -1,    -1,    -1,    -1,    -1,   125,    21,
      -1,    -1,   129,    -1,    -1,   301,    -1,    -1,    -1,    -1,
     306,    -1,    -1,    -1,   141,    -1,    -1,    -1,    -1,   146,
      -1,    -1,   149,    -1,    -1,    -1,    -1,   154,    -1,    -1,
     157,    -1,    -1,   160,   161,    -1,    -1,    -1,   165,    -1,
      -1,   168,    -1,   170,   340,    -1,    -1,    -1,    70,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   355,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   195,   196,
      -1,    -1,    -1,    -1,    -1,   280,    -1,    -1,   283,   284,
     102,   103,   104,   105,    -1,    -1,    -1,    -1,   110,    -1,
      -1,    -1,   114,    -1,    -1,    -1,    -1,   119,    -1,    -1,
      -1,    -1,    -1,   125,    -1,    -1,    -1,   129,    -1,    -1,
      -1,    -1,    -1,   318,   319,    -1,   321,    22,    23,   141,
      -1,    -1,    -1,    -1,   146,    -1,    -1,   149,    -1,    -1,
      -1,    -1,   154,    -1,    -1,   157,    -1,    -1,   160,   161,
     345,   346,    -1,   165,    -1,    -1,   168,    -1,   170,   354,
      -1,   356,    -1,   280,   359,    -1,   283,   284,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    70,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   195,   196,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   318,   319,    -1,   321,    -1,    -1,   102,   103,   104,
     105,    -1,    -1,    -1,    -1,   110,    -1,    -1,    -1,   114,
      -1,    -1,    -1,    -1,   119,    -1,    -1,    -1,   345,   346,
     125,    -1,    -1,    -1,   129,    -1,    -1,   354,    -1,   356,
      -1,    -1,   359,    -1,    -1,    -1,   141,    -1,    -1,    -1,
      -1,   146,    -1,    -1,   149,    -1,    -1,    -1,    -1,   154,
      -1,    -1,   157,    -1,    -1,   160,   161,    -1,   280,    -1,
     165,   283,   284,   168,    -1,   170,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     195,   196,    -1,    -1,    -1,    -1,   318,   319,    -1,   321,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   345,   346,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   356,    -1,    -1,   359,    -1,    -1,
      -1,    23,    -1,    -1,    -1,    -1,    -1,    -1,    30,    31,
      -1,    -1,    -1,    35,    36,    37,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      52,    -1,    -1,    -1,    -1,   280,    -1,    -1,   283,   284,
      62,    63,   103,    -1,    -1,    67,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    78,    79,    80,    81,
      82,    83,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   130,
      -1,    -1,   133,   318,   319,    97,   321,    99,    -1,    -1,
     102,   103,   104,   105,    -1,    -1,   108,    -1,   110,   150,
      -1,    -1,   114,    -1,    -1,    -1,    -1,   119,    -1,    -1,
     345,   346,    -1,   125,    -1,    -1,    -1,    -1,    -1,   354,
      -1,   356,    -1,    -1,   359,    -1,    -1,    -1,    -1,   141,
      -1,    -1,    -1,    -1,   146,    -1,    -1,   149,    -1,    -1,
      -1,    -1,   154,    -1,    -1,   157,    -1,    -1,   160,   161,
      -1,    -1,    -1,   165,    -1,    -1,   168,    -1,   170,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   195,   196,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   247,   248,   249,   250,
     251,   252,   253,   254,   255,   256,   257,   258,   259,   260,
     261,   262,   263,   264,   265,   266,   267,    -1,    -1,   231,
     232,   233,   234,    -1,    -1,    -1,    -1,    -1,   240,   241,
      -1,    -1,   244,   245,   246,   247,   248,   249,   250,   251,
     252,   253,   254,   255,   256,   257,   258,   259,   260,   261,
     262,   263,   264,   265,   266,   267,    -1,   308,   270,    -1,
      -1,   312,   313,    -1,    -1,    -1,    -1,    -1,    -1,    23,
      -1,   322,    -1,   285,    -1,    -1,    30,    31,    -1,    -1,
      -1,    -1,    36,   295,    -1,    -1,    -1,    -1,    -1,   301,
      -1,    -1,    -1,    -1,   306,    -1,    -1,   348,    -1,    -1,
     312,   313,    -1,   315,    -1,    -1,   318,   319,   320,   321,
      -1,    -1,    -1,   325,    -1,    -1,    -1,   329,   330,   331,
      -1,    -1,    -1,   335,   336,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   344,    -1,    -1,   347,   348,    -1,    -1,    -1,
      -1,    -1,   354,    -1,   356,    -1,    -1,   359,   102,   103,
     104,   105,    -1,    -1,   108,    -1,   110,    -1,    -1,    -1,
     114,    -1,    -1,    -1,    -1,   119,    -1,    -1,    -1,    -1,
      -1,   125,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   141,    -1,    -1,
      -1,    -1,   146,    -1,    -1,   149,    -1,    -1,    -1,    -1,
     154,    -1,    -1,   157,    -1,    -1,   160,   161,    -1,    -1,
      -1,   165,    -1,    -1,   168,    -1,   170,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   195,   196,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    23,    -1,    -1,    -1,    -1,    -1,    -1,    30,    31,
      -1,    -1,    -1,    -1,    36,    -1,    -1,   231,   232,   233,
     234,    -1,    -1,    -1,    -1,    -1,   240,   241,    -1,    -1,
     244,   245,   246,   247,   248,   249,   250,   251,   252,   253,
     254,   255,   256,   257,   258,   259,   260,   261,   262,   263,
     264,   265,   266,   267,    -1,    -1,   270,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    86,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     102,   103,   104,   105,    -1,    -1,   108,    -1,   110,    -1,
      -1,    -1,   114,    -1,    -1,    -1,    -1,   119,   312,   313,
      -1,    -1,    -1,   125,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   331,    -1,   141,
      -1,   335,   336,    -1,   146,    -1,    -1,   149,    -1,    -1,
      -1,    -1,   154,   347,   348,   157,    -1,    -1,   160,   161,
     354,    -1,   356,   165,    -1,   359,   168,    -1,   170,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      23,    -1,    -1,   195,   196,    -1,    -1,    30,    31,    -1,
      -1,    -1,    -1,    36,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   231,
     232,   233,   234,    -1,    -1,    -1,    -1,    -1,   240,   241,
      -1,    -1,   244,   245,   246,   247,   248,   249,   250,   251,
     252,   253,   254,   255,   256,   257,   258,   259,   260,   261,
     262,   263,   264,   265,   266,   267,    -1,    -1,   270,   102,
     103,   104,   105,    -1,    -1,   108,    -1,   110,    -1,    -1,
      -1,   114,    -1,    -1,    -1,    -1,   119,    -1,    -1,    -1,
      -1,    -1,   125,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   141,    -1,
     312,   313,    -1,   146,    -1,    -1,   149,    -1,    -1,    -1,
      -1,   154,    -1,    -1,   157,    -1,    -1,   160,   161,   331,
      -1,    -1,   165,   335,   336,   168,    -1,   170,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   347,   348,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   356,    -1,    -1,   359,    -1,    23,
      -1,    -1,   195,   196,    -1,    -1,    -1,    31,    -1,    -1,
      -1,    -1,    36,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   231,   232,
     233,   234,    -1,    -1,    -1,    -1,    70,   240,   241,    -1,
      -1,   244,   245,   246,   247,   248,   249,   250,   251,   252,
     253,   254,   255,   256,   257,   258,   259,   260,   261,   262,
     263,   264,   265,   266,   267,    -1,    -1,   270,   102,   103,
     104,   105,    -1,    -1,   108,    -1,   110,    -1,    -1,    -1,
     114,    -1,    -1,    -1,    -1,   119,    -1,    -1,    -1,    -1,
      -1,   125,    -1,    -1,    -1,   129,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   141,    -1,   312,
     313,    -1,   146,    -1,    -1,   149,    -1,    -1,    -1,    -1,
     154,    -1,    -1,   157,    -1,    -1,   160,   161,   331,    -1,
      -1,   165,   335,   336,   168,    -1,   170,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   347,   348,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   356,    -1,    -1,   359,    -1,    -1,    -1,
      -1,   195,   196,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      23,    -1,    -1,    -1,    -1,    -1,    -1,   231,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   246,   247,   248,   249,   250,   251,   252,   253,
     254,   255,   256,   257,   258,   259,   260,   261,   262,   263,
     264,   265,   266,   267,    -1,    -1,   270,    70,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   280,    -1,    -1,   283,
     284,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   102,
     103,   104,   105,    -1,    -1,    -1,    -1,   110,   312,   313,
      -1,   114,    -1,    -1,   318,   319,   119,    -1,    -1,    -1,
      -1,    -1,   125,    -1,    -1,    -1,   129,   331,    -1,    -1,
      -1,   335,   336,    -1,    -1,    -1,    -1,    -1,   141,    -1,
      -1,   345,   346,   146,   348,    -1,   149,    -1,    -1,    -1,
      -1,   154,   356,    -1,   157,   359,    -1,   160,   161,    -1,
       0,     1,   165,    -1,     4,   168,     6,   170,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    26,    27,    28,    29,
      -1,    -1,   195,   196,    -1,    -1,    -1,    37,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    45,    -1,    47,    -1,    49,
      -1,    -1,    52,    53,    54,    -1,    56,    -1,    -1,    -1,
      60,    61,    62,    -1,    64,    65,    66,    67,    68,    69,
      70,    71,    72,    73,    74,    75,    76,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   103,    -1,    -1,    -1,    -1,    -1,   109,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   280,    -1,   119,
     283,   284,    -1,    -1,    -1,   125,    -1,    -1,    -1,    70,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    78,    79,    80,
      81,    82,    83,    -1,    -1,    -1,    -1,    -1,    -1,   149,
      -1,    -1,    -1,    -1,    -1,   318,   319,    -1,   321,    -1,
      -1,   102,   103,   104,   105,    -1,    -1,    -1,    -1,   110,
      -1,    -1,    -1,   114,    -1,    -1,    -1,    70,   119,    -1,
      -1,    -1,   345,   346,   125,    -1,    -1,    -1,   129,    -1,
      -1,   354,    -1,   356,    -1,    -1,   359,    -1,    -1,    -1,
     141,    -1,    -1,    -1,    -1,   146,    -1,    -1,   149,   102,
     103,   104,   105,   154,    -1,    -1,   157,   110,    -1,   160,
     161,   114,    -1,    -1,   165,    -1,   119,   168,    -1,   170,
      -1,    -1,   125,    -1,    -1,    -1,   129,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   141,    -1,
      -1,    -1,    -1,   146,   195,   196,   149,    -1,    -1,    -1,
      -1,   154,    -1,    -1,   157,    -1,    -1,   160,   161,    -1,
     270,    -1,   165,    -1,    -1,   168,    -1,   170,    -1,    -1,
      -1,    70,    -1,    -1,    -1,   285,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   301,   195,   196,    -1,    -1,   306,    -1,   308,    -1,
      -1,    -1,    -1,   102,   103,   104,   105,    -1,    -1,    -1,
      -1,   110,    -1,    -1,    -1,   114,    -1,    -1,    -1,    -1,
     119,    -1,    -1,    -1,    -1,    -1,   125,    -1,    -1,   280,
     129,    -1,   283,   284,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   141,    -1,    -1,    -1,    -1,   146,    -1,    -1,
     149,    -1,    -1,    -1,    -1,   154,    -1,    -1,   157,    -1,
      -1,   160,   161,    -1,    -1,    -1,   165,   318,   319,   168,
     321,   170,    -1,    -1,    -1,    -1,    -1,   280,    -1,    -1,
     283,   284,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   345,   346,   195,   196,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   356,    -1,    -1,   359,    -1,
      -1,    -1,    -1,    -1,    -1,   318,   319,    -1,   321,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   345,   346,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   356,    -1,    -1,   359,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   280,    -1,    -1,   283,   284,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   318,
     319,    -1,   321,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   345,   346,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   356,    -1,    -1,
     359
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_int16 yystos[] =
{
       0,   363,     0,     1,     4,     6,    26,    27,    28,    29,
      37,    45,    47,    49,    52,    53,    54,    56,    60,    61,
      62,    64,    65,    66,    67,    68,    69,    70,    71,    72,
      73,    74,    75,    76,   109,   119,   125,   149,   270,   285,
     301,   306,   308,   364,   388,   389,   390,   391,   463,   464,
     465,   467,   482,   364,   104,   103,   460,   460,   460,   465,
     476,   465,   467,   482,   465,   470,   470,   470,   465,   473,
     391,    49,   392,    37,    45,    47,    52,    53,    54,    56,
     270,   285,   301,   306,   308,   393,    49,   394,    37,    45,
      47,    49,    52,    53,    54,    56,   270,   285,   301,   306,
     308,   399,    53,   400,    37,    42,    45,    46,    47,    48,
      51,    52,    54,    55,    56,    58,    97,    99,   100,   101,
     270,   285,   290,   291,   292,   293,   301,   306,   308,   309,
     401,   285,   290,   291,   306,   404,    45,    47,    52,    54,
      58,    97,    99,   405,    47,   406,    23,    30,    31,    36,
     102,   103,   104,   105,   108,   110,   114,   119,   125,   141,
     146,   149,   154,   157,   160,   161,   165,   168,   170,   195,
     196,   231,   232,   233,   234,   240,   241,   244,   245,   246,
     247,   248,   249,   250,   251,   252,   253,   254,   255,   256,
     257,   258,   259,   260,   261,   262,   263,   264,   265,   266,
     267,   270,   312,   313,   331,   335,   336,   347,   348,   356,
     359,   414,   461,   584,   585,   588,   589,   590,   594,   657,
     660,   662,   666,   671,   672,   674,   676,   686,   687,   689,
     691,   693,   695,   699,   701,   703,   705,   707,   709,   711,
     713,   715,   717,   727,   735,   737,   739,   740,   742,   744,
     746,   748,   750,   752,   754,   756,    58,   341,   342,   343,
     407,   413,    58,   408,   413,   103,   409,   410,   366,   372,
     373,    89,   277,   279,   476,   476,   476,   476,     0,   364,
     460,   460,    57,   338,   339,   479,   480,   481,    35,    37,
      52,    62,    63,    67,    78,    79,    80,    81,    82,    83,
      97,    99,   246,   270,   285,   295,   301,   306,   315,   318,
     319,   320,   321,   325,   329,   330,   344,   354,   486,   487,
     488,   490,   491,   492,   493,   494,   495,   499,   500,   501,
     504,   505,   512,   516,   524,   525,   528,   529,   530,   531,
     532,   553,   554,   556,   557,   559,   560,   563,   564,   565,
     575,   576,   577,   578,   579,   582,   583,   589,   596,   597,
     598,   599,   600,   601,   605,   606,   607,   641,   655,   660,
     661,   684,   685,   686,   364,   353,   353,   364,   460,   536,
     415,   418,   486,   460,   423,   425,   584,   607,   428,   460,
     433,   467,   483,   476,   465,   467,   470,   470,   470,   473,
      89,   277,   279,   476,   476,   476,   476,   482,   398,   465,
     476,   477,   395,   463,   465,   466,   396,   465,   467,   468,
     483,   397,   465,   470,   471,   470,   470,   465,   473,   474,
      89,   277,   279,   630,   398,   398,   398,   398,   470,   476,
     403,   464,   485,   465,   485,   467,   485,    45,   485,   470,
     470,   485,   473,   485,    45,    46,   470,   485,   485,    89,
     277,   294,   630,   631,   476,    45,   485,    45,   485,    45,
     485,    45,   485,   476,   476,   476,    45,   485,   376,   476,
      45,   485,    45,   485,   476,   465,   467,   470,   470,   485,
      45,   470,   467,   103,   106,   107,   108,   688,   111,   112,
     247,   248,   251,   592,   593,    32,    33,    34,   247,   663,
     132,   595,   166,   167,   738,   111,   112,   113,   690,   113,
     115,   116,   117,   118,   692,   111,   112,   120,   121,   122,
     123,   124,   694,   111,   112,   115,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   175,   696,   113,   115,   134,
     142,   143,   144,   145,   700,   113,   134,   147,   297,   702,
     111,   112,   126,   128,   129,   130,   151,   152,   153,   704,
     113,   115,   134,   142,   143,   145,   155,   156,   706,   127,
     143,   152,   158,   159,   708,   143,   159,   710,   152,   162,
     163,   712,   130,   134,   166,   167,   714,   134,   166,   167,
     169,   716,   134,   143,   158,   162,   166,   167,   171,   172,
     173,   174,   175,   718,   113,   166,   167,   728,   134,   166,
     167,   197,   230,   736,   113,   125,   127,   145,   149,   152,
     235,   268,   269,   348,   673,   675,   743,   236,   745,   236,
     747,   162,   237,   238,   239,   749,   127,   152,   741,   115,
     131,   152,   158,   242,   243,   751,   127,   152,   753,   113,
     127,   134,   152,   158,   755,   103,   130,   133,   150,   308,
     322,   348,   658,   659,   660,   111,   112,   115,   133,   247,
     271,   272,   273,   274,   275,   276,   278,   279,   280,   281,
     282,   283,   284,   287,   288,   289,   308,   677,   678,   681,
     322,   332,   665,   601,   606,   333,   231,   240,   241,   244,
     245,   757,   351,   352,   375,   668,   600,   460,   380,   413,
     342,   413,    46,    48,    50,    51,    58,    59,    91,   411,
     476,   476,   476,   368,   625,   640,   627,   629,   102,   102,
     102,    84,   673,   286,   576,   460,   584,   656,   656,    62,
      98,   460,   103,   658,    89,   189,   277,   677,   678,   286,
     286,   302,   286,   304,   305,   513,    84,   162,    84,    84,
     673,     4,   365,   608,   609,   340,   484,   491,   418,   368,
     287,   288,   502,   503,   387,   162,   296,   297,   298,   299,
     300,   506,   507,   316,   527,     5,    70,    84,    86,   110,
     114,   119,   125,   129,   149,   231,   280,   283,   284,   296,
     318,   319,   345,   346,   356,   539,   540,   541,   542,   543,
     544,   545,   547,   548,   549,   550,   551,   552,   585,   588,
     594,   650,   651,   652,   657,   662,   666,   672,   673,   674,
     676,   682,   683,   686,    38,    39,   185,   188,   533,   534,
      84,   322,   323,   324,   555,   561,   562,    84,   558,   561,
     381,   326,   327,   328,   566,   567,   571,   572,    23,   584,
     586,   587,    45,   580,   581,    15,    16,    17,    18,   358,
       8,    24,    54,     9,    10,    11,    12,    13,    14,    19,
     110,   114,   119,   125,   141,   146,   149,   154,   157,   160,
     161,   165,   168,   170,   195,   196,   321,   356,   585,   587,
     588,   602,   603,   604,   607,   642,   643,   644,   645,   646,
     647,   648,   649,   651,   652,   653,   654,    52,    52,    22,
     354,   623,   642,   643,   648,   623,    38,   354,   535,   354,
     354,   354,   354,   354,   479,   486,   536,   415,   418,   423,
     425,   428,   433,   476,   476,   476,   368,   625,   640,   627,
     629,   486,    57,    57,    57,    57,   425,    57,   433,   476,
     368,   377,   379,   385,   425,    43,   402,   465,   470,   485,
     476,    45,   368,   465,   465,   465,   465,   377,   379,   385,
     465,   368,   465,   465,   379,   470,   460,     7,     8,   113,
     251,   252,   591,   300,   386,   103,   126,   286,   369,   374,
     110,   125,   110,   125,   366,   137,   138,   139,   140,   697,
     372,   373,    23,    38,   102,   173,   176,   177,   178,   179,
     180,   181,   182,   183,   184,   185,   186,   187,   188,   719,
     720,   721,   180,   198,   199,   200,   201,   202,   203,   204,
     205,   206,   207,   208,   209,   210,   211,   212,   213,   214,
     729,   734,   383,   372,   373,   375,   675,   382,   382,   360,
     360,   385,   385,   111,   112,   125,   133,   149,   271,   272,
     273,   679,   680,   681,   367,   333,   333,   102,   382,   350,
     667,   357,   412,   413,   638,   638,   638,   287,   354,   624,
     302,   354,   639,   354,   513,   626,   354,   461,   628,     5,
     125,   149,   551,    84,   551,   573,   574,   601,    23,    23,
      96,   354,    52,    52,    52,   102,   304,    52,   681,    52,
     551,   551,   304,   305,   517,   551,   102,   568,   569,   570,
     584,   588,   601,   605,   666,   672,   571,   551,   551,    84,
      21,   607,   612,   613,   614,   621,   648,   649,     7,   355,
     461,   354,   102,   102,   503,    77,   110,   125,   170,   254,
     509,   461,   102,   102,   102,   461,   508,   507,   141,   154,
     170,   317,   551,     5,   551,    84,   369,   374,   366,   372,
     373,    84,   544,   585,   652,    15,    16,    17,    18,   358,
      20,    22,     8,    54,     5,   561,    84,    86,   236,   296,
       7,     7,   102,   102,   534,     5,     7,     5,   551,   569,
     584,   588,   567,     7,   460,   354,   460,   354,   581,   653,
     653,   644,   645,   646,   600,   354,   496,   586,   643,   372,
     373,   380,   383,   648,     7,    20,    15,    16,    17,    18,
     358,     7,    20,    22,     8,   642,   643,   648,   551,   551,
     102,   355,   364,    20,   364,   102,   448,   417,   419,   424,
     430,   434,   535,   354,   354,   354,   354,   354,   638,   638,
     638,   624,   639,   626,   628,   102,   102,   102,   102,   102,
     354,   638,   103,   367,   465,   102,   593,   370,   102,   369,
     372,   369,   372,   113,   130,   135,   136,   236,   372,   698,
      38,   173,   178,   188,   720,   721,    96,   725,   189,   723,
     194,   726,   192,   193,   724,   190,   191,   722,   130,   220,
     224,   225,   226,   733,   215,   216,   217,   218,   731,   219,
     220,   221,   222,   223,   732,   732,   224,   227,   227,   228,
     229,   228,   113,   130,   162,   730,   384,   382,   102,   102,
     111,   112,   111,   112,   367,   367,   102,   102,   334,   664,
     102,   159,   349,   669,   673,   354,   354,   354,   102,   441,
     368,   517,   446,   377,   442,   102,   379,   447,   385,   551,
       5,     5,   551,   586,    89,    92,   484,   615,   616,   461,
     461,   102,   601,   610,   611,   551,   551,   551,   367,   102,
     551,    52,   551,   377,   102,   519,   521,   522,   379,   103,
     288,   514,    22,   381,    84,   326,    43,   551,   365,     5,
     365,   270,   285,   301,   618,   619,    89,    92,   484,   617,
     620,   365,   609,   420,   369,   148,   143,   148,   510,   511,
     103,   113,   526,   588,   113,   526,   380,   113,   526,   551,
       5,   551,   551,   357,   539,   539,   540,   541,   542,   102,
     544,   539,   546,   586,   607,   551,   551,    84,     8,    84,
     585,   652,   682,   682,   551,   562,   551,   561,   572,   573,
     610,   365,   497,   498,   357,   648,   642,   648,   653,   653,
     644,   645,   646,   648,   102,   642,   648,   604,   648,    20,
      20,   102,    39,   364,   355,   364,   388,   484,   535,    37,
      47,    52,    54,    56,   162,   270,   285,   301,   306,   308,
     355,   364,   388,   416,   484,    93,   113,   162,   355,   364,
     388,   450,   456,   457,   484,   486,    40,    88,    89,    90,
      91,    93,    96,   113,   162,   270,   355,   364,   388,   431,
     484,   489,   490,    40,    89,    91,   113,   162,   355,   364,
     388,   431,   484,   489,    41,    44,   162,   285,   355,   364,
     388,   417,   419,   424,   430,   434,   354,   354,   354,   368,
     377,   379,   385,   434,   367,   367,     7,   386,   372,     7,
     383,   361,   361,   372,   372,   373,   373,   664,   337,   664,
     102,   371,   375,   111,   112,   670,   444,   445,   443,   288,
     355,   364,   388,   484,   624,   519,   521,   355,   364,   388,
     484,   639,   355,   364,   388,   484,   626,   514,   355,   364,
     388,   484,   628,   551,   551,     5,   103,   462,   462,   616,
     354,   491,   615,   367,   367,   367,   551,   367,    20,   103,
     288,   303,   518,   303,   520,    20,   307,   515,   568,   584,
     588,   570,   569,   551,    43,    81,    82,   622,   649,   655,
     189,   287,   368,   302,   619,   462,   462,   620,   355,   364,
     486,   372,     7,   380,   526,   526,    70,   526,   551,     5,
     551,   164,   551,   561,   561,     5,   355,   489,   491,   612,
       7,   355,   642,   642,   102,    39,   460,   478,   460,   469,
     460,   472,   472,   460,   475,   103,    89,   277,   279,   478,
     478,   478,   478,   364,    78,    79,   458,   459,   584,   103,
      98,   364,   364,   364,   364,   364,   422,   589,   462,   462,
     353,    94,    95,   432,   102,   103,   128,   129,   247,   267,
     268,   438,   439,   449,    85,    86,    87,    89,   426,   427,
     364,   364,   364,   490,   422,   462,   353,   439,   426,   364,
     364,   364,   103,   353,    98,   368,   355,   355,   355,   355,
     355,   444,   445,   443,   355,   102,   102,   378,   102,   371,
     375,    93,   133,   271,   355,   364,   388,   484,   636,    89,
      96,   133,   167,   271,   355,   364,   388,   484,   637,   113,
     271,   355,   364,   388,   484,   633,   102,   368,   518,   520,
     377,   379,   515,   385,   551,   610,   355,   367,   310,   311,
     312,   313,   314,   523,   102,   377,   102,   522,   377,   523,
     102,   379,   381,   381,   551,   365,   102,   304,   102,   517,
     364,   511,   551,    84,   573,     5,   355,   355,     5,   365,
     498,   188,   537,   102,   440,   418,   423,   428,   433,   478,
     478,   478,   440,   440,   440,   440,    41,     8,   364,   364,
     364,   425,     8,   364,     7,   364,     5,   364,   425,     5,
     364,   150,   451,   354,   435,   584,   364,   355,   355,   355,
       7,   664,   353,   165,   170,   632,   464,   367,   462,   102,
     632,   102,   464,   367,   104,   464,   367,   491,   287,   103,
     514,   367,   102,   288,   519,   521,   551,   355,   573,   655,
     185,   538,   364,   354,   354,   354,   354,   354,   440,   440,
     440,   354,   354,   354,   354,   103,   589,   438,   427,    86,
     421,   422,   589,    37,    86,   285,   301,   306,   308,   429,
     439,    22,   102,   103,   352,   452,   453,   454,   584,   364,
     103,   104,   436,   437,   584,   364,   367,   367,   367,   102,
     371,   354,   380,   364,   364,   364,   364,   364,   364,   364,
     133,   364,   355,   367,   102,   518,   520,   355,   365,   537,
     448,   419,   424,   430,   434,   354,   354,   354,   441,   446,
     442,   447,    43,    44,   455,   422,   364,     8,   439,   368,
     377,   379,   385,   364,   364,   102,    22,    25,     7,   355,
     103,   634,   635,   632,   368,   377,   377,   538,   355,   355,
     355,   355,   355,   444,   445,   443,   355,   355,   355,   355,
     461,   584,   353,   451,   364,   589,   364,   102,   102,   365,
     437,     5,     7,   355,   364,   364,   364,   364,   364,   364,
     355,   355,   355,   364,   364,   364,   364,   435,   102,   635,
     364,   367,   367,   367,   368,   377,   379,   385,   364,   364,
     364
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_int16 yyr1[] =
{
       0,   362,   363,   363,   364,   364,   365,   365,   366,   367,
     368,   369,   370,   371,   372,   373,   374,   375,   376,   377,
     378,   379,   380,   381,   382,   383,   384,   385,   386,   387,
     388,   388,   388,   388,   388,   389,   389,   389,   389,   390,
     390,   390,   390,   390,   390,   390,   390,   390,   390,   390,
     390,   390,   390,   390,   391,   391,   391,   391,   391,   391,
     391,   391,   391,   391,   391,   391,   391,   391,   391,   391,
     391,   391,   391,   391,   391,   391,   391,   391,   392,   393,
     393,   393,   393,   393,   393,   393,   393,   393,   393,   393,
     393,   393,   393,   393,   393,   393,   394,   395,   395,   396,
     396,   397,   397,   398,   398,   399,   399,   399,   399,   399,
     399,   399,   399,   399,   399,   399,   399,   399,   399,   399,
     400,   401,   401,   401,   401,   401,   401,   401,   401,   401,
     401,   401,   401,   401,   401,   401,   401,   401,   401,   401,
     401,   401,   401,   401,   401,   401,   401,   401,   401,   401,
     401,   401,   401,   401,   401,   402,   403,   403,   404,   404,
     404,   404,   404,   404,   405,   405,   405,   405,   405,   405,
     405,   406,   407,   407,   408,   408,   409,   410,   410,   411,
     411,   411,   411,   411,   411,   411,   411,   412,   412,   413,
     413,   413,   414,   415,   416,   416,   417,   417,   417,   417,
     417,   417,   417,   417,   417,   417,   417,   417,   417,   417,
     417,   417,   418,   419,   419,   419,   419,   419,   419,   419,
     419,   420,   420,   420,   421,   421,   422,   422,   423,   424,
     424,   424,   424,   424,   424,   424,   424,   424,   424,   424,
     424,   424,   425,   425,   426,   426,   427,   427,   427,   427,
     428,   429,   429,   429,   429,   429,   430,   430,   430,   430,
     430,   430,   430,   430,   430,   430,   430,   430,   430,   430,
     431,   431,   432,   432,   433,   434,   434,   434,   434,   434,
     434,   434,   435,   435,   436,   436,   436,   437,   437,   437,
     438,   438,   439,   439,   440,   441,   441,   441,   441,   441,
     442,   442,   442,   442,   442,   443,   443,   443,   443,   443,
     444,   444,   444,   444,   444,   445,   445,   445,   445,   445,
     446,   446,   446,   446,   446,   447,   447,   447,   447,   447,
     448,   448,   448,   448,   448,   449,   449,   449,   449,   449,
     450,   451,   452,   452,   453,   453,   453,   453,   453,   454,
     454,   455,   455,   455,   455,   456,   457,   458,   458,   459,
     459,   460,   461,   461,   461,   462,   463,   463,   464,   464,
     464,   464,   464,   464,   465,   466,   467,   468,   469,   470,
     471,   472,   473,   474,   475,   476,   477,   478,   479,   480,
     481,   482,   482,   482,   482,   483,   484,   485,   485,   486,
     486,   487,   488,   488,   489,   489,   490,   490,   490,   490,
     491,   491,   491,   491,   491,   491,   491,   491,   491,   491,
     491,   491,   491,   491,   491,   491,   491,   491,   491,   491,
     492,   492,   493,   494,   494,   495,   496,   496,   497,   497,
     497,   498,   499,   499,   500,   500,   501,   501,   502,   502,
     503,   503,   504,   504,   505,   506,   506,   507,   507,   507,
     507,   507,   507,   508,   509,   509,   509,   509,   509,   510,
     510,   511,   511,   512,   512,   512,   513,   513,   513,   514,
     514,   515,   515,   516,   516,   517,   517,   517,   518,   518,
     519,   520,   520,   521,   521,   522,   522,   523,   523,   523,
     523,   523,   524,   525,   526,   526,   527,   527,   527,   527,
     527,   527,   527,   527,   528,   529,   529,   530,   530,   530,
     530,   530,   530,   531,   531,   532,   532,   533,   533,   534,
     534,   534,   534,   535,   535,   536,   537,   537,   538,   538,
     539,   539,   539,   539,   539,   539,   539,   539,   539,   539,
     539,   539,   539,   540,   540,   540,   541,   541,   542,   542,
     543,   543,   544,   545,   545,   546,   546,   547,   547,   548,
     549,   550,   550,   551,   551,   551,   552,   552,   552,   552,
     552,   552,   552,   552,   552,   552,   552,   552,   552,   552,
     553,   553,   554,   555,   555,   555,   556,   556,   557,   558,
     558,   558,   558,   558,   559,   559,   560,   560,   561,   561,
     562,   562,   562,   563,   563,   563,   563,   564,   564,   565,
     566,   566,   567,   567,   568,   568,   569,   569,   569,   570,
     570,   570,   570,   571,   571,   572,   572,   573,   573,   574,
     575,   575,   575,   576,   576,   576,   577,   577,   578,   578,
     579,   580,   580,   581,   582,   582,   583,   584,   585,   585,
     586,   586,   587,   588,   589,   589,   589,   589,   589,   589,
     589,   589,   589,   589,   589,   589,   589,   589,   589,   590,
     591,   591,   591,   592,   592,   592,   592,   592,   593,   593,
     594,   594,   595,   595,   596,   596,   596,   597,   597,   598,
     598,   599,   599,   600,   601,   601,   602,   603,   604,   604,
     605,   606,   606,   606,   607,   608,   608,   608,   609,   609,
     609,   610,   610,   611,   612,   612,   613,   613,   614,   614,
     615,   615,   616,   616,   616,   617,   617,   618,   618,   619,
     619,   619,   619,   619,   619,   620,   620,   620,   621,   622,
     622,   623,   623,   623,   623,   624,   625,   626,   627,   628,
     629,   630,   630,   630,   631,   631,   631,   632,   632,   633,
     633,   634,   634,   635,   636,   636,   636,   637,   637,   637,
     637,   637,   638,   639,   639,   640,   641,   641,   641,   641,
     641,   641,   641,   641,   642,   642,   643,   643,   643,   644,
     644,   644,   645,   645,   646,   646,   647,   647,   648,   649,
     649,   649,   649,   650,   650,   651,   652,   652,   652,   652,
     652,   652,   652,   652,   652,   652,   652,   652,   653,   653,
     653,   653,   653,   653,   653,   653,   653,   653,   653,   653,
     653,   653,   653,   653,   653,   654,   654,   654,   654,   654,
     654,   654,   655,   655,   655,   655,   655,   655,   656,   656,
     657,   657,   657,   658,   658,   659,   659,   659,   659,   659,
     660,   660,   660,   660,   660,   660,   660,   660,   660,   660,
     660,   660,   660,   660,   660,   660,   660,   660,   660,   660,
     660,   660,   660,   660,   661,   661,   661,   661,   661,   661,
     662,   662,   663,   663,   663,   664,   664,   665,   665,   666,
     667,   667,   668,   668,   669,   669,   670,   670,   671,   671,
     672,   672,   672,   673,   673,   674,   674,   675,   675,   675,
     675,   676,   676,   676,   677,   677,   678,   678,   678,   678,
     678,   678,   678,   678,   678,   678,   678,   678,   678,   678,
     678,   678,   678,   679,   679,   679,   679,   679,   679,   679,
     680,   680,   680,   680,   681,   681,   681,   681,   682,   682,
     683,   683,   684,   684,   684,   684,   685,   686,   686,   686,
     686,   686,   686,   686,   686,   686,   686,   686,   686,   686,
     686,   686,   686,   686,   686,   687,   688,   688,   688,   688,
     689,   690,   690,   690,   691,   692,   692,   692,   692,   692,
     693,   694,   694,   694,   694,   694,   694,   694,   694,   694,
     695,   695,   695,   696,   696,   696,   696,   696,   696,   696,
     696,   696,   696,   696,   696,   697,   697,   697,   697,   698,
     698,   698,   698,   698,   699,   700,   700,   700,   700,   700,
     700,   700,   701,   702,   702,   702,   702,   703,   704,   704,
     704,   704,   704,   704,   704,   704,   704,   705,   706,   706,
     706,   706,   706,   706,   706,   706,   707,   708,   708,   708,
     708,   708,   709,   710,   710,   711,   712,   712,   712,   713,
     714,   714,   714,   714,   715,   716,   716,   716,   716,   717,
     717,   717,   717,   718,   718,   718,   718,   718,   718,   718,
     718,   718,   718,   719,   719,   719,   719,   719,   719,   720,
     720,   720,   720,   720,   721,   721,   721,   721,   721,   721,
     721,   721,   721,   721,   721,   721,   722,   722,   723,   724,
     724,   725,   726,   727,   728,   728,   728,   729,   729,   729,
     729,   729,   729,   729,   729,   729,   729,   729,   729,   729,
     729,   729,   729,   729,   729,   730,   730,   730,   731,   731,
     731,   731,   732,   732,   732,   732,   732,   733,   733,   733,
     733,   734,   734,   734,   734,   734,   734,   734,   734,   734,
     734,   734,   734,   735,   735,   736,   736,   736,   736,   737,
     738,   738,   739,   739,   739,   739,   739,   739,   739,   739,
     740,   741,   741,   742,   743,   743,   743,   743,   744,   745,
     746,   747,   748,   749,   749,   749,   749,   750,   751,   751,
     751,   751,   751,   751,   752,   753,   753,   754,   755,   755,
     755,   755,   755,   756,   757,   757,   757,   757,   757
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     0,     2,     1,     1,     1,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       3,     5,     5,     3,     2,     1,     1,     2,     2,     1,
       2,     2,     2,     2,     2,     2,     3,     2,     2,     2,
       2,     2,     2,     2,     2,     6,     2,     6,     3,     2,
       6,     6,     3,     6,     3,     5,     7,     5,     7,     8,
       8,     8,     5,     7,     5,     7,     4,     6,     3,     2,
       6,     2,     6,     6,     6,     3,     6,     3,     5,     5,
       8,     8,     8,     5,     5,     4,     3,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     2,     2,     2,     2,
       3,     2,     2,     6,     3,     3,     5,     3,     3,     2,
       3,     2,     2,     2,     2,     2,     3,     2,     2,     3,
       3,     2,     3,     3,     2,     3,     3,     2,     3,     3,
       2,     3,     2,     2,     3,     3,     2,     2,     2,     2,
       2,     2,     4,     5,     2,     2,     1,     2,     2,     3,
       3,     2,     3,     3,     2,     2,     2,     2,     3,     2,
       2,     3,     2,     1,     2,     1,     3,     0,     1,     0,
       1,     1,     1,     1,     1,     1,     1,     0,     1,     1,
       1,     2,     1,     0,     2,     1,     0,     2,     2,     3,
       8,     8,     8,     8,     9,     9,    10,    10,    10,     9,
       9,     8,     0,     0,     2,     2,     3,     3,     3,     3,
       3,     0,     2,     3,     1,     3,     1,     3,     0,     0,
       2,     2,     4,     4,     4,     4,     4,     3,     4,     2,
       3,     3,     1,     1,     3,     1,     1,     1,     1,     1,
       0,     2,     2,     2,     2,     1,     0,     2,     2,     4,
       6,     7,     6,     7,     6,     4,     3,     4,     3,     3,
       2,     2,     1,     1,     0,     0,     2,     2,     5,     5,
       3,     4,     3,     1,     1,     3,     3,     1,     1,     1,
       1,     1,     1,     3,     0,     0,     2,     2,     2,     2,
       0,     2,     2,     2,     2,     0,     2,     2,     2,     2,
       0,     2,     2,     2,     2,     0,     2,     2,     2,     2,
       0,     2,     2,     2,     2,     0,     2,     2,     2,     2,
       0,     2,     2,     2,     2,     1,     1,     1,     1,     1,
       6,     2,     1,     1,     1,     1,     1,     3,     3,     1,
       2,     2,     2,     3,     0,     2,     2,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     0,     1,     2,     2,
       1,     2,     1,     1,     2,     3,     2,     3,     1,     2,
       3,     1,     2,     3,     1,     2,     3,     1,     2,     2,
       2,     1,     2,     2,     2,     2,     2,     0,     1,     1,
       2,     1,     1,     2,     1,     2,     2,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     2,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     5,     1,     1,     3,     3,     1,     1,     3,
       3,     5,     4,     5,     1,     2,     1,     3,     1,     2,
       2,     2,     1,     2,     1,     1,     2,     2,     2,     2,
       2,     2,     2,     1,     3,     3,     1,     2,     1,     3,
       1,     1,     1,     6,     6,     4,     1,     1,     0,     1,
       1,     0,     3,     6,     4,     1,     1,     0,     0,     3,
       3,     0,     2,     2,     3,     2,     2,     1,     1,     1,
       1,     1,     2,     1,     1,     1,     0,     4,     3,     4,
       3,     4,     3,     4,     2,     1,     1,     3,     4,     4,
       5,     6,     5,     1,     2,     1,     3,     1,     2,     2,
       2,     1,     1,     6,     8,     0,     0,     1,     0,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     3,     1,     3,     3,     1,     3,     1,     3,
       1,     3,     1,     1,     3,     1,     1,     3,     1,     3,
       3,     1,     1,     1,     1,     1,     1,     2,     3,     3,
       4,     5,     2,     3,     2,     6,     4,     3,     4,     3,
       2,     1,     1,     3,     4,     1,     2,     1,     1,     2,
       3,     1,     3,     4,     3,     5,     3,     6,     1,     3,
       1,     1,     1,     2,     4,     6,     6,     1,     2,     1,
       1,     2,     2,     1,     1,     1,     1,     1,     3,     1,
       1,     1,     1,     1,     3,     1,     1,     1,     2,     1,
       4,     5,     6,     1,     1,     1,     7,     8,     6,     1,
       1,     1,     2,     2,     6,     8,     1,     2,     1,     1,
       1,     1,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     3,     4,
       1,     1,     1,     1,     1,     1,     1,     1,     3,     1,
       3,     3,     0,     2,     1,     3,     3,     1,     3,     1,
       3,     1,     3,     1,     1,     3,     3,     3,     1,     1,
       3,     1,     1,     1,     3,     1,     3,     3,     3,     3,
       5,     1,     2,     1,     1,     2,     1,     1,     2,     1,
       1,     2,     2,     2,     1,     1,     2,     1,     2,     2,
       6,     6,     6,     4,     5,     2,     2,     1,     1,     1,
       1,     1,     1,     2,     2,     4,     0,     4,     0,     1,
       0,     1,     1,     1,     1,     1,     1,     2,     1,     5,
       3,     1,     3,     3,     3,     6,     3,     3,     3,     3,
       3,     3,     0,     4,     4,     0,     2,     2,     4,     4,
       5,     5,     3,     3,     3,     3,     1,     1,     1,     1,
       3,     3,     1,     3,     1,     3,     1,     3,     1,     1,
       1,     3,     3,     1,     1,     1,     2,     2,     2,     2,
       2,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     2,     1,     3,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     2,     1,     1,     1,
       2,     1,     2,     1,     1,     1,     1,     1,     1,     2,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       2,     1,     1,     1,     4,     3,     4,     1,     4,     4,
       3,     5,     1,     1,     1,     0,     2,     1,     1,     6,
       2,     0,     1,     1,     1,     1,     1,     1,     5,     6,
       8,     6,     5,     2,     2,     3,     4,     1,     1,     1,
       2,     3,     4,     4,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       2,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       3,     3,     3,     3,     1,     1,     1,     1,     1,     1,
       3,     3,     5,     5,     5,     6,     3,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     2,     1,     1,     1,     6,     1,     1,     1,     1,
       3,     1,     1,     1,     3,     1,     1,     1,     1,     1,
       3,     1,     1,     1,     1,     1,     3,     3,     3,     3,
       3,     5,     4,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     2,     1,     1,     1,     1,     1,
       1,     1,     2,     1,     1,     1,     1,     3,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     2,     1,     1,
       1,     1,     1,     1,     1,     1,     2,     1,     1,     1,
       1,     1,     2,     1,     1,     2,     1,     1,     1,     2,
       1,     1,     1,     1,     2,     1,     1,     1,     1,     2,
       3,     3,     8,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     2,     2,     2,     2,     2,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     3,     5,     1,     1,     1,     1,     2,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       2,     1,     1,     3,     1,     1,     1,     1,     2,     4,
       2,     1,     2,     1,     1,     1,     4,     2,     1,     1,
       1,     1,     1,     1,     2,     1,     1,     2,     1,     1,
       1,     1,     1,     2,     1,     2,     1,     1,     1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (&yylloc, nft, scanner, state, YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF

/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)                                \
    do                                                                  \
      if (N)                                                            \
        {                                                               \
          (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;        \
          (Current).first_column = YYRHSLOC (Rhs, 1).first_column;      \
          (Current).last_line    = YYRHSLOC (Rhs, N).last_line;         \
          (Current).last_column  = YYRHSLOC (Rhs, N).last_column;       \
        }                                                               \
      else                                                              \
        {                                                               \
          (Current).first_line   = (Current).last_line   =              \
            YYRHSLOC (Rhs, 0).last_line;                                \
          (Current).first_column = (Current).last_column =              \
            YYRHSLOC (Rhs, 0).last_column;                              \
        }                                                               \
    while (0)
#endif

#define YYRHSLOC(Rhs, K) ((Rhs)[K])


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

# ifndef YY_LOCATION_PRINT
#  if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL

/* Print *YYLOCP on YYO.  Private, do not rely on its existence. */

YY_ATTRIBUTE_UNUSED
static int
yy_location_print_ (FILE *yyo, YYLTYPE const * const yylocp)
{
  int res = 0;
  int end_col = 0 != yylocp->last_column ? yylocp->last_column - 1 : 0;
  if (0 <= yylocp->first_line)
    {
      res += YYFPRINTF (yyo, "%d", yylocp->first_line);
      if (0 <= yylocp->first_column)
        res += YYFPRINTF (yyo, ".%d", yylocp->first_column);
    }
  if (0 <= yylocp->last_line)
    {
      if (yylocp->first_line < yylocp->last_line)
        {
          res += YYFPRINTF (yyo, "-%d", yylocp->last_line);
          if (0 <= end_col)
            res += YYFPRINTF (yyo, ".%d", end_col);
        }
      else if (0 <= end_col && yylocp->first_column < end_col)
        res += YYFPRINTF (yyo, "-%d", end_col);
    }
  return res;
 }

#   define YY_LOCATION_PRINT(File, Loc)          \
  yy_location_print_ (File, &(Loc))

#  else
#   define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#  endif
# endif /* !defined YY_LOCATION_PRINT */


# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value, Location, nft, scanner, state); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, struct nft_ctx *nft, void *scanner, struct parser_state *state)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  YY_USE (yylocationp);
  YY_USE (nft);
  YY_USE (scanner);
  YY_USE (state);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yykind < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yykind], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, struct nft_ctx *nft, void *scanner, struct parser_state *state)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  YY_LOCATION_PRINT (yyo, *yylocationp);
  YYFPRINTF (yyo, ": ");
  yy_symbol_value_print (yyo, yykind, yyvaluep, yylocationp, nft, scanner, state);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp, YYLTYPE *yylsp,
                 int yyrule, struct nft_ctx *nft, void *scanner, struct parser_state *state)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)],
                       &(yylsp[(yyi + 1) - (yynrhs)]), nft, scanner, state);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, yylsp, Rule, nft, scanner, state); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


/* Context of a parse error.  */
typedef struct
{
  yy_state_t *yyssp;
  yysymbol_kind_t yytoken;
  YYLTYPE *yylloc;
} yypcontext_t;

/* Put in YYARG at most YYARGN of the expected tokens given the
   current YYCTX, and return the number of tokens stored in YYARG.  If
   YYARG is null, return the number of expected tokens (guaranteed to
   be less than YYNTOKENS).  Return YYENOMEM on memory exhaustion.
   Return 0 if there are more than YYARGN expected tokens, yet fill
   YYARG up to YYARGN. */
static int
yypcontext_expected_tokens (const yypcontext_t *yyctx,
                            yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  int yyn = yypact[+*yyctx->yyssp];
  if (!yypact_value_is_default (yyn))
    {
      /* Start YYX at -YYN if negative to avoid negative indexes in
         YYCHECK.  In other words, skip the first -YYN actions for
         this state because they are default actions.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;
      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yyx;
      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
        if (yycheck[yyx + yyn] == yyx && yyx != YYSYMBOL_YYerror
            && !yytable_value_is_error (yytable[yyx + yyn]))
          {
            if (!yyarg)
              ++yycount;
            else if (yycount == yyargn)
              return 0;
            else
              yyarg[yycount++] = YY_CAST (yysymbol_kind_t, yyx);
          }
    }
  if (yyarg && yycount == 0 && 0 < yyargn)
    yyarg[0] = YYSYMBOL_YYEMPTY;
  return yycount;
}




#ifndef yystrlen
# if defined __GLIBC__ && defined _STRING_H
#  define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
# else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
# endif
#endif

#ifndef yystpcpy
# if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#  define yystpcpy stpcpy
# else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
# endif
#endif

#ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;
      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
#endif


static int
yy_syntax_error_arguments (const yypcontext_t *yyctx,
                           yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yyctx->yytoken != YYSYMBOL_YYEMPTY)
    {
      int yyn;
      if (yyarg)
        yyarg[yycount] = yyctx->yytoken;
      ++yycount;
      yyn = yypcontext_expected_tokens (yyctx,
                                        yyarg ? yyarg + 1 : yyarg, yyargn - 1);
      if (yyn == YYENOMEM)
        return YYENOMEM;
      else
        yycount += yyn;
    }
  return yycount;
}

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return -1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return YYENOMEM if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                const yypcontext_t *yyctx)
{
  enum { YYARGS_MAX = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  yysymbol_kind_t yyarg[YYARGS_MAX];
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* Actual size of YYARG. */
  int yycount = yy_syntax_error_arguments (yyctx, yyarg, YYARGS_MAX);
  if (yycount == YYENOMEM)
    return YYENOMEM;

  switch (yycount)
    {
#define YYCASE_(N, S)                       \
      case N:                               \
        yyformat = S;                       \
        break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
#undef YYCASE_
    }

  /* Compute error message size.  Don't count the "%s"s, but reserve
     room for the terminator.  */
  yysize = yystrlen (yyformat) - 2 * yycount + 1;
  {
    int yyi;
    for (yyi = 0; yyi < yycount; ++yyi)
      {
        YYPTRDIFF_T yysize1
          = yysize + yytnamerr (YY_NULLPTR, yytname[yyarg[yyi]]);
        if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
          yysize = yysize1;
        else
          return YYENOMEM;
      }
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return -1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yytname[yyarg[yyi++]]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep, YYLTYPE *yylocationp, struct nft_ctx *nft, void *scanner, struct parser_state *state)
{
  YY_USE (yyvaluep);
  YY_USE (yylocationp);
  YY_USE (nft);
  YY_USE (scanner);
  YY_USE (state);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  switch (yykind)
    {
    case YYSYMBOL_STRING: /* "string"  */
#line 320 "parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5755 "parser_bison.c"
        break;

    case YYSYMBOL_QUOTED_STRING: /* "quoted string"  */
#line 320 "parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5761 "parser_bison.c"
        break;

    case YYSYMBOL_ASTERISK_STRING: /* "string with a trailing asterisk"  */
#line 320 "parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5767 "parser_bison.c"
        break;

    case YYSYMBOL_line: /* line  */
#line 630 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5773 "parser_bison.c"
        break;

    case YYSYMBOL_base_cmd: /* base_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5779 "parser_bison.c"
        break;

    case YYSYMBOL_add_cmd: /* add_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5785 "parser_bison.c"
        break;

    case YYSYMBOL_replace_cmd: /* replace_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5791 "parser_bison.c"
        break;

    case YYSYMBOL_create_cmd: /* create_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5797 "parser_bison.c"
        break;

    case YYSYMBOL_insert_cmd: /* insert_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5803 "parser_bison.c"
        break;

    case YYSYMBOL_table_or_id_spec: /* table_or_id_spec  */
#line 636 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5809 "parser_bison.c"
        break;

    case YYSYMBOL_chain_or_id_spec: /* chain_or_id_spec  */
#line 638 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5815 "parser_bison.c"
        break;

    case YYSYMBOL_set_or_id_spec: /* set_or_id_spec  */
#line 643 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5821 "parser_bison.c"
        break;

    case YYSYMBOL_obj_or_id_spec: /* obj_or_id_spec  */
#line 645 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5827 "parser_bison.c"
        break;

    case YYSYMBOL_delete_cmd: /* delete_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5833 "parser_bison.c"
        break;

    case YYSYMBOL_get_cmd: /* get_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5839 "parser_bison.c"
        break;

    case YYSYMBOL_list_cmd: /* list_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5845 "parser_bison.c"
        break;

    case YYSYMBOL_basehook_device_name: /* basehook_device_name  */
#line 657 "parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5851 "parser_bison.c"
        break;

    case YYSYMBOL_basehook_spec: /* basehook_spec  */
#line 651 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5857 "parser_bison.c"
        break;

    case YYSYMBOL_reset_cmd: /* reset_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5863 "parser_bison.c"
        break;

    case YYSYMBOL_flush_cmd: /* flush_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5869 "parser_bison.c"
        break;

    case YYSYMBOL_rename_cmd: /* rename_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5875 "parser_bison.c"
        break;

    case YYSYMBOL_import_cmd: /* import_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5881 "parser_bison.c"
        break;

    case YYSYMBOL_export_cmd: /* export_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5887 "parser_bison.c"
        break;

    case YYSYMBOL_monitor_cmd: /* monitor_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5893 "parser_bison.c"
        break;

    case YYSYMBOL_monitor_event: /* monitor_event  */
#line 876 "parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5899 "parser_bison.c"
        break;

    case YYSYMBOL_describe_cmd: /* describe_cmd  */
#line 633 "parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5905 "parser_bison.c"
        break;

    case YYSYMBOL_table_block_alloc: /* table_block_alloc  */
#line 663 "parser_bison.y"
            { close_scope(state); table_free(((*yyvaluep).table)); }
#line 5911 "parser_bison.c"
        break;

    case YYSYMBOL_chain_block_alloc: /* chain_block_alloc  */
#line 665 "parser_bison.y"
            { close_scope(state); chain_free(((*yyvaluep).chain)); }
#line 5917 "parser_bison.c"
        break;

    case YYSYMBOL_typeof_data_expr: /* typeof_data_expr  */
#line 737 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5923 "parser_bison.c"
        break;

    case YYSYMBOL_typeof_expr: /* typeof_expr  */
#line 737 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5929 "parser_bison.c"
        break;

    case YYSYMBOL_set_block_alloc: /* set_block_alloc  */
#line 674 "parser_bison.y"
            { set_free(((*yyvaluep).set)); }
#line 5935 "parser_bison.c"
        break;

    case YYSYMBOL_set_block_expr: /* set_block_expr  */
#line 778 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5941 "parser_bison.c"
        break;

    case YYSYMBOL_map_block_alloc: /* map_block_alloc  */
#line 677 "parser_bison.y"
            { set_free(((*yyvaluep).set)); }
#line 5947 "parser_bison.c"
        break;

    case YYSYMBOL_flowtable_block_alloc: /* flowtable_block_alloc  */
#line 681 "parser_bison.y"
            { flowtable_free(((*yyvaluep).flowtable)); }
#line 5953 "parser_bison.c"
        break;

    case YYSYMBOL_flowtable_expr: /* flowtable_expr  */
#line 778 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5959 "parser_bison.c"
        break;

    case YYSYMBOL_flowtable_list_expr: /* flowtable_list_expr  */
#line 778 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5965 "parser_bison.c"
        break;

    case YYSYMBOL_flowtable_expr_member: /* flowtable_expr_member  */
#line 778 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5971 "parser_bison.c"
        break;

    case YYSYMBOL_data_type_atom_expr: /* data_type_atom_expr  */
#line 627 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5977 "parser_bison.c"
        break;

    case YYSYMBOL_data_type_expr: /* data_type_expr  */
#line 627 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5983 "parser_bison.c"
        break;

    case YYSYMBOL_obj_block_alloc: /* obj_block_alloc  */
#line 684 "parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 5989 "parser_bison.c"
        break;

    case YYSYMBOL_type_identifier: /* type_identifier  */
#line 622 "parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5995 "parser_bison.c"
        break;

    case YYSYMBOL_extended_prio_name: /* extended_prio_name  */
#line 657 "parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 6001 "parser_bison.c"
        break;

    case YYSYMBOL_dev_spec: /* dev_spec  */
#line 660 "parser_bison.y"
            { xfree(((*yyvaluep).expr)); }
#line 6007 "parser_bison.c"
        break;

    case YYSYMBOL_policy_expr: /* policy_expr  */
#line 735 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6013 "parser_bison.c"
        break;

    case YYSYMBOL_identifier: /* identifier  */
#line 622 "parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 6019 "parser_bison.c"
        break;

    case YYSYMBOL_string: /* string  */
#line 622 "parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 6025 "parser_bison.c"
        break;

    case YYSYMBOL_table_spec: /* table_spec  */
#line 636 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6031 "parser_bison.c"
        break;

    case YYSYMBOL_tableid_spec: /* tableid_spec  */
#line 636 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6037 "parser_bison.c"
        break;

    case YYSYMBOL_chain_spec: /* chain_spec  */
#line 638 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6043 "parser_bison.c"
        break;

    case YYSYMBOL_chainid_spec: /* chainid_spec  */
#line 638 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6049 "parser_bison.c"
        break;

    case YYSYMBOL_chain_identifier: /* chain_identifier  */
#line 641 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6055 "parser_bison.c"
        break;

    case YYSYMBOL_set_spec: /* set_spec  */
#line 643 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6061 "parser_bison.c"
        break;

    case YYSYMBOL_setid_spec: /* setid_spec  */
#line 643 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6067 "parser_bison.c"
        break;

    case YYSYMBOL_set_identifier: /* set_identifier  */
#line 648 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6073 "parser_bison.c"
        break;

    case YYSYMBOL_flowtable_spec: /* flowtable_spec  */
#line 641 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6079 "parser_bison.c"
        break;

    case YYSYMBOL_flowtableid_spec: /* flowtableid_spec  */
#line 648 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6085 "parser_bison.c"
        break;

    case YYSYMBOL_obj_spec: /* obj_spec  */
#line 645 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6091 "parser_bison.c"
        break;

    case YYSYMBOL_objid_spec: /* objid_spec  */
#line 645 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6097 "parser_bison.c"
        break;

    case YYSYMBOL_obj_identifier: /* obj_identifier  */
#line 648 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6103 "parser_bison.c"
        break;

    case YYSYMBOL_handle_spec: /* handle_spec  */
#line 641 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6109 "parser_bison.c"
        break;

    case YYSYMBOL_position_spec: /* position_spec  */
#line 641 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6115 "parser_bison.c"
        break;

    case YYSYMBOL_index_spec: /* index_spec  */
#line 641 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6121 "parser_bison.c"
        break;

    case YYSYMBOL_rule_position: /* rule_position  */
#line 641 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6127 "parser_bison.c"
        break;

    case YYSYMBOL_ruleid_spec: /* ruleid_spec  */
#line 641 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6133 "parser_bison.c"
        break;

    case YYSYMBOL_comment_spec: /* comment_spec  */
#line 622 "parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 6139 "parser_bison.c"
        break;

    case YYSYMBOL_ruleset_spec: /* ruleset_spec  */
#line 641 "parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 6145 "parser_bison.c"
        break;

    case YYSYMBOL_rule: /* rule  */
#line 667 "parser_bison.y"
            { rule_free(((*yyvaluep).rule)); }
#line 6151 "parser_bison.c"
        break;

    case YYSYMBOL_stmt_list: /* stmt_list  */
#line 687 "parser_bison.y"
            { stmt_list_free(((*yyvaluep).list)); xfree(((*yyvaluep).list)); }
#line 6157 "parser_bison.c"
        break;

    case YYSYMBOL_stateful_stmt_list: /* stateful_stmt_list  */
#line 687 "parser_bison.y"
            { stmt_list_free(((*yyvaluep).list)); xfree(((*yyvaluep).list)); }
#line 6163 "parser_bison.c"
        break;

    case YYSYMBOL_stateful_stmt: /* stateful_stmt  */
#line 691 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6169 "parser_bison.c"
        break;

    case YYSYMBOL_stmt: /* stmt  */
#line 689 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6175 "parser_bison.c"
        break;

    case YYSYMBOL_chain_stmt: /* chain_stmt  */
#line 714 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6181 "parser_bison.c"
        break;

    case YYSYMBOL_verdict_stmt: /* verdict_stmt  */
#line 689 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6187 "parser_bison.c"
        break;

    case YYSYMBOL_verdict_map_stmt: /* verdict_map_stmt  */
#line 772 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6193 "parser_bison.c"
        break;

    case YYSYMBOL_verdict_map_expr: /* verdict_map_expr  */
#line 775 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6199 "parser_bison.c"
        break;

    case YYSYMBOL_verdict_map_list_expr: /* verdict_map_list_expr  */
#line 775 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6205 "parser_bison.c"
        break;

    case YYSYMBOL_verdict_map_list_member_expr: /* verdict_map_list_member_expr  */
#line 775 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6211 "parser_bison.c"
        break;

    case YYSYMBOL_connlimit_stmt: /* connlimit_stmt  */
#line 702 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6217 "parser_bison.c"
        break;

    case YYSYMBOL_counter_stmt: /* counter_stmt  */
#line 691 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6223 "parser_bison.c"
        break;

    case YYSYMBOL_counter_stmt_alloc: /* counter_stmt_alloc  */
#line 691 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6229 "parser_bison.c"
        break;

    case YYSYMBOL_log_stmt: /* log_stmt  */
#line 699 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6235 "parser_bison.c"
        break;

    case YYSYMBOL_log_stmt_alloc: /* log_stmt_alloc  */
#line 699 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6241 "parser_bison.c"
        break;

    case YYSYMBOL_limit_stmt: /* limit_stmt  */
#line 702 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6247 "parser_bison.c"
        break;

    case YYSYMBOL_quota_unit: /* quota_unit  */
#line 657 "parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 6253 "parser_bison.c"
        break;

    case YYSYMBOL_quota_stmt: /* quota_stmt  */
#line 702 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6259 "parser_bison.c"
        break;

    case YYSYMBOL_reject_stmt: /* reject_stmt  */
#line 705 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6265 "parser_bison.c"
        break;

    case YYSYMBOL_reject_stmt_alloc: /* reject_stmt_alloc  */
#line 705 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6271 "parser_bison.c"
        break;

    case YYSYMBOL_reject_with_expr: /* reject_with_expr  */
#line 720 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6277 "parser_bison.c"
        break;

    case YYSYMBOL_nat_stmt: /* nat_stmt  */
#line 707 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6283 "parser_bison.c"
        break;

    case YYSYMBOL_nat_stmt_alloc: /* nat_stmt_alloc  */
#line 707 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6289 "parser_bison.c"
        break;

    case YYSYMBOL_tproxy_stmt: /* tproxy_stmt  */
#line 710 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6295 "parser_bison.c"
        break;

    case YYSYMBOL_synproxy_stmt: /* synproxy_stmt  */
#line 712 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6301 "parser_bison.c"
        break;

    case YYSYMBOL_synproxy_stmt_alloc: /* synproxy_stmt_alloc  */
#line 712 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6307 "parser_bison.c"
        break;

    case YYSYMBOL_synproxy_obj: /* synproxy_obj  */
#line 798 "parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 6313 "parser_bison.c"
        break;

    case YYSYMBOL_primary_stmt_expr: /* primary_stmt_expr  */
#line 759 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6319 "parser_bison.c"
        break;

    case YYSYMBOL_shift_stmt_expr: /* shift_stmt_expr  */
#line 761 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6325 "parser_bison.c"
        break;

    case YYSYMBOL_and_stmt_expr: /* and_stmt_expr  */
#line 763 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6331 "parser_bison.c"
        break;

    case YYSYMBOL_exclusive_or_stmt_expr: /* exclusive_or_stmt_expr  */
#line 763 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6337 "parser_bison.c"
        break;

    case YYSYMBOL_inclusive_or_stmt_expr: /* inclusive_or_stmt_expr  */
#line 763 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6343 "parser_bison.c"
        break;

    case YYSYMBOL_basic_stmt_expr: /* basic_stmt_expr  */
#line 759 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6349 "parser_bison.c"
        break;

    case YYSYMBOL_concat_stmt_expr: /* concat_stmt_expr  */
#line 751 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6355 "parser_bison.c"
        break;

    case YYSYMBOL_map_stmt_expr_set: /* map_stmt_expr_set  */
#line 751 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6361 "parser_bison.c"
        break;

    case YYSYMBOL_map_stmt_expr: /* map_stmt_expr  */
#line 751 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6367 "parser_bison.c"
        break;

    case YYSYMBOL_prefix_stmt_expr: /* prefix_stmt_expr  */
#line 756 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6373 "parser_bison.c"
        break;

    case YYSYMBOL_range_stmt_expr: /* range_stmt_expr  */
#line 756 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6379 "parser_bison.c"
        break;

    case YYSYMBOL_multiton_stmt_expr: /* multiton_stmt_expr  */
#line 754 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6385 "parser_bison.c"
        break;

    case YYSYMBOL_stmt_expr: /* stmt_expr  */
#line 751 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6391 "parser_bison.c"
        break;

    case YYSYMBOL_masq_stmt: /* masq_stmt  */
#line 707 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6397 "parser_bison.c"
        break;

    case YYSYMBOL_masq_stmt_alloc: /* masq_stmt_alloc  */
#line 707 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6403 "parser_bison.c"
        break;

    case YYSYMBOL_redir_stmt: /* redir_stmt  */
#line 707 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6409 "parser_bison.c"
        break;

    case YYSYMBOL_redir_stmt_alloc: /* redir_stmt_alloc  */
#line 707 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6415 "parser_bison.c"
        break;

    case YYSYMBOL_dup_stmt: /* dup_stmt  */
#line 723 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6421 "parser_bison.c"
        break;

    case YYSYMBOL_fwd_stmt: /* fwd_stmt  */
#line 725 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6427 "parser_bison.c"
        break;

    case YYSYMBOL_queue_stmt: /* queue_stmt  */
#line 718 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6433 "parser_bison.c"
        break;

    case YYSYMBOL_queue_stmt_compat: /* queue_stmt_compat  */
#line 718 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6439 "parser_bison.c"
        break;

    case YYSYMBOL_queue_stmt_alloc: /* queue_stmt_alloc  */
#line 718 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6445 "parser_bison.c"
        break;

    case YYSYMBOL_queue_expr: /* queue_expr  */
#line 720 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6451 "parser_bison.c"
        break;

    case YYSYMBOL_queue_stmt_expr_simple: /* queue_stmt_expr_simple  */
#line 720 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6457 "parser_bison.c"
        break;

    case YYSYMBOL_queue_stmt_expr: /* queue_stmt_expr  */
#line 720 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6463 "parser_bison.c"
        break;

    case YYSYMBOL_set_elem_expr_stmt: /* set_elem_expr_stmt  */
#line 782 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6469 "parser_bison.c"
        break;

    case YYSYMBOL_set_elem_expr_stmt_alloc: /* set_elem_expr_stmt_alloc  */
#line 782 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6475 "parser_bison.c"
        break;

    case YYSYMBOL_set_stmt: /* set_stmt  */
#line 727 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6481 "parser_bison.c"
        break;

    case YYSYMBOL_map_stmt: /* map_stmt  */
#line 730 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6487 "parser_bison.c"
        break;

    case YYSYMBOL_meter_stmt: /* meter_stmt  */
#line 732 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6493 "parser_bison.c"
        break;

    case YYSYMBOL_flow_stmt_legacy_alloc: /* flow_stmt_legacy_alloc  */
#line 732 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6499 "parser_bison.c"
        break;

    case YYSYMBOL_meter_stmt_alloc: /* meter_stmt_alloc  */
#line 732 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6505 "parser_bison.c"
        break;

    case YYSYMBOL_match_stmt: /* match_stmt  */
#line 689 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6511 "parser_bison.c"
        break;

    case YYSYMBOL_variable_expr: /* variable_expr  */
#line 735 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6517 "parser_bison.c"
        break;

    case YYSYMBOL_symbol_expr: /* symbol_expr  */
#line 735 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6523 "parser_bison.c"
        break;

    case YYSYMBOL_set_ref_expr: /* set_ref_expr  */
#line 743 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6529 "parser_bison.c"
        break;

    case YYSYMBOL_set_ref_symbol_expr: /* set_ref_symbol_expr  */
#line 743 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6535 "parser_bison.c"
        break;

    case YYSYMBOL_integer_expr: /* integer_expr  */
#line 735 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6541 "parser_bison.c"
        break;

    case YYSYMBOL_primary_expr: /* primary_expr  */
#line 737 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6547 "parser_bison.c"
        break;

    case YYSYMBOL_fib_expr: /* fib_expr  */
#line 867 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6553 "parser_bison.c"
        break;

    case YYSYMBOL_osf_expr: /* osf_expr  */
#line 872 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6559 "parser_bison.c"
        break;

    case YYSYMBOL_shift_expr: /* shift_expr  */
#line 737 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6565 "parser_bison.c"
        break;

    case YYSYMBOL_and_expr: /* and_expr  */
#line 737 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6571 "parser_bison.c"
        break;

    case YYSYMBOL_exclusive_or_expr: /* exclusive_or_expr  */
#line 739 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6577 "parser_bison.c"
        break;

    case YYSYMBOL_inclusive_or_expr: /* inclusive_or_expr  */
#line 739 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6583 "parser_bison.c"
        break;

    case YYSYMBOL_basic_expr: /* basic_expr  */
#line 741 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6589 "parser_bison.c"
        break;

    case YYSYMBOL_concat_expr: /* concat_expr  */
#line 766 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6595 "parser_bison.c"
        break;

    case YYSYMBOL_prefix_rhs_expr: /* prefix_rhs_expr  */
#line 748 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6601 "parser_bison.c"
        break;

    case YYSYMBOL_range_rhs_expr: /* range_rhs_expr  */
#line 748 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6607 "parser_bison.c"
        break;

    case YYSYMBOL_multiton_rhs_expr: /* multiton_rhs_expr  */
#line 746 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6613 "parser_bison.c"
        break;

    case YYSYMBOL_map_expr: /* map_expr  */
#line 769 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6619 "parser_bison.c"
        break;

    case YYSYMBOL_expr: /* expr  */
#line 788 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6625 "parser_bison.c"
        break;

    case YYSYMBOL_set_expr: /* set_expr  */
#line 778 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6631 "parser_bison.c"
        break;

    case YYSYMBOL_set_list_expr: /* set_list_expr  */
#line 778 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6637 "parser_bison.c"
        break;

    case YYSYMBOL_set_list_member_expr: /* set_list_member_expr  */
#line 778 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6643 "parser_bison.c"
        break;

    case YYSYMBOL_meter_key_expr: /* meter_key_expr  */
#line 785 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6649 "parser_bison.c"
        break;

    case YYSYMBOL_meter_key_expr_alloc: /* meter_key_expr_alloc  */
#line 785 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6655 "parser_bison.c"
        break;

    case YYSYMBOL_set_elem_expr: /* set_elem_expr  */
#line 780 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6661 "parser_bison.c"
        break;

    case YYSYMBOL_set_elem_key_expr: /* set_elem_key_expr  */
#line 907 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6667 "parser_bison.c"
        break;

    case YYSYMBOL_set_elem_expr_alloc: /* set_elem_expr_alloc  */
#line 780 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6673 "parser_bison.c"
        break;

    case YYSYMBOL_set_elem_stmt_list: /* set_elem_stmt_list  */
#line 687 "parser_bison.y"
            { stmt_list_free(((*yyvaluep).list)); xfree(((*yyvaluep).list)); }
#line 6679 "parser_bison.c"
        break;

    case YYSYMBOL_set_elem_stmt: /* set_elem_stmt  */
#line 689 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6685 "parser_bison.c"
        break;

    case YYSYMBOL_set_lhs_expr: /* set_lhs_expr  */
#line 780 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6691 "parser_bison.c"
        break;

    case YYSYMBOL_set_rhs_expr: /* set_rhs_expr  */
#line 780 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6697 "parser_bison.c"
        break;

    case YYSYMBOL_initializer_expr: /* initializer_expr  */
#line 788 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6703 "parser_bison.c"
        break;

    case YYSYMBOL_counter_obj: /* counter_obj  */
#line 798 "parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 6709 "parser_bison.c"
        break;

    case YYSYMBOL_quota_obj: /* quota_obj  */
#line 798 "parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 6715 "parser_bison.c"
        break;

    case YYSYMBOL_secmark_obj: /* secmark_obj  */
#line 798 "parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 6721 "parser_bison.c"
        break;

    case YYSYMBOL_timeout_states: /* timeout_states  */
#line 900 "parser_bison.y"
            { xfree(((*yyvaluep).list)); }
#line 6727 "parser_bison.c"
        break;

    case YYSYMBOL_timeout_state: /* timeout_state  */
#line 900 "parser_bison.y"
            { xfree(((*yyvaluep).list)); }
#line 6733 "parser_bison.c"
        break;

    case YYSYMBOL_ct_obj_alloc: /* ct_obj_alloc  */
#line 798 "parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 6739 "parser_bison.c"
        break;

    case YYSYMBOL_limit_obj: /* limit_obj  */
#line 798 "parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 6745 "parser_bison.c"
        break;

    case YYSYMBOL_relational_expr: /* relational_expr  */
#line 801 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6751 "parser_bison.c"
        break;

    case YYSYMBOL_list_rhs_expr: /* list_rhs_expr  */
#line 793 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6757 "parser_bison.c"
        break;

    case YYSYMBOL_rhs_expr: /* rhs_expr  */
#line 791 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6763 "parser_bison.c"
        break;

    case YYSYMBOL_shift_rhs_expr: /* shift_rhs_expr  */
#line 793 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6769 "parser_bison.c"
        break;

    case YYSYMBOL_and_rhs_expr: /* and_rhs_expr  */
#line 795 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6775 "parser_bison.c"
        break;

    case YYSYMBOL_exclusive_or_rhs_expr: /* exclusive_or_rhs_expr  */
#line 795 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6781 "parser_bison.c"
        break;

    case YYSYMBOL_inclusive_or_rhs_expr: /* inclusive_or_rhs_expr  */
#line 795 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6787 "parser_bison.c"
        break;

    case YYSYMBOL_basic_rhs_expr: /* basic_rhs_expr  */
#line 791 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6793 "parser_bison.c"
        break;

    case YYSYMBOL_concat_rhs_expr: /* concat_rhs_expr  */
#line 791 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6799 "parser_bison.c"
        break;

    case YYSYMBOL_boolean_expr: /* boolean_expr  */
#line 890 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6805 "parser_bison.c"
        break;

    case YYSYMBOL_keyword_expr: /* keyword_expr  */
#line 788 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6811 "parser_bison.c"
        break;

    case YYSYMBOL_primary_rhs_expr: /* primary_rhs_expr  */
#line 793 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6817 "parser_bison.c"
        break;

    case YYSYMBOL_verdict_expr: /* verdict_expr  */
#line 735 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6823 "parser_bison.c"
        break;

    case YYSYMBOL_chain_expr: /* chain_expr  */
#line 735 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6829 "parser_bison.c"
        break;

    case YYSYMBOL_meta_expr: /* meta_expr  */
#line 849 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6835 "parser_bison.c"
        break;

    case YYSYMBOL_meta_stmt: /* meta_stmt  */
#line 697 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6841 "parser_bison.c"
        break;

    case YYSYMBOL_socket_expr: /* socket_expr  */
#line 853 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6847 "parser_bison.c"
        break;

    case YYSYMBOL_numgen_expr: /* numgen_expr  */
#line 814 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6853 "parser_bison.c"
        break;

    case YYSYMBOL_xfrm_expr: /* xfrm_expr  */
#line 904 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6859 "parser_bison.c"
        break;

    case YYSYMBOL_hash_expr: /* hash_expr  */
#line 814 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6865 "parser_bison.c"
        break;

    case YYSYMBOL_rt_expr: /* rt_expr  */
#line 859 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6871 "parser_bison.c"
        break;

    case YYSYMBOL_ct_expr: /* ct_expr  */
#line 863 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6877 "parser_bison.c"
        break;

    case YYSYMBOL_symbol_stmt_expr: /* symbol_stmt_expr  */
#line 793 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6883 "parser_bison.c"
        break;

    case YYSYMBOL_list_stmt_expr: /* list_stmt_expr  */
#line 761 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6889 "parser_bison.c"
        break;

    case YYSYMBOL_ct_stmt: /* ct_stmt  */
#line 695 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6895 "parser_bison.c"
        break;

    case YYSYMBOL_payload_stmt: /* payload_stmt  */
#line 693 "parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6901 "parser_bison.c"
        break;

    case YYSYMBOL_payload_expr: /* payload_expr  */
#line 805 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6907 "parser_bison.c"
        break;

    case YYSYMBOL_payload_raw_expr: /* payload_raw_expr  */
#line 805 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6913 "parser_bison.c"
        break;

    case YYSYMBOL_eth_hdr_expr: /* eth_hdr_expr  */
#line 808 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6919 "parser_bison.c"
        break;

    case YYSYMBOL_vlan_hdr_expr: /* vlan_hdr_expr  */
#line 808 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6925 "parser_bison.c"
        break;

    case YYSYMBOL_arp_hdr_expr: /* arp_hdr_expr  */
#line 811 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6931 "parser_bison.c"
        break;

    case YYSYMBOL_ip_hdr_expr: /* ip_hdr_expr  */
#line 814 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6937 "parser_bison.c"
        break;

    case YYSYMBOL_icmp_hdr_expr: /* icmp_hdr_expr  */
#line 814 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6943 "parser_bison.c"
        break;

    case YYSYMBOL_igmp_hdr_expr: /* igmp_hdr_expr  */
#line 814 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6949 "parser_bison.c"
        break;

    case YYSYMBOL_ip6_hdr_expr: /* ip6_hdr_expr  */
#line 818 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6955 "parser_bison.c"
        break;

    case YYSYMBOL_icmp6_hdr_expr: /* icmp6_hdr_expr  */
#line 818 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6961 "parser_bison.c"
        break;

    case YYSYMBOL_auth_hdr_expr: /* auth_hdr_expr  */
#line 821 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6967 "parser_bison.c"
        break;

    case YYSYMBOL_esp_hdr_expr: /* esp_hdr_expr  */
#line 821 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6973 "parser_bison.c"
        break;

    case YYSYMBOL_comp_hdr_expr: /* comp_hdr_expr  */
#line 821 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6979 "parser_bison.c"
        break;

    case YYSYMBOL_udp_hdr_expr: /* udp_hdr_expr  */
#line 824 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6985 "parser_bison.c"
        break;

    case YYSYMBOL_udplite_hdr_expr: /* udplite_hdr_expr  */
#line 824 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6991 "parser_bison.c"
        break;

    case YYSYMBOL_tcp_hdr_expr: /* tcp_hdr_expr  */
#line 882 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6997 "parser_bison.c"
        break;

    case YYSYMBOL_dccp_hdr_expr: /* dccp_hdr_expr  */
#line 827 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7003 "parser_bison.c"
        break;

    case YYSYMBOL_sctp_chunk_alloc: /* sctp_chunk_alloc  */
#line 827 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7009 "parser_bison.c"
        break;

    case YYSYMBOL_sctp_hdr_expr: /* sctp_hdr_expr  */
#line 827 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7015 "parser_bison.c"
        break;

    case YYSYMBOL_th_hdr_expr: /* th_hdr_expr  */
#line 833 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7021 "parser_bison.c"
        break;

    case YYSYMBOL_exthdr_expr: /* exthdr_expr  */
#line 837 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7027 "parser_bison.c"
        break;

    case YYSYMBOL_hbh_hdr_expr: /* hbh_hdr_expr  */
#line 839 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7033 "parser_bison.c"
        break;

    case YYSYMBOL_rt_hdr_expr: /* rt_hdr_expr  */
#line 842 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7039 "parser_bison.c"
        break;

    case YYSYMBOL_rt0_hdr_expr: /* rt0_hdr_expr  */
#line 842 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7045 "parser_bison.c"
        break;

    case YYSYMBOL_rt2_hdr_expr: /* rt2_hdr_expr  */
#line 842 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7051 "parser_bison.c"
        break;

    case YYSYMBOL_rt4_hdr_expr: /* rt4_hdr_expr  */
#line 842 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7057 "parser_bison.c"
        break;

    case YYSYMBOL_frag_hdr_expr: /* frag_hdr_expr  */
#line 839 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7063 "parser_bison.c"
        break;

    case YYSYMBOL_dst_hdr_expr: /* dst_hdr_expr  */
#line 839 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7069 "parser_bison.c"
        break;

    case YYSYMBOL_mh_hdr_expr: /* mh_hdr_expr  */
#line 845 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7075 "parser_bison.c"
        break;

    case YYSYMBOL_exthdr_exists_expr: /* exthdr_exists_expr  */
#line 894 "parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 7081 "parser_bison.c"
        break;

      default:
        break;
    }
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}






/*----------.
| yyparse.  |
`----------*/

int
yyparse (struct nft_ctx *nft, void *scanner, struct parser_state *state)
{
/* Lookahead token kind.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

/* Location data for the lookahead symbol.  */
static YYLTYPE yyloc_default
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
  = { 1, 1, 1, 1 }
# endif
;
YYLTYPE yylloc = yyloc_default;

    /* Number of syntax errors so far.  */
    int yynerrs = 0;

    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

    /* The location stack: array, bottom, top.  */
    YYLTYPE yylsa[YYINITDEPTH];
    YYLTYPE *yyls = yylsa;
    YYLTYPE *yylsp = yyls;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
  YYLTYPE yyloc;

  /* The locations where the error started and ended.  */
  YYLTYPE yyerror_range[3];

  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N), yylsp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

/* User initialization code.  */
#line 159 "parser_bison.y"
{
	location_init(scanner, state, &yylloc);
	if (nft->debug_mask & NFT_DEBUG_SCANNER)
		nft_set_debug(1, scanner);
	if (nft->debug_mask & NFT_DEBUG_PARSER)
		yydebug = 1;
}

#line 7186 "parser_bison.c"

  yylsp[0] = yylloc;
  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    goto yyexhaustedlab;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;
        YYLTYPE *yyls1 = yyls;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yyls1, yysize * YYSIZEOF (*yylsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
        yyls = yyls1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
        YYSTACK_RELOCATE (yyls_alloc, yyls);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
      yylsp = yyls + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex (&yylval, &yylloc, scanner);
    }

  if (yychar <= TOKEN_EOF)
    {
      yychar = TOKEN_EOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      yyerror_range[1] = yylloc;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END
  *++yylsp = yylloc;

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

  /* Default location. */
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
  yyerror_range[1] = yyloc;
  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 3: /* input: input line  */
#line 913 "parser_bison.y"
                        {
				if ((yyvsp[0].cmd) != NULL) {
					(yyvsp[0].cmd)->location = (yylsp[0]);
					list_add_tail(&(yyvsp[0].cmd)->list, state->cmds);
				}
			}
#line 7403 "parser_bison.c"
    break;

  case 8: /* close_scope_arp: %empty  */
#line 929 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_ARP); }
#line 7409 "parser_bison.c"
    break;

  case 9: /* close_scope_ct: %empty  */
#line 930 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_CT); }
#line 7415 "parser_bison.c"
    break;

  case 10: /* close_scope_counter: %empty  */
#line 931 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_COUNTER); }
#line 7421 "parser_bison.c"
    break;

  case 11: /* close_scope_eth: %empty  */
#line 932 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_ETH); }
#line 7427 "parser_bison.c"
    break;

  case 12: /* close_scope_fib: %empty  */
#line 933 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_FIB); }
#line 7433 "parser_bison.c"
    break;

  case 13: /* close_scope_hash: %empty  */
#line 934 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_HASH); }
#line 7439 "parser_bison.c"
    break;

  case 14: /* close_scope_ip: %empty  */
#line 935 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_IP); }
#line 7445 "parser_bison.c"
    break;

  case 15: /* close_scope_ip6: %empty  */
#line 936 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_IP6); }
#line 7451 "parser_bison.c"
    break;

  case 16: /* close_scope_vlan: %empty  */
#line 937 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_VLAN); }
#line 7457 "parser_bison.c"
    break;

  case 17: /* close_scope_ipsec: %empty  */
#line 938 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_IPSEC); }
#line 7463 "parser_bison.c"
    break;

  case 18: /* close_scope_list: %empty  */
#line 939 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_CMD_LIST); }
#line 7469 "parser_bison.c"
    break;

  case 19: /* close_scope_limit: %empty  */
#line 940 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_LIMIT); }
#line 7475 "parser_bison.c"
    break;

  case 20: /* close_scope_numgen: %empty  */
#line 941 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_NUMGEN); }
#line 7481 "parser_bison.c"
    break;

  case 21: /* close_scope_quota: %empty  */
#line 942 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_QUOTA); }
#line 7487 "parser_bison.c"
    break;

  case 22: /* close_scope_tcp: %empty  */
#line 943 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_TCP); }
#line 7493 "parser_bison.c"
    break;

  case 23: /* close_scope_queue: %empty  */
#line 944 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_QUEUE); }
#line 7499 "parser_bison.c"
    break;

  case 24: /* close_scope_rt: %empty  */
#line 945 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_RT); }
#line 7505 "parser_bison.c"
    break;

  case 25: /* close_scope_sctp: %empty  */
#line 946 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_SCTP); }
#line 7511 "parser_bison.c"
    break;

  case 26: /* close_scope_sctp_chunk: %empty  */
#line 947 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_SCTP_CHUNK); }
#line 7517 "parser_bison.c"
    break;

  case 27: /* close_scope_secmark: %empty  */
#line 948 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_SECMARK); }
#line 7523 "parser_bison.c"
    break;

  case 28: /* close_scope_socket: %empty  */
#line 949 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_SOCKET); }
#line 7529 "parser_bison.c"
    break;

  case 29: /* close_scope_log: %empty  */
#line 951 "parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_STMT_LOG); }
#line 7535 "parser_bison.c"
    break;

  case 30: /* common_block: "include" "quoted string" stmt_separator  */
#line 954 "parser_bison.y"
                        {
				if (scanner_include_file(nft, scanner, (yyvsp[-1].string), &(yyloc)) < 0) {
					xfree((yyvsp[-1].string));
					YYERROR;
				}
				xfree((yyvsp[-1].string));
			}
#line 7547 "parser_bison.c"
    break;

  case 31: /* common_block: "define" identifier '=' initializer_expr stmt_separator  */
#line 962 "parser_bison.y"
                        {
				struct scope *scope = current_scope(state);

				if (symbol_lookup(scope, (yyvsp[-3].string)) != NULL) {
					erec_queue(error(&(yylsp[-3]), "redefinition of symbol '%s'", (yyvsp[-3].string)),
						   state->msgs);
					expr_free((yyvsp[-1].expr));
					xfree((yyvsp[-3].string));
					YYERROR;
				}

				symbol_bind(scope, (yyvsp[-3].string), (yyvsp[-1].expr));
				xfree((yyvsp[-3].string));
			}
#line 7566 "parser_bison.c"
    break;

  case 32: /* common_block: "redefine" identifier '=' initializer_expr stmt_separator  */
#line 977 "parser_bison.y"
                        {
				struct scope *scope = current_scope(state);

				symbol_bind(scope, (yyvsp[-3].string), (yyvsp[-1].expr));
				xfree((yyvsp[-3].string));
			}
#line 7577 "parser_bison.c"
    break;

  case 33: /* common_block: "undefine" identifier stmt_separator  */
#line 984 "parser_bison.y"
                        {
				struct scope *scope = current_scope(state);

				if (symbol_unbind(scope, (yyvsp[-1].string)) < 0) {
					erec_queue(error(&(yylsp[-1]), "undefined symbol '%s'", (yyvsp[-1].string)),
						   state->msgs);
					xfree((yyvsp[-1].string));
					YYERROR;
				}
				xfree((yyvsp[-1].string));
			}
#line 7593 "parser_bison.c"
    break;

  case 34: /* common_block: error stmt_separator  */
#line 996 "parser_bison.y"
                        {
				if (++state->nerrs == nft->parser_max_errors)
					YYABORT;
				yyerrok;
			}
#line 7603 "parser_bison.c"
    break;

  case 35: /* line: common_block  */
#line 1003 "parser_bison.y"
                                                                { (yyval.cmd) = NULL; }
#line 7609 "parser_bison.c"
    break;

  case 36: /* line: stmt_separator  */
#line 1004 "parser_bison.y"
                                                                { (yyval.cmd) = NULL; }
#line 7615 "parser_bison.c"
    break;

  case 37: /* line: base_cmd stmt_separator  */
#line 1005 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[-1].cmd); }
#line 7621 "parser_bison.c"
    break;

  case 38: /* line: base_cmd "end of file"  */
#line 1007 "parser_bison.y"
                        {
				/*
				 * Very hackish workaround for bison >= 2.4: previous versions
				 * terminated parsing after EOF, 2.4+ tries to get further input
				 * in 'input' and calls the scanner again, causing a crash when
				 * the final input buffer has been popped. Terminate manually to
				 * avoid this. The correct fix should be to adjust the grammar
				 * to accept EOF in input, but for unknown reasons it does not
				 * work.
				 */
				if ((yyvsp[-1].cmd) != NULL) {
					(yyvsp[-1].cmd)->location = (yylsp[-1]);
					list_add_tail(&(yyvsp[-1].cmd)->list, state->cmds);
				}
				(yyval.cmd) = NULL;
				YYACCEPT;
			}
#line 7643 "parser_bison.c"
    break;

  case 39: /* base_cmd: add_cmd  */
#line 1026 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7649 "parser_bison.c"
    break;

  case 40: /* base_cmd: "add" add_cmd  */
#line 1027 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7655 "parser_bison.c"
    break;

  case 41: /* base_cmd: "replace" replace_cmd  */
#line 1028 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7661 "parser_bison.c"
    break;

  case 42: /* base_cmd: "create" create_cmd  */
#line 1029 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7667 "parser_bison.c"
    break;

  case 43: /* base_cmd: "insert" insert_cmd  */
#line 1030 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7673 "parser_bison.c"
    break;

  case 44: /* base_cmd: "delete" delete_cmd  */
#line 1031 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7679 "parser_bison.c"
    break;

  case 45: /* base_cmd: "get" get_cmd  */
#line 1032 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7685 "parser_bison.c"
    break;

  case 46: /* base_cmd: "list" list_cmd close_scope_list  */
#line 1033 "parser_bison.y"
                                                                                        { (yyval.cmd) = (yyvsp[-1].cmd); }
#line 7691 "parser_bison.c"
    break;

  case 47: /* base_cmd: "reset" reset_cmd  */
#line 1034 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7697 "parser_bison.c"
    break;

  case 48: /* base_cmd: "flush" flush_cmd  */
#line 1035 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7703 "parser_bison.c"
    break;

  case 49: /* base_cmd: "rename" rename_cmd  */
#line 1036 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7709 "parser_bison.c"
    break;

  case 50: /* base_cmd: "import" import_cmd  */
#line 1037 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7715 "parser_bison.c"
    break;

  case 51: /* base_cmd: "export" export_cmd  */
#line 1038 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7721 "parser_bison.c"
    break;

  case 52: /* base_cmd: "monitor" monitor_cmd  */
#line 1039 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7727 "parser_bison.c"
    break;

  case 53: /* base_cmd: "describe" describe_cmd  */
#line 1040 "parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7733 "parser_bison.c"
    break;

  case 54: /* add_cmd: "table" table_spec  */
#line 1044 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_TABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 7741 "parser_bison.c"
    break;

  case 55: /* add_cmd: "table" table_spec table_block_alloc '{' table_block '}'  */
#line 1049 "parser_bison.y"
                        {
				handle_merge(&(yyvsp[-3].table)->handle, &(yyvsp[-4].handle));
				close_scope(state);
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_TABLE, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].table));
			}
#line 7751 "parser_bison.c"
    break;

  case 56: /* add_cmd: "chain" chain_spec  */
#line 1055 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_CHAIN, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 7759 "parser_bison.c"
    break;

  case 57: /* add_cmd: "chain" chain_spec chain_block_alloc '{' chain_block '}'  */
#line 1060 "parser_bison.y"
                        {
				(yyvsp[-1].chain)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].chain)->handle, &(yyvsp[-4].handle));
				close_scope(state);
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_CHAIN, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].chain));
			}
#line 7770 "parser_bison.c"
    break;

  case 58: /* add_cmd: "rule" rule_position rule  */
#line 1067 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_RULE, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].rule));
			}
#line 7778 "parser_bison.c"
    break;

  case 59: /* add_cmd: rule_position rule  */
#line 1071 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_RULE, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].rule));
			}
#line 7786 "parser_bison.c"
    break;

  case 60: /* add_cmd: "set" set_spec set_block_alloc '{' set_block '}'  */
#line 1076 "parser_bison.y"
                        {
				(yyvsp[-1].set)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].set)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_SET, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].set));
			}
#line 7796 "parser_bison.c"
    break;

  case 61: /* add_cmd: "map" set_spec map_block_alloc '{' map_block '}'  */
#line 1083 "parser_bison.y"
                        {
				(yyvsp[-1].set)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].set)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_SET, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].set));
			}
#line 7806 "parser_bison.c"
    break;

  case 62: /* add_cmd: "element" set_spec set_block_expr  */
#line 1089 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_ELEMENTS, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].expr));
			}
#line 7814 "parser_bison.c"
    break;

  case 63: /* add_cmd: "flowtable" flowtable_spec flowtable_block_alloc '{' flowtable_block '}'  */
#line 1094 "parser_bison.y"
                        {
				(yyvsp[-1].flowtable)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].flowtable)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_FLOWTABLE, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].flowtable));
			}
#line 7824 "parser_bison.c"
    break;

  case 64: /* add_cmd: "counter" obj_spec close_scope_counter  */
#line 1100 "parser_bison.y"
                        {
				struct obj *obj;

				obj = obj_alloc(&(yyloc));
				obj->type = NFT_OBJECT_COUNTER;
				handle_merge(&obj->handle, &(yyvsp[-1].handle));
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_COUNTER, &(yyvsp[-1].handle), &(yyloc), obj);
			}
#line 7837 "parser_bison.c"
    break;

  case 65: /* add_cmd: "counter" obj_spec counter_obj counter_config close_scope_counter  */
#line 1109 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_COUNTER, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 7845 "parser_bison.c"
    break;

  case 66: /* add_cmd: "counter" obj_spec counter_obj '{' counter_block '}' close_scope_counter  */
#line 1113 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_COUNTER, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7853 "parser_bison.c"
    break;

  case 67: /* add_cmd: "quota" obj_spec quota_obj quota_config close_scope_quota  */
#line 1117 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_QUOTA, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 7861 "parser_bison.c"
    break;

  case 68: /* add_cmd: "quota" obj_spec quota_obj '{' quota_block '}' close_scope_quota  */
#line 1121 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_QUOTA, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7869 "parser_bison.c"
    break;

  case 69: /* add_cmd: "ct" "helper" obj_spec ct_obj_alloc '{' ct_helper_block '}' close_scope_ct  */
#line 1125 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_ADD, NFT_OBJECT_CT_HELPER, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7877 "parser_bison.c"
    break;

  case 70: /* add_cmd: "ct" "timeout" obj_spec ct_obj_alloc '{' ct_timeout_block '}' close_scope_ct  */
#line 1129 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_ADD, NFT_OBJECT_CT_TIMEOUT, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7885 "parser_bison.c"
    break;

  case 71: /* add_cmd: "ct" "expectation" obj_spec ct_obj_alloc '{' ct_expect_block '}' close_scope_ct  */
#line 1133 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_ADD, NFT_OBJECT_CT_EXPECT, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7893 "parser_bison.c"
    break;

  case 72: /* add_cmd: "limit" obj_spec limit_obj limit_config close_scope_limit  */
#line 1137 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_LIMIT, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 7901 "parser_bison.c"
    break;

  case 73: /* add_cmd: "limit" obj_spec limit_obj '{' limit_block '}' close_scope_limit  */
#line 1141 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_LIMIT, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7909 "parser_bison.c"
    break;

  case 74: /* add_cmd: "secmark" obj_spec secmark_obj secmark_config close_scope_secmark  */
#line 1145 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_SECMARK, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 7917 "parser_bison.c"
    break;

  case 75: /* add_cmd: "secmark" obj_spec secmark_obj '{' secmark_block '}' close_scope_secmark  */
#line 1149 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_SECMARK, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7925 "parser_bison.c"
    break;

  case 76: /* add_cmd: "synproxy" obj_spec synproxy_obj synproxy_config  */
#line 1153 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_SYNPROXY, &(yyvsp[-2].handle), &(yyloc), (yyvsp[-1].obj));
			}
#line 7933 "parser_bison.c"
    break;

  case 77: /* add_cmd: "synproxy" obj_spec synproxy_obj '{' synproxy_block '}'  */
#line 1157 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_SYNPROXY, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-3].obj));
			}
#line 7941 "parser_bison.c"
    break;

  case 78: /* replace_cmd: "rule" ruleid_spec rule  */
#line 1163 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_REPLACE, CMD_OBJ_RULE, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].rule));
			}
#line 7949 "parser_bison.c"
    break;

  case 79: /* create_cmd: "table" table_spec  */
#line 1169 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_TABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 7957 "parser_bison.c"
    break;

  case 80: /* create_cmd: "table" table_spec table_block_alloc '{' table_block '}'  */
#line 1174 "parser_bison.y"
                        {
				handle_merge(&(yyvsp[-3].table)->handle, &(yyvsp[-4].handle));
				close_scope(state);
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_TABLE, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].table));
			}
#line 7967 "parser_bison.c"
    break;

  case 81: /* create_cmd: "chain" chain_spec  */
#line 1180 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_CHAIN, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 7975 "parser_bison.c"
    break;

  case 82: /* create_cmd: "chain" chain_spec chain_block_alloc '{' chain_block '}'  */
#line 1185 "parser_bison.y"
                        {
				(yyvsp[-1].chain)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].chain)->handle, &(yyvsp[-4].handle));
				close_scope(state);
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_CHAIN, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].chain));
			}
#line 7986 "parser_bison.c"
    break;

  case 83: /* create_cmd: "set" set_spec set_block_alloc '{' set_block '}'  */
#line 1193 "parser_bison.y"
                        {
				(yyvsp[-1].set)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].set)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_SET, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].set));
			}
#line 7996 "parser_bison.c"
    break;

  case 84: /* create_cmd: "map" set_spec map_block_alloc '{' map_block '}'  */
#line 1200 "parser_bison.y"
                        {
				(yyvsp[-1].set)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].set)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_SET, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].set));
			}
#line 8006 "parser_bison.c"
    break;

  case 85: /* create_cmd: "element" set_spec set_block_expr  */
#line 1206 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_ELEMENTS, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].expr));
			}
#line 8014 "parser_bison.c"
    break;

  case 86: /* create_cmd: "flowtable" flowtable_spec flowtable_block_alloc '{' flowtable_block '}'  */
#line 1211 "parser_bison.y"
                        {
				(yyvsp[-1].flowtable)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].flowtable)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_FLOWTABLE, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].flowtable));
			}
#line 8024 "parser_bison.c"
    break;

  case 87: /* create_cmd: "counter" obj_spec close_scope_counter  */
#line 1217 "parser_bison.y"
                        {
				struct obj *obj;

				obj = obj_alloc(&(yyloc));
				obj->type = NFT_OBJECT_COUNTER;
				handle_merge(&obj->handle, &(yyvsp[-1].handle));
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_COUNTER, &(yyvsp[-1].handle), &(yyloc), obj);
			}
#line 8037 "parser_bison.c"
    break;

  case 88: /* create_cmd: "counter" obj_spec counter_obj counter_config close_scope_counter  */
#line 1226 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_COUNTER, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 8045 "parser_bison.c"
    break;

  case 89: /* create_cmd: "quota" obj_spec quota_obj quota_config close_scope_quota  */
#line 1230 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_QUOTA, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 8053 "parser_bison.c"
    break;

  case 90: /* create_cmd: "ct" "helper" obj_spec ct_obj_alloc '{' ct_helper_block '}' close_scope_ct  */
#line 1234 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_CREATE, NFT_OBJECT_CT_HELPER, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 8061 "parser_bison.c"
    break;

  case 91: /* create_cmd: "ct" "timeout" obj_spec ct_obj_alloc '{' ct_timeout_block '}' close_scope_ct  */
#line 1238 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_CREATE, NFT_OBJECT_CT_TIMEOUT, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 8069 "parser_bison.c"
    break;

  case 92: /* create_cmd: "ct" "expectation" obj_spec ct_obj_alloc '{' ct_expect_block '}' close_scope_ct  */
#line 1242 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_CREATE, NFT_OBJECT_CT_EXPECT, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 8077 "parser_bison.c"
    break;

  case 93: /* create_cmd: "limit" obj_spec limit_obj limit_config close_scope_limit  */
#line 1246 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_LIMIT, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 8085 "parser_bison.c"
    break;

  case 94: /* create_cmd: "secmark" obj_spec secmark_obj secmark_config close_scope_secmark  */
#line 1250 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_SECMARK, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 8093 "parser_bison.c"
    break;

  case 95: /* create_cmd: "synproxy" obj_spec synproxy_obj synproxy_config  */
#line 1254 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_SYNPROXY, &(yyvsp[-2].handle), &(yyloc), (yyvsp[-1].obj));
			}
#line 8101 "parser_bison.c"
    break;

  case 96: /* insert_cmd: "rule" rule_position rule  */
#line 1260 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_INSERT, CMD_OBJ_RULE, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].rule));
			}
#line 8109 "parser_bison.c"
    break;

  case 105: /* delete_cmd: "table" table_or_id_spec  */
#line 1282 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_TABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8117 "parser_bison.c"
    break;

  case 106: /* delete_cmd: "chain" chain_or_id_spec  */
#line 1286 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_CHAIN, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8125 "parser_bison.c"
    break;

  case 107: /* delete_cmd: "rule" ruleid_spec  */
#line 1290 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_RULE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8133 "parser_bison.c"
    break;

  case 108: /* delete_cmd: "set" set_or_id_spec  */
#line 1294 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_SET, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8141 "parser_bison.c"
    break;

  case 109: /* delete_cmd: "map" set_spec  */
#line 1298 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_SET, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8149 "parser_bison.c"
    break;

  case 110: /* delete_cmd: "element" set_spec set_block_expr  */
#line 1302 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_ELEMENTS, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].expr));
			}
#line 8157 "parser_bison.c"
    break;

  case 111: /* delete_cmd: "flowtable" flowtable_spec  */
#line 1306 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_FLOWTABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8165 "parser_bison.c"
    break;

  case 112: /* delete_cmd: "flowtable" flowtableid_spec  */
#line 1310 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_FLOWTABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8173 "parser_bison.c"
    break;

  case 113: /* delete_cmd: "flowtable" flowtable_spec flowtable_block_alloc '{' flowtable_block '}'  */
#line 1315 "parser_bison.y"
                        {
				(yyvsp[-1].flowtable)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].flowtable)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_FLOWTABLE, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].flowtable));
			}
#line 8183 "parser_bison.c"
    break;

  case 114: /* delete_cmd: "counter" obj_or_id_spec close_scope_counter  */
#line 1321 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_COUNTER, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8191 "parser_bison.c"
    break;

  case 115: /* delete_cmd: "quota" obj_or_id_spec close_scope_quota  */
#line 1325 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_QUOTA, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8199 "parser_bison.c"
    break;

  case 116: /* delete_cmd: "ct" ct_obj_type obj_spec ct_obj_alloc close_scope_ct  */
#line 1329 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_DELETE, (yyvsp[-3].val), &(yyvsp[-2].handle), &(yyloc), (yyvsp[-1].obj));
				if ((yyvsp[-3].val) == NFT_OBJECT_CT_TIMEOUT)
					init_list_head(&(yyvsp[-1].obj)->ct_timeout.timeout_list);
			}
#line 8209 "parser_bison.c"
    break;

  case 117: /* delete_cmd: "limit" obj_or_id_spec close_scope_limit  */
#line 1335 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_LIMIT, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8217 "parser_bison.c"
    break;

  case 118: /* delete_cmd: "secmark" obj_or_id_spec close_scope_secmark  */
#line 1339 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_SECMARK, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8225 "parser_bison.c"
    break;

  case 119: /* delete_cmd: "synproxy" obj_or_id_spec  */
#line 1343 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_SYNPROXY, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8233 "parser_bison.c"
    break;

  case 120: /* get_cmd: "element" set_spec set_block_expr  */
#line 1349 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_GET, CMD_OBJ_ELEMENTS, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].expr));
			}
#line 8241 "parser_bison.c"
    break;

  case 121: /* list_cmd: "table" table_spec  */
#line 1355 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_TABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8249 "parser_bison.c"
    break;

  case 122: /* list_cmd: "tables" ruleset_spec  */
#line 1359 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_TABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8257 "parser_bison.c"
    break;

  case 123: /* list_cmd: "chain" chain_spec  */
#line 1363 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_CHAIN, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8265 "parser_bison.c"
    break;

  case 124: /* list_cmd: "chains" ruleset_spec  */
#line 1367 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_CHAINS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8273 "parser_bison.c"
    break;

  case 125: /* list_cmd: "sets" ruleset_spec  */
#line 1371 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SETS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8281 "parser_bison.c"
    break;

  case 126: /* list_cmd: "sets" "table" table_spec  */
#line 1375 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SETS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8289 "parser_bison.c"
    break;

  case 127: /* list_cmd: "set" set_spec  */
#line 1379 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SET, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8297 "parser_bison.c"
    break;

  case 128: /* list_cmd: "counters" ruleset_spec  */
#line 1383 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_COUNTERS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8305 "parser_bison.c"
    break;

  case 129: /* list_cmd: "counters" "table" table_spec  */
#line 1387 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_COUNTERS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8313 "parser_bison.c"
    break;

  case 130: /* list_cmd: "counter" obj_spec close_scope_counter  */
#line 1391 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_COUNTER, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8321 "parser_bison.c"
    break;

  case 131: /* list_cmd: "quotas" ruleset_spec  */
#line 1395 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_QUOTAS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8329 "parser_bison.c"
    break;

  case 132: /* list_cmd: "quotas" "table" table_spec  */
#line 1399 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_QUOTAS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8337 "parser_bison.c"
    break;

  case 133: /* list_cmd: "quota" obj_spec close_scope_quota  */
#line 1403 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_QUOTA, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8345 "parser_bison.c"
    break;

  case 134: /* list_cmd: "limits" ruleset_spec  */
#line 1407 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_LIMITS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8353 "parser_bison.c"
    break;

  case 135: /* list_cmd: "limits" "table" table_spec  */
#line 1411 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_LIMITS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8361 "parser_bison.c"
    break;

  case 136: /* list_cmd: "limit" obj_spec close_scope_limit  */
#line 1415 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_LIMIT, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8369 "parser_bison.c"
    break;

  case 137: /* list_cmd: "secmarks" ruleset_spec  */
#line 1419 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SECMARKS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8377 "parser_bison.c"
    break;

  case 138: /* list_cmd: "secmarks" "table" table_spec  */
#line 1423 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SECMARKS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8385 "parser_bison.c"
    break;

  case 139: /* list_cmd: "secmark" obj_spec close_scope_secmark  */
#line 1427 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SECMARK, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8393 "parser_bison.c"
    break;

  case 140: /* list_cmd: "synproxys" ruleset_spec  */
#line 1431 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SYNPROXYS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8401 "parser_bison.c"
    break;

  case 141: /* list_cmd: "synproxys" "table" table_spec  */
#line 1435 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SYNPROXYS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8409 "parser_bison.c"
    break;

  case 142: /* list_cmd: "synproxy" obj_spec  */
#line 1439 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SYNPROXY, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8417 "parser_bison.c"
    break;

  case 143: /* list_cmd: "ruleset" ruleset_spec  */
#line 1443 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_RULESET, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8425 "parser_bison.c"
    break;

  case 144: /* list_cmd: "flow" "tables" ruleset_spec  */
#line 1447 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_METERS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8433 "parser_bison.c"
    break;

  case 145: /* list_cmd: "flow" "table" set_spec  */
#line 1451 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_METER, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8441 "parser_bison.c"
    break;

  case 146: /* list_cmd: "meters" ruleset_spec  */
#line 1455 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_METERS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8449 "parser_bison.c"
    break;

  case 147: /* list_cmd: "meter" set_spec  */
#line 1459 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_METER, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8457 "parser_bison.c"
    break;

  case 148: /* list_cmd: "flowtables" ruleset_spec  */
#line 1463 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_FLOWTABLES, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8465 "parser_bison.c"
    break;

  case 149: /* list_cmd: "flowtable" flowtable_spec  */
#line 1467 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_FLOWTABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8473 "parser_bison.c"
    break;

  case 150: /* list_cmd: "maps" ruleset_spec  */
#line 1471 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_MAPS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8481 "parser_bison.c"
    break;

  case 151: /* list_cmd: "map" set_spec  */
#line 1475 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_MAP, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8489 "parser_bison.c"
    break;

  case 152: /* list_cmd: "ct" ct_obj_type obj_spec close_scope_ct  */
#line 1479 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_LIST, (yyvsp[-2].val), &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8497 "parser_bison.c"
    break;

  case 153: /* list_cmd: "ct" ct_cmd_type "table" table_spec close_scope_ct  */
#line 1483 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, (yyvsp[-3].val), &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8505 "parser_bison.c"
    break;

  case 154: /* list_cmd: "hooks" basehook_spec  */
#line 1487 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_HOOKS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8513 "parser_bison.c"
    break;

  case 155: /* basehook_device_name: "device" "string"  */
#line 1493 "parser_bison.y"
                        {
				(yyval.string) = (yyvsp[0].string);
			}
#line 8521 "parser_bison.c"
    break;

  case 156: /* basehook_spec: ruleset_spec  */
#line 1499 "parser_bison.y"
                        {
				(yyval.handle) = (yyvsp[0].handle);
			}
#line 8529 "parser_bison.c"
    break;

  case 157: /* basehook_spec: ruleset_spec basehook_device_name  */
#line 1503 "parser_bison.y"
                        {
				if ((yyvsp[0].string)) {
					(yyvsp[-1].handle).obj.name = (yyvsp[0].string);
					(yyvsp[-1].handle).obj.location = (yylsp[0]);
				}
				(yyval.handle) = (yyvsp[-1].handle);
			}
#line 8541 "parser_bison.c"
    break;

  case 158: /* reset_cmd: "counters" ruleset_spec  */
#line 1513 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RESET, CMD_OBJ_COUNTERS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8549 "parser_bison.c"
    break;

  case 159: /* reset_cmd: "counters" "table" table_spec  */
#line 1517 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RESET, CMD_OBJ_COUNTERS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8557 "parser_bison.c"
    break;

  case 160: /* reset_cmd: "counter" obj_spec close_scope_counter  */
#line 1521 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RESET, CMD_OBJ_COUNTER, &(yyvsp[-1].handle),&(yyloc), NULL);
			}
#line 8565 "parser_bison.c"
    break;

  case 161: /* reset_cmd: "quotas" ruleset_spec  */
#line 1525 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RESET, CMD_OBJ_QUOTAS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8573 "parser_bison.c"
    break;

  case 162: /* reset_cmd: "quotas" "table" table_spec  */
#line 1529 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RESET, CMD_OBJ_QUOTAS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8581 "parser_bison.c"
    break;

  case 163: /* reset_cmd: "quota" obj_spec close_scope_quota  */
#line 1533 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RESET, CMD_OBJ_QUOTA, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8589 "parser_bison.c"
    break;

  case 164: /* flush_cmd: "table" table_spec  */
#line 1539 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_TABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8597 "parser_bison.c"
    break;

  case 165: /* flush_cmd: "chain" chain_spec  */
#line 1543 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_CHAIN, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8605 "parser_bison.c"
    break;

  case 166: /* flush_cmd: "set" set_spec  */
#line 1547 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_SET, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8613 "parser_bison.c"
    break;

  case 167: /* flush_cmd: "map" set_spec  */
#line 1551 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_MAP, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8621 "parser_bison.c"
    break;

  case 168: /* flush_cmd: "flow" "table" set_spec  */
#line 1555 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_METER, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8629 "parser_bison.c"
    break;

  case 169: /* flush_cmd: "meter" set_spec  */
#line 1559 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_METER, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8637 "parser_bison.c"
    break;

  case 170: /* flush_cmd: "ruleset" ruleset_spec  */
#line 1563 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_RULESET, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8645 "parser_bison.c"
    break;

  case 171: /* rename_cmd: "chain" chain_spec identifier  */
#line 1569 "parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RENAME, CMD_OBJ_CHAIN, &(yyvsp[-1].handle), &(yyloc), NULL);
				(yyval.cmd)->arg = (yyvsp[0].string);
			}
#line 8654 "parser_bison.c"
    break;

  case 172: /* import_cmd: "ruleset" markup_format  */
#line 1576 "parser_bison.y"
                        {
				struct handle h = { .family = NFPROTO_UNSPEC };
				struct markup *markup = markup_alloc((yyvsp[0].val));
				(yyval.cmd) = cmd_alloc(CMD_IMPORT, CMD_OBJ_MARKUP, &h, &(yyloc), markup);
			}
#line 8664 "parser_bison.c"
    break;

  case 173: /* import_cmd: markup_format  */
#line 1582 "parser_bison.y"
                        {
				struct handle h = { .family = NFPROTO_UNSPEC };
				struct markup *markup = markup_alloc((yyvsp[0].val));
				(yyval.cmd) = cmd_alloc(CMD_IMPORT, CMD_OBJ_MARKUP, &h, &(yyloc), markup);
			}
#line 8674 "parser_bison.c"
    break;

  case 174: /* export_cmd: "ruleset" markup_format  */
#line 1590 "parser_bison.y"
                        {
				struct handle h = { .family = NFPROTO_UNSPEC };
				struct markup *markup = markup_alloc((yyvsp[0].val));
				(yyval.cmd) = cmd_alloc(CMD_EXPORT, CMD_OBJ_MARKUP, &h, &(yyloc), markup);
			}
#line 8684 "parser_bison.c"
    break;

  case 175: /* export_cmd: markup_format  */
#line 1596 "parser_bison.y"
                        {
				struct handle h = { .family = NFPROTO_UNSPEC };
				struct markup *markup = markup_alloc((yyvsp[0].val));
				(yyval.cmd) = cmd_alloc(CMD_EXPORT, CMD_OBJ_MARKUP, &h, &(yyloc), markup);
			}
#line 8694 "parser_bison.c"
    break;

  case 176: /* monitor_cmd: monitor_event monitor_object monitor_format  */
#line 1604 "parser_bison.y"
                        {
				struct handle h = { .family = NFPROTO_UNSPEC };
				struct monitor *m = monitor_alloc((yyvsp[0].val), (yyvsp[-1].val), (yyvsp[-2].string));
				m->location = (yylsp[-2]);
				(yyval.cmd) = cmd_alloc(CMD_MONITOR, CMD_OBJ_MONITOR, &h, &(yyloc), m);
			}
#line 8705 "parser_bison.c"
    break;

  case 177: /* monitor_event: %empty  */
#line 1612 "parser_bison.y"
                                                { (yyval.string) = NULL; }
#line 8711 "parser_bison.c"
    break;

  case 178: /* monitor_event: "string"  */
#line 1613 "parser_bison.y"
                                                { (yyval.string) = (yyvsp[0].string); }
#line 8717 "parser_bison.c"
    break;

  case 179: /* monitor_object: %empty  */
#line 1616 "parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_ANY; }
#line 8723 "parser_bison.c"
    break;

  case 180: /* monitor_object: "tables"  */
#line 1617 "parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_TABLES; }
#line 8729 "parser_bison.c"
    break;

  case 181: /* monitor_object: "chains"  */
#line 1618 "parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_CHAINS; }
#line 8735 "parser_bison.c"
    break;

  case 182: /* monitor_object: "sets"  */
#line 1619 "parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_SETS; }
#line 8741 "parser_bison.c"
    break;

  case 183: /* monitor_object: "rules"  */
#line 1620 "parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_RULES; }
#line 8747 "parser_bison.c"
    break;

  case 184: /* monitor_object: "elements"  */
#line 1621 "parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_ELEMS; }
#line 8753 "parser_bison.c"
    break;

  case 185: /* monitor_object: "ruleset"  */
#line 1622 "parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_RULESET; }
#line 8759 "parser_bison.c"
    break;

  case 186: /* monitor_object: "trace"  */
#line 1623 "parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_TRACE; }
#line 8765 "parser_bison.c"
    break;

  case 187: /* monitor_format: %empty  */
#line 1626 "parser_bison.y"
                                                { (yyval.val) = NFTNL_OUTPUT_DEFAULT; }
#line 8771 "parser_bison.c"
    break;

  case 189: /* markup_format: "xml"  */
#line 1630 "parser_bison.y"
                                                { (yyval.val) = __NFT_OUTPUT_NOTSUPP; }
#line 8777 "parser_bison.c"
    break;

  case 190: /* markup_format: "json"  */
#line 1631 "parser_bison.y"
                                                { (yyval.val) = NFTNL_OUTPUT_JSON; }
#line 8783 "parser_bison.c"
    break;

  case 191: /* markup_format: "vm" "json"  */
#line 1632 "parser_bison.y"
                                                { (yyval.val) = NFTNL_OUTPUT_JSON; }
#line 8789 "parser_bison.c"
    break;

  case 192: /* describe_cmd: primary_expr  */
#line 1636 "parser_bison.y"
                        {
				struct handle h = { .family = NFPROTO_UNSPEC };
				(yyval.cmd) = cmd_alloc(CMD_DESCRIBE, CMD_OBJ_EXPR, &h, &(yyloc), NULL);
				(yyval.cmd)->expr = (yyvsp[0].expr);
			}
#line 8799 "parser_bison.c"
    break;

  case 193: /* table_block_alloc: %empty  */
#line 1644 "parser_bison.y"
                        {
				(yyval.table) = table_alloc();
				open_scope(state, &(yyval.table)->scope);
			}
#line 8808 "parser_bison.c"
    break;

  case 194: /* table_options: "flags" "string"  */
#line 1651 "parser_bison.y"
                        {
				if (strcmp((yyvsp[0].string), "dormant") == 0) {
					(yyvsp[-2].table)->flags |= TABLE_F_DORMANT;
					xfree((yyvsp[0].string));
				} else if (strcmp((yyvsp[0].string), "owner") == 0) {
					(yyvsp[-2].table)->flags |= TABLE_F_OWNER;
					xfree((yyvsp[0].string));
				} else {
					erec_queue(error(&(yylsp[0]), "unknown table option %s", (yyvsp[0].string)),
						   state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
			}
#line 8827 "parser_bison.c"
    break;

  case 195: /* table_options: comment_spec  */
#line 1666 "parser_bison.y"
                        {
				if (already_set((yyvsp[-1].table)->comment, &(yyloc), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].table)->comment = (yyvsp[0].string);
			}
#line 8839 "parser_bison.c"
    break;

  case 196: /* table_block: %empty  */
#line 1675 "parser_bison.y"
                                                { (yyval.table) = (yyvsp[(-1) - (0)].table); }
#line 8845 "parser_bison.c"
    break;

  case 200: /* table_block: table_block "chain" chain_identifier chain_block_alloc '{' chain_block '}' stmt_separator  */
#line 1682 "parser_bison.y"
                        {
				(yyvsp[-4].chain)->location = (yylsp[-5]);
				handle_merge(&(yyvsp[-4].chain)->handle, &(yyvsp[-5].handle));
				handle_free(&(yyvsp[-5].handle));
				close_scope(state);
				list_add_tail(&(yyvsp[-4].chain)->list, &(yyvsp[-7].table)->chains);
				(yyval.table) = (yyvsp[-7].table);
			}
#line 8858 "parser_bison.c"
    break;

  case 201: /* table_block: table_block "set" set_identifier set_block_alloc '{' set_block '}' stmt_separator  */
#line 1693 "parser_bison.y"
                        {
				(yyvsp[-4].set)->location = (yylsp[-5]);
				handle_merge(&(yyvsp[-4].set)->handle, &(yyvsp[-5].handle));
				handle_free(&(yyvsp[-5].handle));
				list_add_tail(&(yyvsp[-4].set)->list, &(yyvsp[-7].table)->sets);
				(yyval.table) = (yyvsp[-7].table);
			}
#line 8870 "parser_bison.c"
    break;

  case 202: /* table_block: table_block "map" set_identifier map_block_alloc '{' map_block '}' stmt_separator  */
#line 1703 "parser_bison.y"
                        {
				(yyvsp[-4].set)->location = (yylsp[-5]);
				handle_merge(&(yyvsp[-4].set)->handle, &(yyvsp[-5].handle));
				handle_free(&(yyvsp[-5].handle));
				list_add_tail(&(yyvsp[-4].set)->list, &(yyvsp[-7].table)->sets);
				(yyval.table) = (yyvsp[-7].table);
			}
#line 8882 "parser_bison.c"
    break;

  case 203: /* table_block: table_block "flowtable" flowtable_identifier flowtable_block_alloc '{' flowtable_block '}' stmt_separator  */
#line 1714 "parser_bison.y"
                        {
				(yyvsp[-4].flowtable)->location = (yylsp[-5]);
				handle_merge(&(yyvsp[-4].flowtable)->handle, &(yyvsp[-5].handle));
				handle_free(&(yyvsp[-5].handle));
				list_add_tail(&(yyvsp[-4].flowtable)->list, &(yyvsp[-7].table)->flowtables);
				(yyval.table) = (yyvsp[-7].table);
			}
#line 8894 "parser_bison.c"
    break;

  case 204: /* table_block: table_block "counter" obj_identifier obj_block_alloc '{' counter_block '}' stmt_separator close_scope_counter  */
#line 1724 "parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_COUNTER;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-8].table)->objs);
				(yyval.table) = (yyvsp[-8].table);
			}
#line 8907 "parser_bison.c"
    break;

  case 205: /* table_block: table_block "quota" obj_identifier obj_block_alloc '{' quota_block '}' stmt_separator close_scope_quota  */
#line 1735 "parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_QUOTA;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-8].table)->objs);
				(yyval.table) = (yyvsp[-8].table);
			}
#line 8920 "parser_bison.c"
    break;

  case 206: /* table_block: table_block "ct" "helper" obj_identifier obj_block_alloc '{' ct_helper_block '}' close_scope_ct stmt_separator  */
#line 1744 "parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_CT_HELPER;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-9].table)->objs);
				(yyval.table) = (yyvsp[-9].table);
			}
#line 8933 "parser_bison.c"
    break;

  case 207: /* table_block: table_block "ct" "timeout" obj_identifier obj_block_alloc '{' ct_timeout_block '}' close_scope_ct stmt_separator  */
#line 1753 "parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_CT_TIMEOUT;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-9].table)->objs);
				(yyval.table) = (yyvsp[-9].table);
			}
#line 8946 "parser_bison.c"
    break;

  case 208: /* table_block: table_block "ct" "expectation" obj_identifier obj_block_alloc '{' ct_expect_block '}' close_scope_ct stmt_separator  */
#line 1762 "parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_CT_EXPECT;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-9].table)->objs);
				(yyval.table) = (yyvsp[-9].table);
			}
#line 8959 "parser_bison.c"
    break;

  case 209: /* table_block: table_block "limit" obj_identifier obj_block_alloc '{' limit_block '}' stmt_separator close_scope_limit  */
#line 1773 "parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_LIMIT;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-8].table)->objs);
				(yyval.table) = (yyvsp[-8].table);
			}
#line 8972 "parser_bison.c"
    break;

  case 210: /* table_block: table_block "secmark" obj_identifier obj_block_alloc '{' secmark_block '}' stmt_separator close_scope_secmark  */
#line 1784 "parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_SECMARK;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-8].table)->objs);
				(yyval.table) = (yyvsp[-8].table);
			}
#line 8985 "parser_bison.c"
    break;

  case 211: /* table_block: table_block "synproxy" obj_identifier obj_block_alloc '{' synproxy_block '}' stmt_separator  */
#line 1795 "parser_bison.y"
                        {
				(yyvsp[-4].obj)->location = (yylsp[-5]);
				(yyvsp[-4].obj)->type = NFT_OBJECT_SYNPROXY;
				handle_merge(&(yyvsp[-4].obj)->handle, &(yyvsp[-5].handle));
				handle_free(&(yyvsp[-5].handle));
				list_add_tail(&(yyvsp[-4].obj)->list, &(yyvsp[-7].table)->objs);
				(yyval.table) = (yyvsp[-7].table);
			}
#line 8998 "parser_bison.c"
    break;

  case 212: /* chain_block_alloc: %empty  */
#line 1806 "parser_bison.y"
                        {
				(yyval.chain) = chain_alloc(NULL);
				open_scope(state, &(yyval.chain)->scope);
			}
#line 9007 "parser_bison.c"
    break;

  case 213: /* chain_block: %empty  */
#line 1812 "parser_bison.y"
                                                { (yyval.chain) = (yyvsp[(-1) - (0)].chain); }
#line 9013 "parser_bison.c"
    break;

  case 219: /* chain_block: chain_block rule stmt_separator  */
#line 1819 "parser_bison.y"
                        {
				list_add_tail(&(yyvsp[-1].rule)->list, &(yyvsp[-2].chain)->rules);
				(yyval.chain) = (yyvsp[-2].chain);
			}
#line 9022 "parser_bison.c"
    break;

  case 220: /* chain_block: chain_block comment_spec stmt_separator  */
#line 1824 "parser_bison.y"
                        {
				if (already_set((yyvsp[-2].chain)->comment, &(yylsp[-1]), state)) {
					xfree((yyvsp[-1].string));
					YYERROR;
				}
				(yyvsp[-2].chain)->comment = (yyvsp[-1].string);
			}
#line 9034 "parser_bison.c"
    break;

  case 221: /* subchain_block: %empty  */
#line 1833 "parser_bison.y"
                                                { (yyval.chain) = (yyvsp[(-1) - (0)].chain); }
#line 9040 "parser_bison.c"
    break;

  case 223: /* subchain_block: subchain_block rule stmt_separator  */
#line 1836 "parser_bison.y"
                        {
				list_add_tail(&(yyvsp[-1].rule)->list, &(yyvsp[-2].chain)->rules);
				(yyval.chain) = (yyvsp[-2].chain);
			}
#line 9049 "parser_bison.c"
    break;

  case 224: /* typeof_data_expr: primary_expr  */
#line 1843 "parser_bison.y"
                        {
				struct expr *e = (yyvsp[0].expr);

				if (e->etype == EXPR_SYMBOL &&
				    strcmp("verdict", e->identifier) == 0) {
					struct expr *v = verdict_expr_alloc(&(yylsp[0]), NF_ACCEPT, NULL);

					expr_free(e);
					v->flags &= ~EXPR_F_CONSTANT;
					e = v;
				}

				if (expr_ops(e)->build_udata == NULL) {
					erec_queue(error(&(yylsp[0]), "map data type '%s' lacks typeof serialization", expr_ops(e)->name),
						   state->msgs);
					expr_free(e);
					YYERROR;
				}
				(yyval.expr) = e;
			}
#line 9074 "parser_bison.c"
    break;

  case 225: /* typeof_data_expr: typeof_expr "." primary_expr  */
#line 1864 "parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 9087 "parser_bison.c"
    break;

  case 226: /* typeof_expr: primary_expr  */
#line 1875 "parser_bison.y"
                        {
				if (expr_ops((yyvsp[0].expr))->build_udata == NULL) {
					erec_queue(error(&(yylsp[0]), "primary expression type '%s' lacks typeof serialization", expr_ops((yyvsp[0].expr))->name),
						   state->msgs);
					expr_free((yyvsp[0].expr));
					YYERROR;
				}

				(yyval.expr) = (yyvsp[0].expr);
			}
#line 9102 "parser_bison.c"
    break;

  case 227: /* typeof_expr: typeof_expr "." primary_expr  */
#line 1886 "parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 9115 "parser_bison.c"
    break;

  case 228: /* set_block_alloc: %empty  */
#line 1898 "parser_bison.y"
                        {
				(yyval.set) = set_alloc(NULL);
			}
#line 9123 "parser_bison.c"
    break;

  case 229: /* set_block: %empty  */
#line 1903 "parser_bison.y"
                                                { (yyval.set) = (yyvsp[(-1) - (0)].set); }
#line 9129 "parser_bison.c"
    break;

  case 232: /* set_block: set_block "type" data_type_expr stmt_separator  */
#line 1907 "parser_bison.y"
                        {
				(yyvsp[-3].set)->key = (yyvsp[-1].expr);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9138 "parser_bison.c"
    break;

  case 233: /* set_block: set_block "typeof" typeof_expr stmt_separator  */
#line 1912 "parser_bison.y"
                        {
				(yyvsp[-3].set)->key = (yyvsp[-1].expr);
				datatype_set((yyvsp[-3].set)->key, (yyvsp[-1].expr)->dtype);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9148 "parser_bison.c"
    break;

  case 234: /* set_block: set_block "flags" set_flag_list stmt_separator  */
#line 1918 "parser_bison.y"
                        {
				(yyvsp[-3].set)->flags = (yyvsp[-1].val);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9157 "parser_bison.c"
    break;

  case 235: /* set_block: set_block "timeout" time_spec stmt_separator  */
#line 1923 "parser_bison.y"
                        {
				(yyvsp[-3].set)->timeout = (yyvsp[-1].val);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9166 "parser_bison.c"
    break;

  case 236: /* set_block: set_block "gc-interval" time_spec stmt_separator  */
#line 1928 "parser_bison.y"
                        {
				(yyvsp[-3].set)->gc_int = (yyvsp[-1].val);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9175 "parser_bison.c"
    break;

  case 237: /* set_block: set_block stateful_stmt_list stmt_separator  */
#line 1933 "parser_bison.y"
                        {
				list_splice_tail((yyvsp[-1].list), &(yyvsp[-2].set)->stmt_list);
				(yyval.set) = (yyvsp[-2].set);
				free((yyvsp[-1].list));
			}
#line 9185 "parser_bison.c"
    break;

  case 238: /* set_block: set_block "elements" '=' set_block_expr  */
#line 1939 "parser_bison.y"
                        {
				(yyvsp[-3].set)->init = (yyvsp[0].expr);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9194 "parser_bison.c"
    break;

  case 239: /* set_block: set_block "auto-merge"  */
#line 1944 "parser_bison.y"
                        {
				(yyvsp[-1].set)->automerge = true;
				(yyval.set) = (yyvsp[-1].set);
			}
#line 9203 "parser_bison.c"
    break;

  case 241: /* set_block: set_block comment_spec stmt_separator  */
#line 1950 "parser_bison.y"
                        {
				if (already_set((yyvsp[-2].set)->comment, &(yylsp[-1]), state)) {
					xfree((yyvsp[-1].string));
					YYERROR;
				}
				(yyvsp[-2].set)->comment = (yyvsp[-1].string);
				(yyval.set) = (yyvsp[-2].set);
			}
#line 9216 "parser_bison.c"
    break;

  case 244: /* set_flag_list: set_flag_list "comma" set_flag  */
#line 1965 "parser_bison.y"
                        {
				(yyval.val) = (yyvsp[-2].val) | (yyvsp[0].val);
			}
#line 9224 "parser_bison.c"
    break;

  case 246: /* set_flag: "constant"  */
#line 1971 "parser_bison.y"
                                                { (yyval.val) = NFT_SET_CONSTANT; }
#line 9230 "parser_bison.c"
    break;

  case 247: /* set_flag: "interval"  */
#line 1972 "parser_bison.y"
                                                { (yyval.val) = NFT_SET_INTERVAL; }
#line 9236 "parser_bison.c"
    break;

  case 248: /* set_flag: "timeout"  */
#line 1973 "parser_bison.y"
                                                { (yyval.val) = NFT_SET_TIMEOUT; }
#line 9242 "parser_bison.c"
    break;

  case 249: /* set_flag: "dynamic"  */
#line 1974 "parser_bison.y"
                                                { (yyval.val) = NFT_SET_EVAL; }
#line 9248 "parser_bison.c"
    break;

  case 250: /* map_block_alloc: %empty  */
#line 1978 "parser_bison.y"
                        {
				(yyval.set) = set_alloc(NULL);
			}
#line 9256 "parser_bison.c"
    break;

  case 251: /* map_block_obj_type: "counter" close_scope_counter  */
#line 1983 "parser_bison.y"
                                                            { (yyval.val) = NFT_OBJECT_COUNTER; }
#line 9262 "parser_bison.c"
    break;

  case 252: /* map_block_obj_type: "quota" close_scope_quota  */
#line 1984 "parser_bison.y"
                                                          { (yyval.val) = NFT_OBJECT_QUOTA; }
#line 9268 "parser_bison.c"
    break;

  case 253: /* map_block_obj_type: "limit" close_scope_limit  */
#line 1985 "parser_bison.y"
                                                          { (yyval.val) = NFT_OBJECT_LIMIT; }
#line 9274 "parser_bison.c"
    break;

  case 254: /* map_block_obj_type: "secmark" close_scope_secmark  */
#line 1986 "parser_bison.y"
                                                            { (yyval.val) = NFT_OBJECT_SECMARK; }
#line 9280 "parser_bison.c"
    break;

  case 255: /* map_block_obj_type: "synproxy"  */
#line 1987 "parser_bison.y"
                                         { (yyval.val) = NFT_OBJECT_SYNPROXY; }
#line 9286 "parser_bison.c"
    break;

  case 256: /* map_block: %empty  */
#line 1990 "parser_bison.y"
                                                { (yyval.set) = (yyvsp[(-1) - (0)].set); }
#line 9292 "parser_bison.c"
    break;

  case 259: /* map_block: map_block "timeout" time_spec stmt_separator  */
#line 1994 "parser_bison.y"
                        {
				(yyvsp[-3].set)->timeout = (yyvsp[-1].val);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9301 "parser_bison.c"
    break;

  case 260: /* map_block: map_block "type" data_type_expr "colon" data_type_expr stmt_separator  */
#line 2001 "parser_bison.y"
                        {
				(yyvsp[-5].set)->key = (yyvsp[-3].expr);
				(yyvsp[-5].set)->data = (yyvsp[-1].expr);

				(yyvsp[-5].set)->flags |= NFT_SET_MAP;
				(yyval.set) = (yyvsp[-5].set);
			}
#line 9313 "parser_bison.c"
    break;

  case 261: /* map_block: map_block "type" data_type_expr "colon" "interval" data_type_expr stmt_separator  */
#line 2011 "parser_bison.y"
                        {
				(yyvsp[-6].set)->key = (yyvsp[-4].expr);
				(yyvsp[-6].set)->data = (yyvsp[-1].expr);
				(yyvsp[-6].set)->data->flags |= EXPR_F_INTERVAL;

				(yyvsp[-6].set)->flags |= NFT_SET_MAP;
				(yyval.set) = (yyvsp[-6].set);
			}
#line 9326 "parser_bison.c"
    break;

  case 262: /* map_block: map_block "typeof" typeof_expr "colon" typeof_data_expr stmt_separator  */
#line 2022 "parser_bison.y"
                        {
				(yyvsp[-5].set)->key = (yyvsp[-3].expr);
				datatype_set((yyvsp[-5].set)->key, (yyvsp[-3].expr)->dtype);
				(yyvsp[-5].set)->data = (yyvsp[-1].expr);

				(yyvsp[-5].set)->flags |= NFT_SET_MAP;
				(yyval.set) = (yyvsp[-5].set);
			}
#line 9339 "parser_bison.c"
    break;

  case 263: /* map_block: map_block "typeof" typeof_expr "colon" "interval" typeof_expr stmt_separator  */
#line 2033 "parser_bison.y"
                        {
				(yyvsp[-6].set)->key = (yyvsp[-4].expr);
				datatype_set((yyvsp[-6].set)->key, (yyvsp[-4].expr)->dtype);
				(yyvsp[-6].set)->data = (yyvsp[-1].expr);
				(yyvsp[-6].set)->data->flags |= EXPR_F_INTERVAL;

				(yyvsp[-6].set)->flags |= NFT_SET_MAP;
				(yyval.set) = (yyvsp[-6].set);
			}
#line 9353 "parser_bison.c"
    break;

  case 264: /* map_block: map_block "type" data_type_expr "colon" map_block_obj_type stmt_separator  */
#line 2045 "parser_bison.y"
                        {
				(yyvsp[-5].set)->key = (yyvsp[-3].expr);
				(yyvsp[-5].set)->objtype = (yyvsp[-1].val);
				(yyvsp[-5].set)->flags  |= NFT_SET_OBJECT;
				(yyval.set) = (yyvsp[-5].set);
			}
#line 9364 "parser_bison.c"
    break;

  case 265: /* map_block: map_block "flags" set_flag_list stmt_separator  */
#line 2052 "parser_bison.y"
                        {
				(yyvsp[-3].set)->flags |= (yyvsp[-1].val);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9373 "parser_bison.c"
    break;

  case 266: /* map_block: map_block stateful_stmt_list stmt_separator  */
#line 2057 "parser_bison.y"
                        {
				list_splice_tail((yyvsp[-1].list), &(yyvsp[-2].set)->stmt_list);
				(yyval.set) = (yyvsp[-2].set);
				free((yyvsp[-1].list));
			}
#line 9383 "parser_bison.c"
    break;

  case 267: /* map_block: map_block "elements" '=' set_block_expr  */
#line 2063 "parser_bison.y"
                        {
				(yyvsp[-3].set)->init = (yyvsp[0].expr);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9392 "parser_bison.c"
    break;

  case 268: /* map_block: map_block comment_spec stmt_separator  */
#line 2068 "parser_bison.y"
                        {
				if (already_set((yyvsp[-2].set)->comment, &(yylsp[-1]), state)) {
					xfree((yyvsp[-1].string));
					YYERROR;
				}
				(yyvsp[-2].set)->comment = (yyvsp[-1].string);
				(yyval.set) = (yyvsp[-2].set);
			}
#line 9405 "parser_bison.c"
    break;

  case 270: /* set_mechanism: "policy" set_policy_spec  */
#line 2080 "parser_bison.y"
                        {
				(yyvsp[-2].set)->policy = (yyvsp[0].val);
			}
#line 9413 "parser_bison.c"
    break;

  case 271: /* set_mechanism: "size" "number"  */
#line 2084 "parser_bison.y"
                        {
				(yyvsp[-2].set)->desc.size = (yyvsp[0].val);
			}
#line 9421 "parser_bison.c"
    break;

  case 272: /* set_policy_spec: "performance"  */
#line 2089 "parser_bison.y"
                                                { (yyval.val) = NFT_SET_POL_PERFORMANCE; }
#line 9427 "parser_bison.c"
    break;

  case 273: /* set_policy_spec: "memory"  */
#line 2090 "parser_bison.y"
                                                { (yyval.val) = NFT_SET_POL_MEMORY; }
#line 9433 "parser_bison.c"
    break;

  case 274: /* flowtable_block_alloc: %empty  */
#line 2094 "parser_bison.y"
                        {
				(yyval.flowtable) = flowtable_alloc(NULL);
			}
#line 9441 "parser_bison.c"
    break;

  case 275: /* flowtable_block: %empty  */
#line 2099 "parser_bison.y"
                                                { (yyval.flowtable) = (yyvsp[(-1) - (0)].flowtable); }
#line 9447 "parser_bison.c"
    break;

  case 278: /* flowtable_block: flowtable_block "hook" "string" prio_spec stmt_separator  */
#line 2103 "parser_bison.y"
                        {
				(yyval.flowtable)->hook.loc = (yylsp[-2]);
				(yyval.flowtable)->hook.name = chain_hookname_lookup((yyvsp[-2].string));
				if ((yyval.flowtable)->hook.name == NULL) {
					erec_queue(error(&(yylsp[-2]), "unknown chain hook"),
						   state->msgs);
					xfree((yyvsp[-2].string));
					YYERROR;
				}
				xfree((yyvsp[-2].string));

				(yyval.flowtable)->priority = (yyvsp[-1].prio_spec);
			}
#line 9465 "parser_bison.c"
    break;

  case 279: /* flowtable_block: flowtable_block "devices" '=' flowtable_expr stmt_separator  */
#line 2117 "parser_bison.y"
                        {
				(yyval.flowtable)->dev_expr = (yyvsp[-1].expr);
			}
#line 9473 "parser_bison.c"
    break;

  case 280: /* flowtable_block: flowtable_block "counter" close_scope_counter  */
#line 2121 "parser_bison.y"
                        {
				(yyval.flowtable)->flags |= NFT_FLOWTABLE_COUNTER;
			}
#line 9481 "parser_bison.c"
    break;

  case 281: /* flowtable_block: flowtable_block "flags" "offload" stmt_separator  */
#line 2125 "parser_bison.y"
                        {
				(yyval.flowtable)->flags |= FLOWTABLE_F_HW_OFFLOAD;
			}
#line 9489 "parser_bison.c"
    break;

  case 282: /* flowtable_expr: '{' flowtable_list_expr '}'  */
#line 2131 "parser_bison.y"
                        {
				(yyvsp[-1].expr)->location = (yyloc);
				(yyval.expr) = (yyvsp[-1].expr);
			}
#line 9498 "parser_bison.c"
    break;

  case 283: /* flowtable_expr: variable_expr  */
#line 2136 "parser_bison.y"
                        {
				(yyvsp[0].expr)->location = (yyloc);
				(yyval.expr) = (yyvsp[0].expr);
			}
#line 9507 "parser_bison.c"
    break;

  case 284: /* flowtable_list_expr: flowtable_expr_member  */
#line 2143 "parser_bison.y"
                        {
				(yyval.expr) = compound_expr_alloc(&(yyloc), EXPR_LIST);
				compound_expr_add((yyval.expr), (yyvsp[0].expr));
			}
#line 9516 "parser_bison.c"
    break;

  case 285: /* flowtable_list_expr: flowtable_list_expr "comma" flowtable_expr_member  */
#line 2148 "parser_bison.y"
                        {
				compound_expr_add((yyvsp[-2].expr), (yyvsp[0].expr));
				(yyval.expr) = (yyvsp[-2].expr);
			}
#line 9525 "parser_bison.c"
    break;

  case 287: /* flowtable_expr_member: "quoted string"  */
#line 2156 "parser_bison.y"
                        {
				(yyval.expr) = constant_expr_alloc(&(yyloc), &string_type,
							 BYTEORDER_HOST_ENDIAN,
							 strlen((yyvsp[0].string)) * BITS_PER_BYTE, (yyvsp[0].string));
				xfree((yyvsp[0].string));
			}
#line 9536 "parser_bison.c"
    break;

  case 288: /* flowtable_expr_member: "string"  */
#line 2163 "parser_bison.y"
                        {
				(yyval.expr) = constant_expr_alloc(&(yyloc), &string_type,
							 BYTEORDER_HOST_ENDIAN,
							 strlen((yyvsp[0].string)) * BITS_PER_BYTE, (yyvsp[0].string));
				xfree((yyvsp[0].string));
			}
#line 9547 "parser_bison.c"
    break;

  case 289: /* flowtable_expr_member: variable_expr  */
#line 2170 "parser_bison.y"
                        {
				datatype_set((yyvsp[0].expr)->sym->expr, &ifname_type);
				(yyval.expr) = (yyvsp[0].expr);
			}
#line 9556 "parser_bison.c"
    break;

  case 290: /* data_type_atom_expr: type_identifier  */
#line 2177 "parser_bison.y"
                        {
				const struct datatype *dtype = datatype_lookup_byname((yyvsp[0].string));
				if (dtype == NULL) {
					erec_queue(error(&(yylsp[0]), "unknown datatype %s", (yyvsp[0].string)),
						   state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyval.expr) = constant_expr_alloc(&(yylsp[0]), dtype, dtype->byteorder,
							 dtype->size, NULL);
				xfree((yyvsp[0].string));
			}
#line 9573 "parser_bison.c"
    break;

  case 291: /* data_type_atom_expr: "time"  */
#line 2190 "parser_bison.y"
                        {
				(yyval.expr) = constant_expr_alloc(&(yylsp[0]), &time_type, time_type.byteorder,
							 time_type.size, NULL);
			}
#line 9582 "parser_bison.c"
    break;

  case 293: /* data_type_expr: data_type_expr "." data_type_atom_expr  */
#line 2198 "parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 9595 "parser_bison.c"
    break;

  case 294: /* obj_block_alloc: %empty  */
#line 2209 "parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(NULL);
			}
#line 9603 "parser_bison.c"
    break;

  case 295: /* counter_block: %empty  */
#line 2214 "parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9609 "parser_bison.c"
    break;

  case 298: /* counter_block: counter_block counter_config  */
#line 2218 "parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9617 "parser_bison.c"
    break;

  case 299: /* counter_block: counter_block comment_spec  */
#line 2222 "parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9629 "parser_bison.c"
    break;

  case 300: /* quota_block: %empty  */
#line 2231 "parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9635 "parser_bison.c"
    break;

  case 303: /* quota_block: quota_block quota_config  */
#line 2235 "parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9643 "parser_bison.c"
    break;

  case 304: /* quota_block: quota_block comment_spec  */
#line 2239 "parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9655 "parser_bison.c"
    break;

  case 305: /* ct_helper_block: %empty  */
#line 2248 "parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9661 "parser_bison.c"
    break;

  case 308: /* ct_helper_block: ct_helper_block ct_helper_config  */
#line 2252 "parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9669 "parser_bison.c"
    break;

  case 309: /* ct_helper_block: ct_helper_block comment_spec  */
#line 2256 "parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9681 "parser_bison.c"
    break;

  case 310: /* ct_timeout_block: %empty  */
#line 2266 "parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[(-1) - (0)].obj);
				init_list_head(&(yyval.obj)->ct_timeout.timeout_list);
			}
#line 9690 "parser_bison.c"
    break;

  case 313: /* ct_timeout_block: ct_timeout_block ct_timeout_config  */
#line 2273 "parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9698 "parser_bison.c"
    break;

  case 314: /* ct_timeout_block: ct_timeout_block comment_spec  */
#line 2277 "parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9710 "parser_bison.c"
    break;

  case 315: /* ct_expect_block: %empty  */
#line 2286 "parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9716 "parser_bison.c"
    break;

  case 318: /* ct_expect_block: ct_expect_block ct_expect_config  */
#line 2290 "parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9724 "parser_bison.c"
    break;

  case 319: /* ct_expect_block: ct_expect_block comment_spec  */
#line 2294 "parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9736 "parser_bison.c"
    break;

  case 320: /* limit_block: %empty  */
#line 2303 "parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9742 "parser_bison.c"
    break;

  case 323: /* limit_block: limit_block limit_config  */
#line 2307 "parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9750 "parser_bison.c"
    break;

  case 324: /* limit_block: limit_block comment_spec  */
#line 2311 "parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9762 "parser_bison.c"
    break;

  case 325: /* secmark_block: %empty  */
#line 2320 "parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9768 "parser_bison.c"
    break;

  case 328: /* secmark_block: secmark_block secmark_config  */
#line 2324 "parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9776 "parser_bison.c"
    break;

  case 329: /* secmark_block: secmark_block comment_spec  */
#line 2328 "parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9788 "parser_bison.c"
    break;

  case 330: /* synproxy_block: %empty  */
#line 2337 "parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9794 "parser_bison.c"
    break;

  case 333: /* synproxy_block: synproxy_block synproxy_config  */
#line 2341 "parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9802 "parser_bison.c"
    break;

  case 334: /* synproxy_block: synproxy_block comment_spec  */
#line 2345 "parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9814 "parser_bison.c"
    break;

  case 335: /* type_identifier: "string"  */
#line 2354 "parser_bison.y"
                                        { (yyval.string) = (yyvsp[0].string); }
#line 9820 "parser_bison.c"
    break;

  case 336: /* type_identifier: "mark"  */
#line 2355 "parser_bison.y"
                                        { (yyval.string) = xstrdup("mark"); }
#line 9826 "parser_bison.c"
    break;

  case 337: /* type_identifier: "dscp"  */
#line 2356 "parser_bison.y"
                                        { (yyval.string) = xstrdup("dscp"); }
#line 9832 "parser_bison.c"
    break;

  case 338: /* type_identifier: "ecn"  */
#line 2357 "parser_bison.y"
                                        { (yyval.string) = xstrdup("ecn"); }
#line 9838 "parser_bison.c"
    break;

  case 339: /* type_identifier: "classid"  */
#line 2358 "parser_bison.y"
                                        { (yyval.string) = xstrdup("classid"); }
#line 9844 "parser_bison.c"
    break;

  case 340: /* hook_spec: "type" "string" "hook" "string" dev_spec prio_spec  */
#line 2362 "parser_bison.y"
                        {
				const char *chain_type = chain_type_name_lookup((yyvsp[-4].string));

				if (chain_type == NULL) {
					erec_queue(error(&(yylsp[-4]), "unknown chain type"),
						   state->msgs);
					xfree((yyvsp[-4].string));
					YYERROR;
				}
				(yyvsp[-6].chain)->type.loc = (yylsp[-4]);
				(yyvsp[-6].chain)->type.str = xstrdup(chain_type);
				xfree((yyvsp[-4].string));

				(yyvsp[-6].chain)->loc = (yyloc);
				(yyvsp[-6].chain)->hook.loc = (yylsp[-2]);
				(yyvsp[-6].chain)->hook.name = chain_hookname_lookup((yyvsp[-2].string));
				if ((yyvsp[-6].chain)->hook.name == NULL) {
					erec_queue(error(&(yylsp[-2]), "unknown chain hook"),
						   state->msgs);
					xfree((yyvsp[-2].string));
					YYERROR;
				}
				xfree((yyvsp[-2].string));

				(yyvsp[-6].chain)->dev_expr	= (yyvsp[-1].expr);
				(yyvsp[-6].chain)->priority	= (yyvsp[0].prio_spec);
				(yyvsp[-6].chain)->flags	|= CHAIN_F_BASECHAIN;
			}
#line 9877 "parser_bison.c"
    break;

  case 341: /* prio_spec: "priority" extended_prio_spec  */
#line 2393 "parser_bison.y"
                        {
				(yyval.prio_spec) = (yyvsp[0].prio_spec);
				(yyval.prio_spec).loc = (yyloc);
			}
#line 9886 "parser_bison.c"
    break;

  case 342: /* extended_prio_name: "out"  */
#line 2400 "parser_bison.y"
                        {
				(yyval.string) = strdup("out");
			}
#line 9894 "parser_bison.c"
    break;

  case 344: /* extended_prio_spec: int_num  */
#line 2407 "parser_bison.y"
                        {
				struct prio_spec spec = {0};

				spec.expr = constant_expr_alloc(&(yyloc), &integer_type,
								BYTEORDER_HOST_ENDIAN,
								sizeof(int) *
								BITS_PER_BYTE, &(yyvsp[0].val32));
				(yyval.prio_spec) = spec;
			}
#line 9908 "parser_bison.c"
    break;

  case 345: /* extended_prio_spec: variable_expr  */
#line 2417 "parser_bison.y"
                        {
				struct prio_spec spec = {0};

				spec.expr = (yyvsp[0].expr);
				(yyval.prio_spec) = spec;
			}
#line 9919 "parser_bison.c"
    break;

  case 346: /* extended_prio_spec: extended_prio_name  */
#line 2424 "parser_bison.y"
                        {
				struct prio_spec spec = {0};

				spec.expr = constant_expr_alloc(&(yyloc), &string_type,
								BYTEORDER_HOST_ENDIAN,
								strlen((yyvsp[0].string)) * BITS_PER_BYTE,
								(yyvsp[0].string));
				xfree((yyvsp[0].string));
				(yyval.prio_spec) = spec;
			}
#line 9934 "parser_bison.c"
    break;

  case 347: /* extended_prio_spec: extended_prio_name "+" "number"  */
#line 2435 "parser_bison.y"
                        {
				struct prio_spec spec = {0};

				char str[NFT_NAME_MAXLEN];
				snprintf(str, sizeof(str), "%s + %" PRIu64, (yyvsp[-2].string), (yyvsp[0].val));
				spec.expr = constant_expr_alloc(&(yyloc), &string_type,
								BYTEORDER_HOST_ENDIAN,
								strlen(str) * BITS_PER_BYTE,
								str);
				xfree((yyvsp[-2].string));
				(yyval.prio_spec) = spec;
			}
#line 9951 "parser_bison.c"
    break;

  case 348: /* extended_prio_spec: extended_prio_name "-" "number"  */
#line 2448 "parser_bison.y"
                        {
				struct prio_spec spec = {0};
				char str[NFT_NAME_MAXLEN];

				snprintf(str, sizeof(str), "%s - %" PRIu64, (yyvsp[-2].string), (yyvsp[0].val));
				spec.expr = constant_expr_alloc(&(yyloc), &string_type,
								BYTEORDER_HOST_ENDIAN,
								strlen(str) * BITS_PER_BYTE,
								str);
				xfree((yyvsp[-2].string));
				(yyval.prio_spec) = spec;
			}
#line 9968 "parser_bison.c"
    break;

  case 349: /* int_num: "number"  */
#line 2462 "parser_bison.y"
                                                        { (yyval.val32) = (yyvsp[0].val); }
#line 9974 "parser_bison.c"
    break;

  case 350: /* int_num: "-" "number"  */
#line 2463 "parser_bison.y"
                                                        { (yyval.val32) = -(yyvsp[0].val); }
#line 9980 "parser_bison.c"
    break;

  case 351: /* dev_spec: "device" string  */
#line 2467 "parser_bison.y"
                        {
				struct expr *expr;

				expr = constant_expr_alloc(&(yyloc), &string_type,
							   BYTEORDER_HOST_ENDIAN,
							   strlen((yyvsp[0].string)) * BITS_PER_BYTE, (yyvsp[0].string));
				xfree((yyvsp[0].string));
				(yyval.expr) = compound_expr_alloc(&(yyloc), EXPR_LIST);
				compound_expr_add((yyval.expr), expr);

			}
#line 9996 "parser_bison.c"
    break;

  case 352: /* dev_spec: "device" variable_expr  */
#line 2479 "parser_bison.y"
                        {
				datatype_set((yyvsp[0].expr)->sym->expr, &ifname_type);
				(yyval.expr) = compound_expr_alloc(&(yyloc), EXPR_LIST);
				compound_expr_add((yyval.expr), (yyvsp[0].expr));
			}
#line 10006 "parser_bison.c"
    break;

  case 353: /* dev_spec: "devices" '=' flowtable_expr  */
#line 2485 "parser_bison.y"
                        {
				(yyval.expr) = (yyvsp[0].expr);
			}
#line 10014 "parser_bison.c"
    break;

  case 354: /* dev_spec: %empty  */
#line 2488 "parser_bison.y"
                                                        { (yyval.expr) = NULL; }
#line 10020 "parser_bison.c"
    break;

  case 355: /* flags_spec: "flags" "offload"  */
#line 2492 "parser_bison.y"
                        {
				(yyvsp[-2].chain)->flags |= CHAIN_F_HW_OFFLOAD;
			}
#line 10028 "parser_bison.c"
    break;

  case 356: /* policy_spec: "policy" policy_expr  */
#line 2498 "parser_bison.y"
                        {
				if ((yyvsp[-2].chain)->policy) {
					erec_queue(error(&(yyloc), "you cannot set chain policy twice"),
						   state->msgs);
					expr_free((yyvsp[0].expr));
					YYERROR;
				}
				(yyvsp[-2].chain)->policy		= (yyvsp[0].expr);
				(yyvsp[-2].chain)->policy->location	= (yyloc);
			}
#line 10043 "parser_bison.c"
    break;

  case 357: /* policy_expr: variable_expr  */
#line 2511 "parser_bison.y"
                        {
				datatype_set((yyvsp[0].expr)->sym->expr, &policy_type);
				(yyval.expr) = (yyvsp[0].expr);
			}
#line 10052 "parser_bison.c"
    break;

  case 358: /* policy_expr: chain_policy  */
#line 2516 "parser_bison.y"
                        {
				(yyval.expr) = constant_expr_alloc(&(yyloc), &integer_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(int) *
							 BITS_PER_BYTE, &(yyvsp[0].val32));
			}
#line 10063 "parser_bison.c"
    break;

  case 359: /* chain_policy: "accept"  */
#line 2524 "parser_bison.y"
                                                { (yyval.val32) = NF_ACCEPT; }
#line 10069 "parser_bison.c"
    break;

  case 360: /* chain_policy: "drop"  */
#line 2525 "parser_bison.y"
                                                { (yyval.val32) = NF_DROP;   }
#line 10075 "parser_bison.c"
    break;

  case 365: /* time_spec: "string"  */
#line 2537 "parser_bison.y"
                        {
				struct error_record *erec;
				uint64_t res;

				erec = time_parse(&(yylsp[0]), (yyvsp[0].string), &res);
				xfree((yyvsp[0].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}
				(yyval.val) = res;
			}
#line 10092 "parser_bison.c"
    break;

  case 366: /* family_spec: %empty  */
#line 2551 "parser_bison.y"
                                                        { (yyval.val) = NFPROTO_IPV4; }
#line 10098 "parser_bison.c"
    break;

  case 368: /* family_spec_explicit: "ip" close_scope_ip  */
#line 2555 "parser_bison.y"
                                                        { (yyval.val) = NFPROTO_IPV4; }
#line 10104 "parser_bison.c"
    break;

  case 369: /* family_spec_explicit: "ip6" close_scope_ip6  */
#line 2556 "parser_bison.y"
                                                        { (yyval.val) = NFPROTO_IPV6; }
#line 10110 "parser_bison.c"
    break;

  case 370: /* family_spec_explicit: "inet"  */
#line 2557 "parser_bison.y"
                                                        { (yyval.val) = NFPROTO_INET; }
#line 10116 "parser_bison.c"
    break;

  case 371: /* family_spec_explicit: "arp" close_scope_arp  */
#line 2558 "parser_bison.y"
                                                        { (yyval.val) = NFPROTO_ARP; }
#line 10122 "parser_bison.c"
    break;

  case 372: /* family_spec_explicit: "bridge"  */
#line 2559 "parser_bison.y"
                                                        { (yyval.val) = NFPROTO_BRIDGE; }
#line 10128 "parser_bison.c"
    break;

  case 373: /* family_spec_explicit: "netdev"  */
#line 2560 "parser_bison.y"
                                                        { (yyval.val) = NFPROTO_NETDEV; }
#line 10134 "parser_bison.c"
    break;

  case 374: /* table_spec: family_spec identifier  */
#line 2564 "parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).family	= (yyvsp[-1].val);
				(yyval.handle).table.location = (yylsp[0]);
				(yyval.handle).table.name	= (yyvsp[0].string);
			}
#line 10145 "parser_bison.c"
    break;

  case 375: /* tableid_spec: family_spec "handle" "number"  */
#line 2573 "parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).family 		= (yyvsp[-2].val);
				(yyval.handle).handle.id 		= (yyvsp[0].val);
				(yyval.handle).handle.location	= (yylsp[0]);
			}
#line 10156 "parser_bison.c"
    break;

  case 376: /* chain_spec: table_spec identifier  */
#line 2582 "parser_bison.y"
                        {
				(yyval.handle)		= (yyvsp[-1].handle);
				(yyval.handle).chain.name	= (yyvsp[0].string);
				(yyval.handle).chain.location = (yylsp[0]);
			}
#line 10166 "parser_bison.c"
    break;

  case 377: /* chainid_spec: table_spec "handle" "number"  */
#line 2590 "parser_bison.y"
                        {
				(yyval.handle) 			= (yyvsp[-2].handle);
				(yyval.handle).handle.location 	= (yylsp[0]);
				(yyval.handle).handle.id 		= (yyvsp[0].val);
			}
#line 10176 "parser_bison.c"
    break;

  case 378: /* chain_identifier: identifier  */
#line 2598 "parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).chain.name		= (yyvsp[0].string);
				(yyval.handle).chain.location	= (yylsp[0]);
			}
#line 10186 "parser_bison.c"
    break;

  case 379: /* set_spec: table_spec identifier  */
#line 2606 "parser_bison.y"
                        {
				(yyval.handle)		= (yyvsp[-1].handle);
				(yyval.handle).set.name	= (yyvsp[0].string);
				(yyval.handle).set.location	= (yylsp[0]);
			}
#line 10196 "parser_bison.c"
    break;

  case 380: /* setid_spec: table_spec "handle" "number"  */
#line 2614 "parser_bison.y"
                        {
				(yyval.handle) 			= (yyvsp[-2].handle);
				(yyval.handle).handle.location 	= (yylsp[0]);
				(yyval.handle).handle.id 		= (yyvsp[0].val);
			}
#line 10206 "parser_bison.c"
    break;

  case 381: /* set_identifier: identifier  */
#line 2622 "parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).set.name	= (yyvsp[0].string);
				(yyval.handle).set.location	= (yylsp[0]);
			}
#line 10216 "parser_bison.c"
    break;

  case 382: /* flowtable_spec: table_spec identifier  */
#line 2630 "parser_bison.y"
                        {
				(yyval.handle)			= (yyvsp[-1].handle);
				(yyval.handle).flowtable.name	= (yyvsp[0].string);
				(yyval.handle).flowtable.location	= (yylsp[0]);
			}
#line 10226 "parser_bison.c"
    break;

  case 383: /* flowtableid_spec: table_spec "handle" "number"  */
#line 2638 "parser_bison.y"
                        {
				(yyval.handle)			= (yyvsp[-2].handle);
				(yyval.handle).handle.location	= (yylsp[0]);
				(yyval.handle).handle.id		= (yyvsp[0].val);
			}
#line 10236 "parser_bison.c"
    break;

  case 384: /* flowtable_identifier: identifier  */
#line 2646 "parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).flowtable.name	= (yyvsp[0].string);
				(yyval.handle).flowtable.location	= (yylsp[0]);
			}
#line 10246 "parser_bison.c"
    break;

  case 385: /* obj_spec: table_spec identifier  */
#line 2654 "parser_bison.y"
                        {
				(yyval.handle)		= (yyvsp[-1].handle);
				(yyval.handle).obj.name	= (yyvsp[0].string);
				(yyval.handle).obj.location	= (yylsp[0]);
			}
#line 10256 "parser_bison.c"
    break;

  case 386: /* objid_spec: table_spec "handle" "number"  */
#line 2662 "parser_bison.y"
                        {
				(yyval.handle) 			= (yyvsp[-2].handle);
				(yyval.handle).handle.location	= (yylsp[0]);
				(yyval.handle).handle.id		= (yyvsp[0].val);
			}
#line 10266 "parser_bison.c"
    break;

  case 387: /* obj_identifier: identifier  */
#line 2670 "parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).obj.name		= (yyvsp[0].string);
				(yyval.handle).obj.location		= (yylsp[0]);
			}
#line 10276 "parser_bison.c"
    break;

  case 388: /* handle_spec: "handle" "number"  */
#line 2678 "parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).handle.location	= (yylsp[0]);
				(yyval.handle).handle.id		= (yyvsp[0].val);
			}
#line 10286 "parser_bison.c"
    break;

  case 389: /* position_spec: "position" "number"  */
#line 2686 "parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).position.location	= (yyloc);
				(yyval.handle).position.id		= (yyvsp[0].val);
			}
#line 10296 "parser_bison.c"
    break;

  case 390: /* index_spec: "index" "number"  */
#line 2694 "parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).index.location	= (yyloc);
				(yyval.handle).index.id		= (yyvsp[0].val) + 1;
			}
#line 10306 "parser_bison.c"
    break;

  case 391: /* rule_position: chain_spec  */
#line 2702 "parser_bison.y"
                        {
				(yyval.handle) = (yyvsp[0].handle);
			}
#line 10314 "parser_bison.c"
    break;

  case 392: /* rule_position: chain_spec position_spec  */
#line 2706 "parser_bison.y"
                        {
				handle_merge(&(yyvsp[-1].handle), &(yyvsp[0].handle));
				(yyval.handle) = (yyvsp[-1].handle);
			}
#line 10323 "parser_bison.c"
    break;

  case 393: /* rule_position: chain_spec handle_spec  */
#line 2711 "parser_bison.y"
                        {
				(yyvsp[0].handle).position.location = (yyvsp[0].handle).handle.location;
				(yyvsp[0].handle).position.id = (yyvsp[0].handle).handle.id;
				(yyvsp[0].handle).handle.id = 0;
				handle_merge(&(yyvsp[-1].handle), &(yyvsp[0].handle));
				(yyval.handle) = (yyvsp[-1].handle);
			}
#line 10335 "parser_bison.c"
    break;

  case 394: /* rule_position: chain_spec index_spec  */
#line 2719 "parser_bison.y"
                        {
				handle_merge(&(yyvsp[-1].handle), &(yyvsp[0].handle));
				(yyval.handle) = (yyvsp[-1].handle);
			}
#line 10344 "parser_bison.c"
    break;

  case 395: /* ruleid_spec: chain_spec handle_spec  */
#line 2726 "parser_bison.y"
                        {
				handle_merge(&(yyvsp[-1].handle), &(yyvsp[0].handle));
				(yyval.handle) = (yyvsp[-1].handle);
			}
#line 10353 "parser_bison.c"
    break;

  case 396: /* comment_spec: "comment" string  */
#line 2733 "parser_bison.y"
                        {
				if (strlen((yyvsp[0].string)) > NFTNL_UDATA_COMMENT_MAXLEN) {
					erec_queue(error(&(yylsp[0]), "comment too long, %d characters maximum allowed",
							 NFTNL_UDATA_COMMENT_MAXLEN),
						   state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyval.string) = (yyvsp[0].string);
			}
#line 10368 "parser_bison.c"
    break;

  case 397: /* ruleset_spec: %empty  */
#line 2746 "parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).family	= NFPROTO_UNSPEC;
			}
#line 10377 "parser_bison.c"
    break;

  case 398: /* ruleset_spec: family_spec_explicit  */
#line 2751 "parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).family	= (yyvsp[0].val);
			}
#line 10386 "parser_bison.c"
    break;

  case 399: /* rule: rule_alloc  */
#line 2758 "parser_bison.y"
                        {
				(yyval.rule)->comment = NULL;
			}
#line 10394 "parser_bison.c"
    break;

  case 400: /* rule: rule_alloc comment_spec  */
#line 2762 "parser_bison.y"
                        {
				(yyval.rule)->comment = (yyvsp[0].string);
			}
#line 10402 "parser_bison.c"
    break;

  case 401: /* rule_alloc: stmt_list  */
#line 2768 "parser_bison.y"
                        {
				struct stmt *i;

				(yyval.rule) = rule_alloc(&(yyloc), NULL);
				list_for_each_entry(i, (yyvsp[0].list), list)
					(yyval.rule)->num_stmts++;
				list_splice_tail((yyvsp[0].list), &(yyval.rule)->stmts);
				xfree((yyvsp[0].list));
			}
#line 10416 "parser_bison.c"
    break;

  case 402: /* stmt_list: stmt  */
#line 2780 "parser_bison.y"
                        {
				(yyval.list) = xmalloc(sizeof(*(yyval.list)));
				init_list_head((yyval.list));
				list_add_tail(&(yyvsp[0].stmt)->list, (yyval.list));
			}
#line 10426 "parser_bison.c"
    break;

  case 403: /* stmt_list: stmt_list stmt  */
#line 2786 "parser_bison.y"
                        {
				(yyval.list) = (yyvsp[-1].list);
				list_add_tail(&(yyvsp[0].stmt)->list, (yyvsp[-1].list));
			}
#line 10435 "parser_bison.c"
    break;

  case 404: /* stateful_stmt_list: stateful_stmt  */
#line 2793 "parser_bison.y"
                        {
				(yyval.list) = xmalloc(sizeof(*(yyval.list)));
				init_list_head((yyval.list));
				list_add_tail(&(yyvsp[0].stmt)->list, (yyval.list));
			}
#line 10445 "parser_bison.c"
    break;

  case 405: /* stateful_stmt_list: stateful_stmt_list stateful_stmt  */
#line 2799 "parser_bison.y"
                        {
				(yyval.list) = (yyvsp[-1].list);
				list_add_tail(&(yyvsp[0].stmt)->list, (yyvsp[-1].list));
			}
#line 10454 "parser_bison.c"
    break;

  case 430: /* chain_stmt_type: "jump"  */
#line 2833 "parser_bison.y"
                                        { (yyval.val) = NFT_JUMP; }
#line 10460 "parser_bison.c"
    break;

  case 431: /* chain_stmt_type: "goto"  */
#line 2834 "parser_bison.y"
                                        { (yyval.val) = NFT_GOTO; }
#line 10466 "parser_bison.c"
    break;

  case 432: /* chain_stmt: chain_stmt_type chain_block_alloc '{' subchain_block '}'  */
#line 2838 "parser_bison.y"
                        {
				(yyvsp[-3].chain)->location = (yylsp[-3]);
				close_scope(state);
				(yyvsp[-1].chain)->location = (yylsp[-1]);
				(yyval.stmt) = chain_stmt_alloc(&(yyloc), (yyvsp[-1].chain), (yyvsp[-4].val));
			}
#line 10477 "parser_bison.c"
    break;

  case 433: /* verdict_stmt: verdict_expr  */
#line 2847 "parser_bison.y"
                        {
				(yyval.stmt) = verdict_stmt_alloc(&(yyloc), (yyvsp[0].expr));
			}
#line 10485 "parser_bison.c"
    break;

  case 434: /* verdict_stmt: verdict_map_stmt  */
#line 2851 "parser_bison.y"
                        {
				(yyval.stmt) = verdict_stmt_alloc(&(yyloc), (yyvsp[0].expr));
			}
#line 10493 "parser_bison.c"
    break;

  case 435: /* verdict_map_stmt: concat_expr "vmap" verdict_map_expr  */
#line 2857 "parser_bison.y"
                        {
				(yyval.expr) = map_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 10501 "parser_bison.c"
    break;

  case 436: /* verdict_map_expr: '{' verdict_map_list_expr '}'  */
#line 2863 "parser_bison.y"
                        {
				(yyvsp[-1].expr)->location = (yyloc);
				(yyval.expr) = (yyvsp[-1].expr);
			}
#line 10510 "parser_bison.c"
    break;

  case 438: /* verdict_map_list_expr: verdict_map_list_member_expr  */
#line 2871 "parser_bison.y"
                        {
				(yyval.expr) = set_expr_alloc(&(yyloc), NULL);
				compound_expr_add((yyval.expr), (yyvsp[0].expr));
			}
#line 10519 "parser_bison.c"
    break;

  case 439: /* verdict_map_list_expr: verdict_map_list_expr "comma" verdict_map_list_member_expr  */
#line 2876 "parser_bison.y"
                        {
				compound_expr_add((yyvsp[-2].expr), (yyvsp[0].expr));
				(yyval.expr) = (yyvsp[-2].expr);
			}
#line 10528 "parser_bison.c"
    break;

  case 441: /* verdict_map_list_member_expr: opt_newline set_elem_expr "colon" verdict_expr opt_newline  */
#line 2884 "parser_bison.y"
                        {
				(yyval.expr) = mapping_expr_alloc(&(yyloc), (yyvsp[-3].expr), (yyvsp[-1].expr));
			}
#line 10536 "parser_bison.c"
    break;

  case 442: /* connlimit_stmt: "ct" "count" "number" close_scope_ct  */
#line 2890 "parser_bison.y"
                        {
				(yyval.stmt) = connlimit_stmt_alloc(&(yyloc));
				(yyval.stmt)->connlimit.count	= (yyvsp[-1].val);
			}
#line 10545 "parser_bison.c"
    break;

  case 443: /* connlimit_stmt: "ct" "count" "over" "number" close_scope_ct  */
#line 2895 "parser_bison.y"
                        {
				(yyval.stmt) = connlimit_stmt_alloc(&(yyloc));
				(yyval.stmt)->connlimit.count = (yyvsp[-1].val);
				(yyval.stmt)->connlimit.flags = NFT_CONNLIMIT_F_INV;
			}
#line 10555 "parser_bison.c"
    break;

  case 446: /* counter_stmt_alloc: "counter"  */
#line 2906 "parser_bison.y"
                        {
				(yyval.stmt) = counter_stmt_alloc(&(yyloc));
			}
#line 10563 "parser_bison.c"
    break;

  case 447: /* counter_stmt_alloc: "counter" "name" stmt_expr  */
#line 2910 "parser_bison.y"
                        {
				(yyval.stmt) = objref_stmt_alloc(&(yyloc));
				(yyval.stmt)->objref.type = NFT_OBJECT_COUNTER;
				(yyval.stmt)->objref.expr = (yyvsp[0].expr);
			}
#line 10573 "parser_bison.c"
    break;

  case 448: /* counter_args: counter_arg  */
#line 2918 "parser_bison.y"
                        {
				(yyval.stmt)	= (yyvsp[-1].stmt);
			}
#line 10581 "parser_bison.c"
    break;

  case 450: /* counter_arg: "packets" "number"  */
#line 2925 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->counter.packets = (yyvsp[0].val);
			}
#line 10589 "parser_bison.c"
    break;

  case 451: /* counter_arg: "bytes" "number"  */
#line 2929 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->counter.bytes	 = (yyvsp[0].val);
			}
#line 10597 "parser_bison.c"
    break;

  case 454: /* log_stmt_alloc: "log"  */
#line 2939 "parser_bison.y"
                        {
				(yyval.stmt) = log_stmt_alloc(&(yyloc));
			}
#line 10605 "parser_bison.c"
    break;

  case 455: /* log_args: log_arg  */
#line 2945 "parser_bison.y"
                        {
				(yyval.stmt)	= (yyvsp[-1].stmt);
			}
#line 10613 "parser_bison.c"
    break;

  case 457: /* log_arg: "prefix" string  */
#line 2952 "parser_bison.y"
                        {
				struct scope *scope = current_scope(state);
				bool done = false, another_var = false;
				char *start, *end, scratch = '\0';
				struct expr *expr, *item;
				struct symbol *sym;
				enum {
					PARSE_TEXT,
					PARSE_VAR,
				} prefix_state;

				/* No variables in log prefix, skip. */
				if (!strchr((yyvsp[0].string), '$')) {
					expr = constant_expr_alloc(&(yyloc), &string_type,
								   BYTEORDER_HOST_ENDIAN,
								   (strlen((yyvsp[0].string)) + 1) * BITS_PER_BYTE, (yyvsp[0].string));
					xfree((yyvsp[0].string));
					(yyvsp[-2].stmt)->log.prefix = expr;
					(yyvsp[-2].stmt)->log.flags |= STMT_LOG_PREFIX;
					break;
				}

				/* Parse variables in log prefix string using a
				 * state machine parser with two states. This
				 * parser creates list of expressions composed
				 * of constant and variable expressions.
				 */
				expr = compound_expr_alloc(&(yyloc), EXPR_LIST);

				start = (char *)(yyvsp[0].string);

				if (*start != '$') {
					prefix_state = PARSE_TEXT;
				} else {
					prefix_state = PARSE_VAR;
					start++;
				}
				end = start;

				/* Not nice, but works. */
				while (!done) {
					switch (prefix_state) {
					case PARSE_TEXT:
						while (*end != '\0' && *end != '$')
							end++;

						if (*end == '\0')
							done = true;

						*end = '\0';
						item = constant_expr_alloc(&(yyloc), &string_type,
									   BYTEORDER_HOST_ENDIAN,
									   (strlen(start) + 1) * BITS_PER_BYTE,
									   start);
						compound_expr_add(expr, item);

						if (done)
							break;

						start = end + 1;
						end = start;

						/* fall through */
					case PARSE_VAR:
						while (isalnum(*end) || *end == '_')
							end++;

						if (*end == '\0')
							done = true;
						else if (*end == '$')
							another_var = true;
						else
							scratch = *end;

						*end = '\0';

						sym = symbol_get(scope, start);
						if (!sym) {
							sym = symbol_lookup_fuzzy(scope, start);
							if (sym) {
								erec_queue(error(&(yylsp[0]), "unknown identifier '%s'; "
										 "did you mean identifier ‘%s’?",
										 start, sym->identifier),
									   state->msgs);
							} else {
								erec_queue(error(&(yylsp[0]), "unknown identifier '%s'",
										 start),
									   state->msgs);
							}
							expr_free(expr);
							xfree((yyvsp[0].string));
							YYERROR;
						}
						item = variable_expr_alloc(&(yyloc), scope, sym);
						compound_expr_add(expr, item);

						if (done)
							break;

						/* Restore original byte after
						 * symbol lookup.
						 */
						if (scratch) {
							*end = scratch;
							scratch = '\0';
						}

						start = end;
						if (another_var) {
							another_var = false;
							start++;
							prefix_state = PARSE_VAR;
						} else {
							prefix_state = PARSE_TEXT;
						}
						end = start;
						break;
					}
				}

				xfree((yyvsp[0].string));
				(yyvsp[-2].stmt)->log.prefix	 = expr;
				(yyvsp[-2].stmt)->log.flags 	|= STMT_LOG_PREFIX;
			}
#line 10742 "parser_bison.c"
    break;

  case 458: /* log_arg: "group" "number"  */
#line 3077 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->log.group	 = (yyvsp[0].val);
				(yyvsp[-2].stmt)->log.flags 	|= STMT_LOG_GROUP;
			}
#line 10751 "parser_bison.c"
    break;

  case 459: /* log_arg: "snaplen" "number"  */
#line 3082 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->log.snaplen	 = (yyvsp[0].val);
				(yyvsp[-2].stmt)->log.flags 	|= STMT_LOG_SNAPLEN;
			}
#line 10760 "parser_bison.c"
    break;

  case 460: /* log_arg: "queue-threshold" "number"  */
#line 3087 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->log.qthreshold = (yyvsp[0].val);
				(yyvsp[-2].stmt)->log.flags 	|= STMT_LOG_QTHRESHOLD;
			}
#line 10769 "parser_bison.c"
    break;

  case 461: /* log_arg: "level" level_type  */
#line 3092 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->log.level	= (yyvsp[0].val);
				(yyvsp[-2].stmt)->log.flags 	|= STMT_LOG_LEVEL;
			}
#line 10778 "parser_bison.c"
    break;

  case 462: /* log_arg: "flags" log_flags  */
#line 3097 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->log.logflags	|= (yyvsp[0].val);
			}
#line 10786 "parser_bison.c"
    break;

  case 463: /* level_type: string  */
#line 3103 "parser_bison.y"
                        {
				if (!strcmp("emerg", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_EMERG;
				else if (!strcmp("alert", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_ALERT;
				else if (!strcmp("crit", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_CRIT;
				else if (!strcmp("err", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_ERR;
				else if (!strcmp("warn", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_WARNING;
				else if (!strcmp("notice", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_NOTICE;
				else if (!strcmp("info", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_INFO;
				else if (!strcmp("debug", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_DEBUG;
				else if (!strcmp("audit", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_AUDIT;
				else {
					erec_queue(error(&(yylsp[0]), "invalid log level"),
						   state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
				xfree((yyvsp[0].string));
			}
#line 10818 "parser_bison.c"
    break;

  case 464: /* log_flags: "tcp" log_flags_tcp close_scope_tcp  */
#line 3133 "parser_bison.y"
                        {
				(yyval.val) = (yyvsp[-1].val);
			}
#line 10826 "parser_bison.c"
    break;

  case 465: /* log_flags: "ip" "options" close_scope_ip  */
#line 3137 "parser_bison.y"
                        {
				(yyval.val) = NF_LOG_IPOPT;
			}
#line 10834 "parser_bison.c"
    break;

  case 466: /* log_flags: "skuid"  */
#line 3141 "parser_bison.y"
                        {
				(yyval.val) = NF_LOG_UID;
			}
#line 10842 "parser_bison.c"
    break;

  case 467: /* log_flags: "ether" close_scope_eth  */
#line 3145 "parser_bison.y"
                        {
				(yyval.val) = NF_LOG_MACDECODE;
			}
#line 10850 "parser_bison.c"
    break;

  case 468: /* log_flags: "all"  */
#line 3149 "parser_bison.y"
                        {
				(yyval.val) = NF_LOG_MASK;
			}
#line 10858 "parser_bison.c"
    break;

  case 469: /* log_flags_tcp: log_flags_tcp "comma" log_flag_tcp  */
#line 3155 "parser_bison.y"
                        {
				(yyval.val) = (yyvsp[-2].val) | (yyvsp[0].val);
			}
#line 10866 "parser_bison.c"
    break;

  case 471: /* log_flag_tcp: "seq"  */
#line 3162 "parser_bison.y"
                        {
				(yyval.val) = NF_LOG_TCPSEQ;
			}
#line 10874 "parser_bison.c"
    break;

  case 472: /* log_flag_tcp: "options"  */
#line 3166 "parser_bison.y"
                        {
				(yyval.val) = NF_LOG_TCPOPT;
			}
#line 10882 "parser_bison.c"
    break;

  case 473: /* limit_stmt: "limit" "rate" limit_mode limit_rate_pkts limit_burst_pkts close_scope_limit  */
#line 3172 "parser_bison.y"
                        {
				if ((yyvsp[-1].val) == 0) {
					erec_queue(error(&(yylsp[-1]), "limit burst must be > 0"),
						   state->msgs);
					YYERROR;
				}
				(yyval.stmt) = limit_stmt_alloc(&(yyloc));
				(yyval.stmt)->limit.rate	= (yyvsp[-2].limit_rate).rate;
				(yyval.stmt)->limit.unit	= (yyvsp[-2].limit_rate).unit;
				(yyval.stmt)->limit.burst	= (yyvsp[-1].val);
				(yyval.stmt)->limit.type	= NFT_LIMIT_PKTS;
				(yyval.stmt)->limit.flags = (yyvsp[-3].val);
			}
#line 10900 "parser_bison.c"
    break;

  case 474: /* limit_stmt: "limit" "rate" limit_mode limit_rate_bytes limit_burst_bytes close_scope_limit  */
#line 3186 "parser_bison.y"
                        {
				if ((yyvsp[-1].val) == 0) {
					erec_queue(error(&(yylsp[-1]), "limit burst must be > 0"),
						   state->msgs);
					YYERROR;
				}
				(yyval.stmt) = limit_stmt_alloc(&(yyloc));
				(yyval.stmt)->limit.rate	= (yyvsp[-2].limit_rate).rate;
				(yyval.stmt)->limit.unit	= (yyvsp[-2].limit_rate).unit;
				(yyval.stmt)->limit.burst	= (yyvsp[-1].val);
				(yyval.stmt)->limit.type	= NFT_LIMIT_PKT_BYTES;
				(yyval.stmt)->limit.flags = (yyvsp[-3].val);
			}
#line 10918 "parser_bison.c"
    break;

  case 475: /* limit_stmt: "limit" "name" stmt_expr close_scope_limit  */
#line 3200 "parser_bison.y"
                        {
				(yyval.stmt) = objref_stmt_alloc(&(yyloc));
				(yyval.stmt)->objref.type = NFT_OBJECT_LIMIT;
				(yyval.stmt)->objref.expr = (yyvsp[-1].expr);
			}
#line 10928 "parser_bison.c"
    break;

  case 476: /* quota_mode: "over"  */
#line 3207 "parser_bison.y"
                                                { (yyval.val) = NFT_QUOTA_F_INV; }
#line 10934 "parser_bison.c"
    break;

  case 477: /* quota_mode: "until"  */
#line 3208 "parser_bison.y"
                                                { (yyval.val) = 0; }
#line 10940 "parser_bison.c"
    break;

  case 478: /* quota_mode: %empty  */
#line 3209 "parser_bison.y"
                                                { (yyval.val) = 0; }
#line 10946 "parser_bison.c"
    break;

  case 479: /* quota_unit: "bytes"  */
#line 3212 "parser_bison.y"
                                                { (yyval.string) = xstrdup("bytes"); }
#line 10952 "parser_bison.c"
    break;

  case 480: /* quota_unit: "string"  */
#line 3213 "parser_bison.y"
                                                { (yyval.string) = (yyvsp[0].string); }
#line 10958 "parser_bison.c"
    break;

  case 481: /* quota_used: %empty  */
#line 3216 "parser_bison.y"
                                                { (yyval.val) = 0; }
#line 10964 "parser_bison.c"
    break;

  case 482: /* quota_used: "used" "number" quota_unit  */
#line 3218 "parser_bison.y"
                        {
				struct error_record *erec;
				uint64_t rate;

				erec = data_unit_parse(&(yyloc), (yyvsp[0].string), &rate);
				xfree((yyvsp[0].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}
				(yyval.val) = (yyvsp[-1].val) * rate;
			}
#line 10981 "parser_bison.c"
    break;

  case 483: /* quota_stmt: "quota" quota_mode "number" quota_unit quota_used close_scope_quota  */
#line 3233 "parser_bison.y"
                        {
				struct error_record *erec;
				uint64_t rate;

				erec = data_unit_parse(&(yyloc), (yyvsp[-2].string), &rate);
				xfree((yyvsp[-2].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}
				(yyval.stmt) = quota_stmt_alloc(&(yyloc));
				(yyval.stmt)->quota.bytes	= (yyvsp[-3].val) * rate;
				(yyval.stmt)->quota.used = (yyvsp[-1].val);
				(yyval.stmt)->quota.flags	= (yyvsp[-4].val);
			}
#line 11001 "parser_bison.c"
    break;

  case 484: /* quota_stmt: "quota" "name" stmt_expr close_scope_quota  */
#line 3249 "parser_bison.y"
                        {
				(yyval.stmt) = objref_stmt_alloc(&(yyloc));
				(yyval.stmt)->objref.type = NFT_OBJECT_QUOTA;
				(yyval.stmt)->objref.expr = (yyvsp[-1].expr);
			}
#line 11011 "parser_bison.c"
    break;

  case 485: /* limit_mode: "over"  */
#line 3256 "parser_bison.y"
                                                                { (yyval.val) = NFT_LIMIT_F_INV; }
#line 11017 "parser_bison.c"
    break;

  case 486: /* limit_mode: "until"  */
#line 3257 "parser_bison.y"
                                                                { (yyval.val) = 0; }
#line 11023 "parser_bison.c"
    break;

  case 487: /* limit_mode: %empty  */
#line 3258 "parser_bison.y"
                                                                { (yyval.val) = 0; }
#line 11029 "parser_bison.c"
    break;

  case 488: /* limit_burst_pkts: %empty  */
#line 3261 "parser_bison.y"
                                                                { (yyval.val) = 5; }
#line 11035 "parser_bison.c"
    break;

  case 489: /* limit_burst_pkts: "burst" "number" "packets"  */
#line 3262 "parser_bison.y"
                                                                { (yyval.val) = (yyvsp[-1].val); }
#line 11041 "parser_bison.c"
    break;

  case 490: /* limit_rate_pkts: "number" "/" time_unit  */
#line 3266 "parser_bison.y"
                        {
				(yyval.limit_rate).rate = (yyvsp[-2].val);
				(yyval.limit_rate).unit = (yyvsp[0].val);
			}
#line 11050 "parser_bison.c"
    break;

  case 491: /* limit_burst_bytes: %empty  */
#line 3272 "parser_bison.y"
                                                                { (yyval.val) = 5; }
#line 11056 "parser_bison.c"
    break;

  case 492: /* limit_burst_bytes: "burst" limit_bytes  */
#line 3273 "parser_bison.y"
                                                                { (yyval.val) = (yyvsp[0].val); }
#line 11062 "parser_bison.c"
    break;

  case 493: /* limit_rate_bytes: "number" "string"  */
#line 3277 "parser_bison.y"
                        {
				struct error_record *erec;
				uint64_t rate, unit;

				erec = rate_parse(&(yyloc), (yyvsp[0].string), &rate, &unit);
				xfree((yyvsp[0].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}
				(yyval.limit_rate).rate = rate * (yyvsp[-1].val);
				(yyval.limit_rate).unit = unit;
			}
#line 11080 "parser_bison.c"
    break;

  case 494: /* limit_rate_bytes: limit_bytes "/" time_unit  */
#line 3291 "parser_bison.y"
                        {
				(yyval.limit_rate).rate = (yyvsp[-2].val);
				(yyval.limit_rate).unit = (yyvsp[0].val);
			}
#line 11089 "parser_bison.c"
    break;

  case 495: /* limit_bytes: "number" "bytes"  */
#line 3297 "parser_bison.y"
                                                        { (yyval.val) = (yyvsp[-1].val); }
#line 11095 "parser_bison.c"
    break;

  case 496: /* limit_bytes: "number" "string"  */
#line 3299 "parser_bison.y"
                        {
				struct error_record *erec;
				uint64_t rate;

				erec = data_unit_parse(&(yyloc), (yyvsp[0].string), &rate);
				xfree((yyvsp[0].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}
				(yyval.val) = (yyvsp[-1].val) * rate;
			}
#line 11112 "parser_bison.c"
    break;

  case 497: /* time_unit: "second"  */
#line 3313 "parser_bison.y"
                                                { (yyval.val) = 1ULL; }
#line 11118 "parser_bison.c"
    break;

  case 498: /* time_unit: "minute"  */
#line 3314 "parser_bison.y"
                                                { (yyval.val) = 1ULL * 60; }
#line 11124 "parser_bison.c"
    break;

  case 499: /* time_unit: "hour"  */
#line 3315 "parser_bison.y"
                                                { (yyval.val) = 1ULL * 60 * 60; }
#line 11130 "parser_bison.c"
    break;

  case 500: /* time_unit: "day"  */
#line 3316 "parser_bison.y"
                                                { (yyval.val) = 1ULL * 60 * 60 * 24; }
#line 11136 "parser_bison.c"
    break;

  case 501: /* time_unit: "week"  */
#line 3317 "parser_bison.y"
                                                { (yyval.val) = 1ULL * 60 * 60 * 24 * 7; }
#line 11142 "parser_bison.c"
    break;

  case 503: /* reject_stmt_alloc: "reject"  */
#line 3324 "parser_bison.y"
                        {
				(yyval.stmt) = reject_stmt_alloc(&(yyloc));
			}
#line 11150 "parser_bison.c"
    break;

  case 504: /* reject_with_expr: "string"  */
#line 3330 "parser_bison.y"
                        {
				(yyval.expr) = symbol_expr_alloc(&(yyloc), SYMBOL_VALUE,
						       current_scope(state), (yyvsp[0].string));
				xfree((yyvsp[0].string));
			}
#line 11160 "parser_bison.c"
    break;

  case 505: /* reject_with_expr: integer_expr  */
#line 3335 "parser_bison.y"
                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11166 "parser_bison.c"
    break;

  case 506: /* reject_opts: %empty  */
#line 3339 "parser_bison.y"
                        {
				(yyvsp[0].stmt)->reject.type = -1;
				(yyvsp[0].stmt)->reject.icmp_code = -1;
			}
#line 11175 "parser_bison.c"
    break;

  case 507: /* reject_opts: "with" "icmp" "type" reject_with_expr  */
#line 3344 "parser_bison.y"
                        {
				(yyvsp[-4].stmt)->reject.family = NFPROTO_IPV4;
				(yyvsp[-4].stmt)->reject.type = NFT_REJECT_ICMP_UNREACH;
				(yyvsp[-4].stmt)->reject.expr = (yyvsp[0].expr);
				datatype_set((yyvsp[-4].stmt)->reject.expr, &icmp_code_type);
			}
#line 11186 "parser_bison.c"
    break;

  case 508: /* reject_opts: "with" "icmp" reject_with_expr  */
#line 3351 "parser_bison.y"
                        {
				(yyvsp[-3].stmt)->reject.family = NFPROTO_IPV4;
				(yyvsp[-3].stmt)->reject.type = NFT_REJECT_ICMP_UNREACH;
				(yyvsp[-3].stmt)->reject.expr = (yyvsp[0].expr);
				datatype_set((yyvsp[-3].stmt)->reject.expr, &icmp_code_type);
			}
#line 11197 "parser_bison.c"
    break;

  case 509: /* reject_opts: "with" "icmpv6" "type" reject_with_expr  */
#line 3358 "parser_bison.y"
                        {
				(yyvsp[-4].stmt)->reject.family = NFPROTO_IPV6;
				(yyvsp[-4].stmt)->reject.type = NFT_REJECT_ICMP_UNREACH;
				(yyvsp[-4].stmt)->reject.expr = (yyvsp[0].expr);
				datatype_set((yyvsp[-4].stmt)->reject.expr, &icmpv6_code_type);
			}
#line 11208 "parser_bison.c"
    break;

  case 510: /* reject_opts: "with" "icmpv6" reject_with_expr  */
#line 3365 "parser_bison.y"
                        {
				(yyvsp[-3].stmt)->reject.family = NFPROTO_IPV6;
				(yyvsp[-3].stmt)->reject.type = NFT_REJECT_ICMP_UNREACH;
				(yyvsp[-3].stmt)->reject.expr = (yyvsp[0].expr);
				datatype_set((yyvsp[-3].stmt)->reject.expr, &icmpv6_code_type);
			}
#line 11219 "parser_bison.c"
    break;

  case 511: /* reject_opts: "with" "icmpx" "type" reject_with_expr  */
#line 3372 "parser_bison.y"
                        {
				(yyvsp[-4].stmt)->reject.type = NFT_REJECT_ICMPX_UNREACH;
				(yyvsp[-4].stmt)->reject.expr = (yyvsp[0].expr);
				datatype_set((yyvsp[-4].stmt)->reject.expr, &icmpx_code_type);
			}
#line 11229 "parser_bison.c"
    break;

  case 512: /* reject_opts: "with" "icmpx" reject_with_expr  */
#line 3378 "parser_bison.y"
                        {
				(yyvsp[-3].stmt)->reject.type = NFT_REJECT_ICMPX_UNREACH;
				(yyvsp[-3].stmt)->reject.expr = (yyvsp[0].expr);
				datatype_set((yyvsp[-3].stmt)->reject.expr, &icmpx_code_type);
			}
#line 11239 "parser_bison.c"
    break;

  case 513: /* reject_opts: "with" "tcp" close_scope_tcp "reset"  */
#line 3384 "parser_bison.y"
                        {
				(yyvsp[-4].stmt)->reject.type = NFT_REJECT_TCP_RST;
			}
#line 11247 "parser_bison.c"
    break;

  case 515: /* nat_stmt_alloc: "snat"  */
#line 3392 "parser_bison.y"
                                        { (yyval.stmt) = nat_stmt_alloc(&(yyloc), NFT_NAT_SNAT); }
#line 11253 "parser_bison.c"
    break;

  case 516: /* nat_stmt_alloc: "dnat"  */
#line 3393 "parser_bison.y"
                                        { (yyval.stmt) = nat_stmt_alloc(&(yyloc), NFT_NAT_DNAT); }
#line 11259 "parser_bison.c"
    break;

  case 517: /* tproxy_stmt: "tproxy" "to" stmt_expr  */
#line 3397 "parser_bison.y"
                        {
				(yyval.stmt) = tproxy_stmt_alloc(&(yyloc));
				(yyval.stmt)->tproxy.family = NFPROTO_UNSPEC;
				(yyval.stmt)->tproxy.addr = (yyvsp[0].expr);
			}
#line 11269 "parser_bison.c"
    break;

  case 518: /* tproxy_stmt: "tproxy" nf_key_proto "to" stmt_expr  */
#line 3403 "parser_bison.y"
                        {
				(yyval.stmt) = tproxy_stmt_alloc(&(yyloc));
				(yyval.stmt)->tproxy.family = (yyvsp[-2].val);
				(yyval.stmt)->tproxy.addr = (yyvsp[0].expr);
			}
#line 11279 "parser_bison.c"
    break;

  case 519: /* tproxy_stmt: "tproxy" "to" "colon" stmt_expr  */
#line 3409 "parser_bison.y"
                        {
				(yyval.stmt) = tproxy_stmt_alloc(&(yyloc));
				(yyval.stmt)->tproxy.family = NFPROTO_UNSPEC;
				(yyval.stmt)->tproxy.port = (yyvsp[0].expr);
			}
#line 11289 "parser_bison.c"
    break;

  case 520: /* tproxy_stmt: "tproxy" "to" stmt_expr "colon" stmt_expr  */
#line 3415 "parser_bison.y"
                        {
				(yyval.stmt) = tproxy_stmt_alloc(&(yyloc));
				(yyval.stmt)->tproxy.family = NFPROTO_UNSPEC;
				(yyval.stmt)->tproxy.addr = (yyvsp[-2].expr);
				(yyval.stmt)->tproxy.port = (yyvsp[0].expr);
			}
#line 11300 "parser_bison.c"
    break;

  case 521: /* tproxy_stmt: "tproxy" nf_key_proto "to" stmt_expr "colon" stmt_expr  */
#line 3422 "parser_bison.y"
                        {
				(yyval.stmt) = tproxy_stmt_alloc(&(yyloc));
				(yyval.stmt)->tproxy.family = (yyvsp[-4].val);
				(yyval.stmt)->tproxy.addr = (yyvsp[-2].expr);
				(yyval.stmt)->tproxy.port = (yyvsp[0].expr);
			}
#line 11311 "parser_bison.c"
    break;

  case 522: /* tproxy_stmt: "tproxy" nf_key_proto "to" "colon" stmt_expr  */
#line 3429 "parser_bison.y"
                        {
				(yyval.stmt) = tproxy_stmt_alloc(&(yyloc));
				(yyval.stmt)->tproxy.family = (yyvsp[-3].val);
				(yyval.stmt)->tproxy.port = (yyvsp[0].expr);
			}
#line 11321 "parser_bison.c"
    break;

  case 525: /* synproxy_stmt_alloc: "synproxy"  */
#line 3441 "parser_bison.y"
                        {
				(yyval.stmt) = synproxy_stmt_alloc(&(yyloc));
			}
#line 11329 "parser_bison.c"
    break;

  case 526: /* synproxy_stmt_alloc: "synproxy" "name" stmt_expr  */
#line 3445 "parser_bison.y"
                        {
				(yyval.stmt) = objref_stmt_alloc(&(yyloc));
				(yyval.stmt)->objref.type = NFT_OBJECT_SYNPROXY;
				(yyval.stmt)->objref.expr = (yyvsp[0].expr);
			}
#line 11339 "parser_bison.c"
    break;

  case 527: /* synproxy_args: synproxy_arg  */
#line 3453 "parser_bison.y"
                        {
				(yyval.stmt)	= (yyvsp[-1].stmt);
			}
#line 11347 "parser_bison.c"
    break;

  case 529: /* synproxy_arg: "mss" "number"  */
#line 3460 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->synproxy.mss = (yyvsp[0].val);
				(yyvsp[-2].stmt)->synproxy.flags |= NF_SYNPROXY_OPT_MSS;
			}
#line 11356 "parser_bison.c"
    break;

  case 530: /* synproxy_arg: "wscale" "number"  */
#line 3465 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->synproxy.wscale = (yyvsp[0].val);
				(yyvsp[-2].stmt)->synproxy.flags |= NF_SYNPROXY_OPT_WSCALE;
			}
#line 11365 "parser_bison.c"
    break;

  case 531: /* synproxy_arg: "timestamp"  */
#line 3470 "parser_bison.y"
                        {
				(yyvsp[-1].stmt)->synproxy.flags |= NF_SYNPROXY_OPT_TIMESTAMP;
			}
#line 11373 "parser_bison.c"
    break;

  case 532: /* synproxy_arg: "sack-permitted"  */
#line 3474 "parser_bison.y"
                        {
				(yyvsp[-1].stmt)->synproxy.flags |= NF_SYNPROXY_OPT_SACK_PERM;
			}
#line 11381 "parser_bison.c"
    break;

  case 533: /* synproxy_config: "mss" "number" "wscale" "number" synproxy_ts synproxy_sack  */
#line 3480 "parser_bison.y"
                        {
				struct synproxy *synproxy;
				uint32_t flags = 0;

				synproxy = &(yyvsp[-6].obj)->synproxy;
				synproxy->mss = (yyvsp[-4].val);
				flags |= NF_SYNPROXY_OPT_MSS;
				synproxy->wscale = (yyvsp[-2].val);
				flags |= NF_SYNPROXY_OPT_WSCALE;
				if ((yyvsp[-1].val))
					flags |= (yyvsp[-1].val);
				if ((yyvsp[0].val))
					flags |= (yyvsp[0].val);
				synproxy->flags = flags;
			}
#line 11401 "parser_bison.c"
    break;

  case 534: /* synproxy_config: "mss" "number" stmt_separator "wscale" "number" stmt_separator synproxy_ts synproxy_sack  */
#line 3496 "parser_bison.y"
                        {
				struct synproxy *synproxy;
				uint32_t flags = 0;

				synproxy = &(yyvsp[-8].obj)->synproxy;
				synproxy->mss = (yyvsp[-6].val);
				flags |= NF_SYNPROXY_OPT_MSS;
				synproxy->wscale = (yyvsp[-3].val);
				flags |= NF_SYNPROXY_OPT_WSCALE;
				if ((yyvsp[-1].val))
					flags |= (yyvsp[-1].val);
				if ((yyvsp[0].val))
					flags |= (yyvsp[0].val);
				synproxy->flags = flags;
			}
#line 11421 "parser_bison.c"
    break;

  case 535: /* synproxy_obj: %empty  */
#line 3514 "parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(&(yyloc));
				(yyval.obj)->type = NFT_OBJECT_SYNPROXY;
			}
#line 11430 "parser_bison.c"
    break;

  case 536: /* synproxy_ts: %empty  */
#line 3520 "parser_bison.y"
                                                { (yyval.val) = 0; }
#line 11436 "parser_bison.c"
    break;

  case 537: /* synproxy_ts: "timestamp"  */
#line 3522 "parser_bison.y"
                        {
				(yyval.val) = NF_SYNPROXY_OPT_TIMESTAMP;
			}
#line 11444 "parser_bison.c"
    break;

  case 538: /* synproxy_sack: %empty  */
#line 3527 "parser_bison.y"
                                                { (yyval.val) = 0; }
#line 11450 "parser_bison.c"
    break;

  case 539: /* synproxy_sack: "sack-permitted"  */
#line 3529 "parser_bison.y"
                        {
				(yyval.val) = NF_SYNPROXY_OPT_SACK_PERM;
			}
#line 11458 "parser_bison.c"
    break;

  case 540: /* primary_stmt_expr: symbol_expr  */
#line 3534 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11464 "parser_bison.c"
    break;

  case 541: /* primary_stmt_expr: integer_expr  */
#line 3535 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11470 "parser_bison.c"
    break;

  case 542: /* primary_stmt_expr: boolean_expr  */
#line 3536 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11476 "parser_bison.c"
    break;

  case 543: /* primary_stmt_expr: meta_expr  */
#line 3537 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11482 "parser_bison.c"
    break;

  case 544: /* primary_stmt_expr: rt_expr  */
#line 3538 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11488 "parser_bison.c"
    break;

  case 545: /* primary_stmt_expr: ct_expr  */
#line 3539 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11494 "parser_bison.c"
    break;

  case 546: /* primary_stmt_expr: numgen_expr  */
#line 3540 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11500 "parser_bison.c"
    break;

  case 547: /* primary_stmt_expr: hash_expr  */
#line 3541 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11506 "parser_bison.c"
    break;

  case 548: /* primary_stmt_expr: payload_expr  */
#line 3542 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11512 "parser_bison.c"
    break;

  case 549: /* primary_stmt_expr: keyword_expr  */
#line 3543 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11518 "parser_bison.c"
    break;

  case 550: /* primary_stmt_expr: socket_expr  */
#line 3544 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11524 "parser_bison.c"
    break;

  case 551: /* primary_stmt_expr: osf_expr  */
#line 3545 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11530 "parser_bison.c"
    break;

  case 552: /* primary_stmt_expr: '(' basic_stmt_expr ')'  */
#line 3546 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[-1].expr); }
#line 11536 "parser_bison.c"
    break;

  case 554: /* shift_stmt_expr: shift_stmt_expr "<<" primary_stmt_expr  */
#line 3551 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_LSHIFT, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11544 "parser_bison.c"
    break;

  case 555: /* shift_stmt_expr: shift_stmt_expr ">>" primary_stmt_expr  */
#line 3555 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_RSHIFT, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11552 "parser_bison.c"
    break;

  case 557: /* and_stmt_expr: and_stmt_expr "&" shift_stmt_expr  */
#line 3562 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_AND, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11560 "parser_bison.c"
    break;

  case 559: /* exclusive_or_stmt_expr: exclusive_or_stmt_expr "^" and_stmt_expr  */
#line 3569 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_XOR, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11568 "parser_bison.c"
    break;

  case 561: /* inclusive_or_stmt_expr: inclusive_or_stmt_expr '|' exclusive_or_stmt_expr  */
#line 3576 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_OR, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11576 "parser_bison.c"
    break;

  case 564: /* concat_stmt_expr: concat_stmt_expr "." primary_stmt_expr  */
#line 3586 "parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 11589 "parser_bison.c"
    break;

  case 567: /* map_stmt_expr: concat_stmt_expr "map" map_stmt_expr_set  */
#line 3601 "parser_bison.y"
                        {
				(yyval.expr) = map_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11597 "parser_bison.c"
    break;

  case 568: /* map_stmt_expr: concat_stmt_expr  */
#line 3604 "parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 11603 "parser_bison.c"
    break;

  case 569: /* prefix_stmt_expr: basic_stmt_expr "/" "number"  */
#line 3608 "parser_bison.y"
                        {
				(yyval.expr) = prefix_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].val));
			}
#line 11611 "parser_bison.c"
    break;

  case 570: /* range_stmt_expr: basic_stmt_expr "-" basic_stmt_expr  */
#line 3614 "parser_bison.y"
                        {
				(yyval.expr) = range_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11619 "parser_bison.c"
    break;

  case 576: /* nat_stmt_args: stmt_expr  */
#line 3629 "parser_bison.y"
                        {
				(yyvsp[-1].stmt)->nat.addr = (yyvsp[0].expr);
			}
#line 11627 "parser_bison.c"
    break;

  case 577: /* nat_stmt_args: "to" stmt_expr  */
#line 3633 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->nat.addr = (yyvsp[0].expr);
			}
#line 11635 "parser_bison.c"
    break;

  case 578: /* nat_stmt_args: nf_key_proto "to" stmt_expr  */
#line 3637 "parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.family = (yyvsp[-2].val);
				(yyvsp[-3].stmt)->nat.addr = (yyvsp[0].expr);
			}
#line 11644 "parser_bison.c"
    break;

  case 579: /* nat_stmt_args: stmt_expr "colon" stmt_expr  */
#line 3642 "parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.addr = (yyvsp[-2].expr);
				(yyvsp[-3].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11653 "parser_bison.c"
    break;

  case 580: /* nat_stmt_args: "to" stmt_expr "colon" stmt_expr  */
#line 3647 "parser_bison.y"
                        {
				(yyvsp[-4].stmt)->nat.addr = (yyvsp[-2].expr);
				(yyvsp[-4].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11662 "parser_bison.c"
    break;

  case 581: /* nat_stmt_args: nf_key_proto "to" stmt_expr "colon" stmt_expr  */
#line 3652 "parser_bison.y"
                        {
				(yyvsp[-5].stmt)->nat.family = (yyvsp[-4].val);
				(yyvsp[-5].stmt)->nat.addr = (yyvsp[-2].expr);
				(yyvsp[-5].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11672 "parser_bison.c"
    break;

  case 582: /* nat_stmt_args: "colon" stmt_expr  */
#line 3658 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11680 "parser_bison.c"
    break;

  case 583: /* nat_stmt_args: "to" "colon" stmt_expr  */
#line 3662 "parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11688 "parser_bison.c"
    break;

  case 584: /* nat_stmt_args: nat_stmt_args nf_nat_flags  */
#line 3666 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->nat.flags = (yyvsp[0].val);
			}
#line 11696 "parser_bison.c"
    break;

  case 585: /* nat_stmt_args: nf_key_proto "addr" "." "port" "to" stmt_expr  */
#line 3670 "parser_bison.y"
                        {
				(yyvsp[-6].stmt)->nat.family = (yyvsp[-5].val);
				(yyvsp[-6].stmt)->nat.addr = (yyvsp[0].expr);
				(yyvsp[-6].stmt)->nat.type_flags = STMT_NAT_F_CONCAT;
			}
#line 11706 "parser_bison.c"
    break;

  case 586: /* nat_stmt_args: nf_key_proto "interval" "to" stmt_expr  */
#line 3676 "parser_bison.y"
                        {
				(yyvsp[-4].stmt)->nat.family = (yyvsp[-3].val);
				(yyvsp[-4].stmt)->nat.addr = (yyvsp[0].expr);
			}
#line 11715 "parser_bison.c"
    break;

  case 587: /* nat_stmt_args: "interval" "to" stmt_expr  */
#line 3681 "parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.addr = (yyvsp[0].expr);
			}
#line 11723 "parser_bison.c"
    break;

  case 588: /* nat_stmt_args: nf_key_proto "prefix" "to" stmt_expr  */
#line 3685 "parser_bison.y"
                        {
				(yyvsp[-4].stmt)->nat.family = (yyvsp[-3].val);
				(yyvsp[-4].stmt)->nat.addr = (yyvsp[0].expr);
				(yyvsp[-4].stmt)->nat.type_flags =
						STMT_NAT_F_PREFIX;
				(yyvsp[-4].stmt)->nat.flags |= NF_NAT_RANGE_NETMAP;
			}
#line 11735 "parser_bison.c"
    break;

  case 589: /* nat_stmt_args: "prefix" "to" stmt_expr  */
#line 3693 "parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.addr = (yyvsp[0].expr);
				(yyvsp[-3].stmt)->nat.type_flags =
						STMT_NAT_F_PREFIX;
				(yyvsp[-3].stmt)->nat.flags |= NF_NAT_RANGE_NETMAP;
			}
#line 11746 "parser_bison.c"
    break;

  case 592: /* masq_stmt_alloc: "masquerade"  */
#line 3705 "parser_bison.y"
                                                { (yyval.stmt) = nat_stmt_alloc(&(yyloc), NFT_NAT_MASQ); }
#line 11752 "parser_bison.c"
    break;

  case 593: /* masq_stmt_args: "to" "colon" stmt_expr  */
#line 3709 "parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11760 "parser_bison.c"
    break;

  case 594: /* masq_stmt_args: "to" "colon" stmt_expr nf_nat_flags  */
#line 3713 "parser_bison.y"
                        {
				(yyvsp[-4].stmt)->nat.proto = (yyvsp[-1].expr);
				(yyvsp[-4].stmt)->nat.flags = (yyvsp[0].val);
			}
#line 11769 "parser_bison.c"
    break;

  case 595: /* masq_stmt_args: nf_nat_flags  */
#line 3718 "parser_bison.y"
                        {
				(yyvsp[-1].stmt)->nat.flags = (yyvsp[0].val);
			}
#line 11777 "parser_bison.c"
    break;

  case 598: /* redir_stmt_alloc: "redirect"  */
#line 3727 "parser_bison.y"
                                                { (yyval.stmt) = nat_stmt_alloc(&(yyloc), NFT_NAT_REDIR); }
#line 11783 "parser_bison.c"
    break;

  case 599: /* redir_stmt_arg: "to" stmt_expr  */
#line 3731 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11791 "parser_bison.c"
    break;

  case 600: /* redir_stmt_arg: "to" "colon" stmt_expr  */
#line 3735 "parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11799 "parser_bison.c"
    break;

  case 601: /* redir_stmt_arg: nf_nat_flags  */
#line 3739 "parser_bison.y"
                        {
				(yyvsp[-1].stmt)->nat.flags = (yyvsp[0].val);
			}
#line 11807 "parser_bison.c"
    break;

  case 602: /* redir_stmt_arg: "to" stmt_expr nf_nat_flags  */
#line 3743 "parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.proto = (yyvsp[-1].expr);
				(yyvsp[-3].stmt)->nat.flags = (yyvsp[0].val);
			}
#line 11816 "parser_bison.c"
    break;

  case 603: /* redir_stmt_arg: "to" "colon" stmt_expr nf_nat_flags  */
#line 3748 "parser_bison.y"
                        {
				(yyvsp[-4].stmt)->nat.proto = (yyvsp[-1].expr);
				(yyvsp[-4].stmt)->nat.flags = (yyvsp[0].val);
			}
#line 11825 "parser_bison.c"
    break;

  case 604: /* dup_stmt: "dup" "to" stmt_expr  */
#line 3755 "parser_bison.y"
                        {
				(yyval.stmt) = dup_stmt_alloc(&(yyloc));
				(yyval.stmt)->dup.to = (yyvsp[0].expr);
			}
#line 11834 "parser_bison.c"
    break;

  case 605: /* dup_stmt: "dup" "to" stmt_expr "device" stmt_expr  */
#line 3760 "parser_bison.y"
                        {
				(yyval.stmt) = dup_stmt_alloc(&(yyloc));
				(yyval.stmt)->dup.to = (yyvsp[-2].expr);
				(yyval.stmt)->dup.dev = (yyvsp[0].expr);
			}
#line 11844 "parser_bison.c"
    break;

  case 606: /* fwd_stmt: "fwd" "to" stmt_expr  */
#line 3768 "parser_bison.y"
                        {
				(yyval.stmt) = fwd_stmt_alloc(&(yyloc));
				(yyval.stmt)->fwd.dev = (yyvsp[0].expr);
			}
#line 11853 "parser_bison.c"
    break;

  case 607: /* fwd_stmt: "fwd" nf_key_proto "to" stmt_expr "device" stmt_expr  */
#line 3773 "parser_bison.y"
                        {
				(yyval.stmt) = fwd_stmt_alloc(&(yyloc));
				(yyval.stmt)->fwd.family = (yyvsp[-4].val);
				(yyval.stmt)->fwd.addr = (yyvsp[-2].expr);
				(yyval.stmt)->fwd.dev = (yyvsp[0].expr);
			}
#line 11864 "parser_bison.c"
    break;

  case 609: /* nf_nat_flags: nf_nat_flags "comma" nf_nat_flag  */
#line 3783 "parser_bison.y"
                        {
				(yyval.val) = (yyvsp[-2].val) | (yyvsp[0].val);
			}
#line 11872 "parser_bison.c"
    break;

  case 610: /* nf_nat_flag: "random"  */
#line 3788 "parser_bison.y"
                                                { (yyval.val) = NF_NAT_RANGE_PROTO_RANDOM; }
#line 11878 "parser_bison.c"
    break;

  case 611: /* nf_nat_flag: "fully-random"  */
#line 3789 "parser_bison.y"
                                                { (yyval.val) = NF_NAT_RANGE_PROTO_RANDOM_FULLY; }
#line 11884 "parser_bison.c"
    break;

  case 612: /* nf_nat_flag: "persistent"  */
#line 3790 "parser_bison.y"
                                                { (yyval.val) = NF_NAT_RANGE_PERSISTENT; }
#line 11890 "parser_bison.c"
    break;

  case 614: /* queue_stmt: "queue" "to" queue_stmt_expr close_scope_queue  */
#line 3795 "parser_bison.y"
                        {
				(yyval.stmt) = queue_stmt_alloc(&(yyloc), (yyvsp[-1].expr), 0);
			}
#line 11898 "parser_bison.c"
    break;

  case 615: /* queue_stmt: "queue" "flags" queue_stmt_flags "to" queue_stmt_expr close_scope_queue  */
#line 3799 "parser_bison.y"
                        {
				(yyval.stmt) = queue_stmt_alloc(&(yyloc), (yyvsp[-1].expr), (yyvsp[-3].val));
			}
#line 11906 "parser_bison.c"
    break;

  case 616: /* queue_stmt: "queue" "flags" queue_stmt_flags "num" queue_stmt_expr_simple close_scope_queue  */
#line 3803 "parser_bison.y"
                        {
				(yyval.stmt) = queue_stmt_alloc(&(yyloc), (yyvsp[-1].expr), (yyvsp[-3].val));
			}
#line 11914 "parser_bison.c"
    break;

  case 619: /* queue_stmt_alloc: "queue"  */
#line 3813 "parser_bison.y"
                        {
				(yyval.stmt) = queue_stmt_alloc(&(yyloc), NULL, 0);
			}
#line 11922 "parser_bison.c"
    break;

  case 620: /* queue_stmt_args: queue_stmt_arg  */
#line 3819 "parser_bison.y"
                        {
				(yyval.stmt)	= (yyvsp[-1].stmt);
			}
#line 11930 "parser_bison.c"
    break;

  case 622: /* queue_stmt_arg: "num" queue_stmt_expr_simple  */
#line 3826 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->queue.queue = (yyvsp[0].expr);
				(yyvsp[-2].stmt)->queue.queue->location = (yyloc);
			}
#line 11939 "parser_bison.c"
    break;

  case 623: /* queue_stmt_arg: queue_stmt_flags  */
#line 3831 "parser_bison.y"
                        {
				(yyvsp[-1].stmt)->queue.flags |= (yyvsp[0].val);
			}
#line 11947 "parser_bison.c"
    break;

  case 628: /* queue_stmt_expr_simple: queue_expr "-" queue_expr  */
#line 3843 "parser_bison.y"
                        {
				(yyval.expr) = range_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11955 "parser_bison.c"
    break;

  case 634: /* queue_stmt_flags: queue_stmt_flags "comma" queue_stmt_flag  */
#line 3856 "parser_bison.y"
                        {
				(yyval.val) = (yyvsp[-2].val) | (yyvsp[0].val);
			}
#line 11963 "parser_bison.c"
    break;

  case 635: /* queue_stmt_flag: "bypass"  */
#line 3861 "parser_bison.y"
                                        { (yyval.val) = NFT_QUEUE_FLAG_BYPASS; }
#line 11969 "parser_bison.c"
    break;

  case 636: /* queue_stmt_flag: "fanout"  */
#line 3862 "parser_bison.y"
                                        { (yyval.val) = NFT_QUEUE_FLAG_CPU_FANOUT; }
#line 11975 "parser_bison.c"
    break;

  case 639: /* set_elem_expr_stmt_alloc: concat_expr  */
#line 3870 "parser_bison.y"
                        {
				(yyval.expr) = set_elem_expr_alloc(&(yylsp[0]), (yyvsp[0].expr));
			}
#line 11983 "parser_bison.c"
    break;

  case 640: /* set_stmt: "set" set_stmt_op set_elem_expr_stmt set_ref_expr  */
#line 3876 "parser_bison.y"
                        {
				(yyval.stmt) = set_stmt_alloc(&(yyloc));
				(yyval.stmt)->set.op  = (yyvsp[-2].val);
				(yyval.stmt)->set.key = (yyvsp[-1].expr);
				(yyval.stmt)->set.set = (yyvsp[0].expr);
			}
#line 11994 "parser_bison.c"
    break;

  case 641: /* set_stmt: set_stmt_op set_ref_expr '{' set_elem_expr_stmt '}'  */
#line 3883 "parser_bison.y"
                        {
				(yyval.stmt) = set_stmt_alloc(&(yyloc));
				(yyval.stmt)->set.op  = (yyvsp[-4].val);
				(yyval.stmt)->set.key = (yyvsp[-1].expr);
				(yyval.stmt)->set.set = (yyvsp[-3].expr);
			}
#line 12005 "parser_bison.c"
    break;

  case 642: /* set_stmt: set_stmt_op set_ref_expr '{' set_elem_expr_stmt stateful_stmt_list '}'  */
#line 3890 "parser_bison.y"
                        {
				(yyval.stmt) = set_stmt_alloc(&(yyloc));
				(yyval.stmt)->set.op  = (yyvsp[-5].val);
				(yyval.stmt)->set.key = (yyvsp[-2].expr);
				(yyval.stmt)->set.set = (yyvsp[-4].expr);
				list_splice_tail((yyvsp[-1].list), &(yyval.stmt)->set.stmt_list);
				free((yyvsp[-1].list));
			}
#line 12018 "parser_bison.c"
    break;

  case 643: /* set_stmt_op: "add"  */
#line 3900 "parser_bison.y"
                                        { (yyval.val) = NFT_DYNSET_OP_ADD; }
#line 12024 "parser_bison.c"
    break;

  case 644: /* set_stmt_op: "update"  */
#line 3901 "parser_bison.y"
                                        { (yyval.val) = NFT_DYNSET_OP_UPDATE; }
#line 12030 "parser_bison.c"
    break;

  case 645: /* set_stmt_op: "delete"  */
#line 3902 "parser_bison.y"
                                        { (yyval.val) = NFT_DYNSET_OP_DELETE; }
#line 12036 "parser_bison.c"
    break;

  case 646: /* map_stmt: set_stmt_op set_ref_expr '{' set_elem_expr_stmt "colon" set_elem_expr_stmt '}'  */
#line 3906 "parser_bison.y"
                        {
				(yyval.stmt) = map_stmt_alloc(&(yyloc));
				(yyval.stmt)->map.op  = (yyvsp[-6].val);
				(yyval.stmt)->map.key = (yyvsp[-3].expr);
				(yyval.stmt)->map.data = (yyvsp[-1].expr);
				(yyval.stmt)->map.set = (yyvsp[-5].expr);
			}
#line 12048 "parser_bison.c"
    break;

  case 647: /* map_stmt: set_stmt_op set_ref_expr '{' set_elem_expr_stmt stateful_stmt_list "colon" set_elem_expr_stmt '}'  */
#line 3914 "parser_bison.y"
                        {
				(yyval.stmt) = map_stmt_alloc(&(yyloc));
				(yyval.stmt)->map.op  = (yyvsp[-7].val);
				(yyval.stmt)->map.key = (yyvsp[-4].expr);
				(yyval.stmt)->map.data = (yyvsp[-1].expr);
				(yyval.stmt)->map.set = (yyvsp[-6].expr);
				list_splice_tail((yyvsp[-3].list), &(yyval.stmt)->map.stmt_list);
				free((yyvsp[-3].list));
			}
#line 12062 "parser_bison.c"
    break;

  case 648: /* meter_stmt: flow_stmt_legacy_alloc flow_stmt_opts '{' meter_key_expr stmt '}'  */
#line 3926 "parser_bison.y"
                        {
				(yyvsp[-5].stmt)->meter.key  = (yyvsp[-2].expr);
				(yyvsp[-5].stmt)->meter.stmt = (yyvsp[-1].stmt);
				(yyval.stmt)->location  = (yyloc);
				(yyval.stmt) = (yyvsp[-5].stmt);
			}
#line 12073 "parser_bison.c"
    break;

  case 649: /* meter_stmt: meter_stmt_alloc  */
#line 3932 "parser_bison.y"
                                                                { (yyval.stmt) = (yyvsp[0].stmt); }
#line 12079 "parser_bison.c"
    break;

  case 650: /* flow_stmt_legacy_alloc: "flow"  */
#line 3936 "parser_bison.y"
                        {
				(yyval.stmt) = meter_stmt_alloc(&(yyloc));
			}
#line 12087 "parser_bison.c"
    break;

  case 651: /* flow_stmt_opts: flow_stmt_opt  */
#line 3942 "parser_bison.y"
                        {
				(yyval.stmt)	= (yyvsp[-1].stmt);
			}
#line 12095 "parser_bison.c"
    break;

  case 653: /* flow_stmt_opt: "table" identifier  */
#line 3949 "parser_bison.y"
                        {
				(yyvsp[-2].stmt)->meter.name = (yyvsp[0].string);
			}
#line 12103 "parser_bison.c"
    break;

  case 654: /* meter_stmt_alloc: "meter" identifier '{' meter_key_expr stmt '}'  */
#line 3955 "parser_bison.y"
                        {
				(yyval.stmt) = meter_stmt_alloc(&(yyloc));
				(yyval.stmt)->meter.name = (yyvsp[-4].string);
				(yyval.stmt)->meter.size = 0;
				(yyval.stmt)->meter.key  = (yyvsp[-2].expr);
				(yyval.stmt)->meter.stmt = (yyvsp[-1].stmt);
				(yyval.stmt)->location  = (yyloc);
			}
#line 12116 "parser_bison.c"
    break;

  case 655: /* meter_stmt_alloc: "meter" identifier "size" "number" '{' meter_key_expr stmt '}'  */
#line 3964 "parser_bison.y"
                        {
				(yyval.stmt) = meter_stmt_alloc(&(yyloc));
				(yyval.stmt)->meter.name = (yyvsp[-6].string);
				(yyval.stmt)->meter.size = (yyvsp[-4].val);
				(yyval.stmt)->meter.key  = (yyvsp[-2].expr);
				(yyval.stmt)->meter.stmt = (yyvsp[-1].stmt);
				(yyval.stmt)->location  = (yyloc);
			}
#line 12129 "parser_bison.c"
    break;

  case 656: /* match_stmt: relational_expr  */
#line 3975 "parser_bison.y"
                        {
				(yyval.stmt) = expr_stmt_alloc(&(yyloc), (yyvsp[0].expr));
			}
#line 12137 "parser_bison.c"
    break;

  case 657: /* variable_expr: '$' identifier  */
#line 3981 "parser_bison.y"
                        {
				struct scope *scope = current_scope(state);
				struct symbol *sym;

				sym = symbol_get(scope, (yyvsp[0].string));
				if (!sym) {
					sym = symbol_lookup_fuzzy(scope, (yyvsp[0].string));
					if (sym) {
						erec_queue(error(&(yylsp[0]), "unknown identifier '%s'; "
								      "did you mean identifier ‘%s’?",
								      (yyvsp[0].string), sym->identifier),
							   state->msgs);
					} else {
						erec_queue(error(&(yylsp[0]), "unknown identifier '%s'", (yyvsp[0].string)),
							   state->msgs);
					}
					xfree((yyvsp[0].string));
					YYERROR;
				}

				(yyval.expr) = variable_expr_alloc(&(yyloc), scope, sym);
				xfree((yyvsp[0].string));
			}
#line 12165 "parser_bison.c"
    break;

  case 659: /* symbol_expr: string  */
#line 4008 "parser_bison.y"
                        {
				(yyval.expr) = symbol_expr_alloc(&(yyloc), SYMBOL_VALUE,
						       current_scope(state),
						       (yyvsp[0].string));
				xfree((yyvsp[0].string));
			}
#line 12176 "parser_bison.c"
    break;

  case 662: /* set_ref_symbol_expr: "@" identifier  */
#line 4021 "parser_bison.y"
                        {
				(yyval.expr) = symbol_expr_alloc(&(yyloc), SYMBOL_SET,
						       current_scope(state),
						       (yyvsp[0].string));
				xfree((yyvsp[0].string));
			}
#line 12187 "parser_bison.c"
    break;

  case 663: /* integer_expr: "number"  */
#line 4030 "parser_bison.y"
                        {
				char str[64];

				snprintf(str, sizeof(str), "%" PRIu64, (yyvsp[0].val));
				(yyval.expr) = symbol_expr_alloc(&(yyloc), SYMBOL_VALUE,
						       current_scope(state),
						       str);
			}
#line 12200 "parser_bison.c"
    break;

  case 664: /* primary_expr: symbol_expr  */
#line 4040 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12206 "parser_bison.c"
    break;

  case 665: /* primary_expr: integer_expr  */
#line 4041 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12212 "parser_bison.c"
    break;

  case 666: /* primary_expr: payload_expr  */
#line 4042 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12218 "parser_bison.c"
    break;

  case 667: /* primary_expr: exthdr_expr  */
#line 4043 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12224 "parser_bison.c"
    break;

  case 668: /* primary_expr: exthdr_exists_expr  */
#line 4044 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12230 "parser_bison.c"
    break;

  case 669: /* primary_expr: meta_expr  */
#line 4045 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12236 "parser_bison.c"
    break;

  case 670: /* primary_expr: socket_expr  */
#line 4046 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12242 "parser_bison.c"
    break;

  case 671: /* primary_expr: rt_expr  */
#line 4047 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12248 "parser_bison.c"
    break;

  case 672: /* primary_expr: ct_expr  */
#line 4048 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12254 "parser_bison.c"
    break;

  case 673: /* primary_expr: numgen_expr  */
#line 4049 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12260 "parser_bison.c"
    break;

  case 674: /* primary_expr: hash_expr  */
#line 4050 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12266 "parser_bison.c"
    break;

  case 675: /* primary_expr: fib_expr  */
#line 4051 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12272 "parser_bison.c"
    break;

  case 676: /* primary_expr: osf_expr  */
#line 4052 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12278 "parser_bison.c"
    break;

  case 677: /* primary_expr: xfrm_expr  */
#line 4053 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12284 "parser_bison.c"
    break;

  case 678: /* primary_expr: '(' basic_expr ')'  */
#line 4054 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[-1].expr); }
#line 12290 "parser_bison.c"
    break;

  case 679: /* fib_expr: "fib" fib_tuple fib_result close_scope_fib  */
#line 4058 "parser_bison.y"
                        {
				if (((yyvsp[-2].val) & (NFTA_FIB_F_SADDR|NFTA_FIB_F_DADDR)) == 0) {
					erec_queue(error(&(yylsp[-2]), "fib: need either saddr or daddr"), state->msgs);
					YYERROR;
				}

				if (((yyvsp[-2].val) & (NFTA_FIB_F_SADDR|NFTA_FIB_F_DADDR)) ==
					  (NFTA_FIB_F_SADDR|NFTA_FIB_F_DADDR)) {
					erec_queue(error(&(yylsp[-2]), "fib: saddr and daddr are mutually exclusive"), state->msgs);
					YYERROR;
				}

				if (((yyvsp[-2].val) & (NFTA_FIB_F_IIF|NFTA_FIB_F_OIF)) ==
					  (NFTA_FIB_F_IIF|NFTA_FIB_F_OIF)) {
					erec_queue(error(&(yylsp[-2]), "fib: iif and oif are mutually exclusive"), state->msgs);
					YYERROR;
				}

				(yyval.expr) = fib_expr_alloc(&(yyloc), (yyvsp[-2].val), (yyvsp[-1].val));
			}
#line 12315 "parser_bison.c"
    break;

  case 680: /* fib_result: "oif"  */
#line 4080 "parser_bison.y"
                                        { (yyval.val) =NFT_FIB_RESULT_OIF; }
#line 12321 "parser_bison.c"
    break;

  case 681: /* fib_result: "oifname"  */
#line 4081 "parser_bison.y"
                                        { (yyval.val) =NFT_FIB_RESULT_OIFNAME; }
#line 12327 "parser_bison.c"
    break;

  case 682: /* fib_result: "type"  */
#line 4082 "parser_bison.y"
                                        { (yyval.val) =NFT_FIB_RESULT_ADDRTYPE; }
#line 12333 "parser_bison.c"
    break;

  case 683: /* fib_flag: "saddr"  */
#line 4085 "parser_bison.y"
                                        { (yyval.val) = NFTA_FIB_F_SADDR; }
#line 12339 "parser_bison.c"
    break;

  case 684: /* fib_flag: "daddr"  */
#line 4086 "parser_bison.y"
                                        { (yyval.val) = NFTA_FIB_F_DADDR; }
#line 12345 "parser_bison.c"
    break;

  case 685: /* fib_flag: "mark"  */
#line 4087 "parser_bison.y"
                                        { (yyval.val) = NFTA_FIB_F_MARK; }
#line 12351 "parser_bison.c"
    break;

  case 686: /* fib_flag: "iif"  */
#line 4088 "parser_bison.y"
                                        { (yyval.val) = NFTA_FIB_F_IIF; }
#line 12357 "parser_bison.c"
    break;

  case 687: /* fib_flag: "oif"  */
#line 4089 "parser_bison.y"
                                        { (yyval.val) = NFTA_FIB_F_OIF; }
#line 12363 "parser_bison.c"
    break;

  case 688: /* fib_tuple: fib_flag "." fib_tuple  */
#line 4093 "parser_bison.y"
                        {
				(yyval.val) = (yyvsp[-2].val) | (yyvsp[0].val);
			}
#line 12371 "parser_bison.c"
    break;

  case 690: /* osf_expr: "osf" osf_ttl "version"  */
#line 4100 "parser_bison.y"
                        {
				(yyval.expr) = osf_expr_alloc(&(yyloc), (yyvsp[-1].val), NFT_OSF_F_VERSION);
			}
#line 12379 "parser_bison.c"
    break;

  case 691: /* osf_expr: "osf" osf_ttl "name"  */
#line 4104 "parser_bison.y"
                        {
				(yyval.expr) = osf_expr_alloc(&(yyloc), (yyvsp[-1].val), 0);
			}
#line 12387 "parser_bison.c"
    break;

  case 692: /* osf_ttl: %empty  */
#line 4110 "parser_bison.y"
                        {
				(yyval.val) = NF_OSF_TTL_TRUE;
			}
#line 12395 "parser_bison.c"
    break;

  case 693: /* osf_ttl: "ttl" "string"  */
#line 4114 "parser_bison.y"
                        {
				if (!strcmp((yyvsp[0].string), "loose"))
					(yyval.val) = NF_OSF_TTL_LESS;
				else if (!strcmp((yyvsp[0].string), "skip"))
					(yyval.val) = NF_OSF_TTL_NOCHECK;
				else {
					erec_queue(error(&(yylsp[0]), "invalid ttl option"),
						   state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
				xfree((yyvsp[0].string));
			}
#line 12413 "parser_bison.c"
    break;

  case 695: /* shift_expr: shift_expr "<<" primary_rhs_expr  */
#line 4131 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_LSHIFT, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12421 "parser_bison.c"
    break;

  case 696: /* shift_expr: shift_expr ">>" primary_rhs_expr  */
#line 4135 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_RSHIFT, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12429 "parser_bison.c"
    break;

  case 698: /* and_expr: and_expr "&" shift_rhs_expr  */
#line 4142 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_AND, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12437 "parser_bison.c"
    break;

  case 700: /* exclusive_or_expr: exclusive_or_expr "^" and_rhs_expr  */
#line 4149 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_XOR, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12445 "parser_bison.c"
    break;

  case 702: /* inclusive_or_expr: inclusive_or_expr '|' exclusive_or_rhs_expr  */
#line 4156 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_OR, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12453 "parser_bison.c"
    break;

  case 705: /* concat_expr: concat_expr "." basic_expr  */
#line 4166 "parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 12466 "parser_bison.c"
    break;

  case 706: /* prefix_rhs_expr: basic_rhs_expr "/" "number"  */
#line 4177 "parser_bison.y"
                        {
				(yyval.expr) = prefix_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].val));
			}
#line 12474 "parser_bison.c"
    break;

  case 707: /* range_rhs_expr: basic_rhs_expr "-" basic_rhs_expr  */
#line 4183 "parser_bison.y"
                        {
				(yyval.expr) = range_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12482 "parser_bison.c"
    break;

  case 710: /* map_expr: concat_expr "map" rhs_expr  */
#line 4193 "parser_bison.y"
                        {
				(yyval.expr) = map_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12490 "parser_bison.c"
    break;

  case 714: /* set_expr: '{' set_list_expr '}'  */
#line 4204 "parser_bison.y"
                        {
				(yyvsp[-1].expr)->location = (yyloc);
				(yyval.expr) = (yyvsp[-1].expr);
			}
#line 12499 "parser_bison.c"
    break;

  case 715: /* set_list_expr: set_list_member_expr  */
#line 4211 "parser_bison.y"
                        {
				(yyval.expr) = set_expr_alloc(&(yyloc), NULL);
				compound_expr_add((yyval.expr), (yyvsp[0].expr));
			}
#line 12508 "parser_bison.c"
    break;

  case 716: /* set_list_expr: set_list_expr "comma" set_list_member_expr  */
#line 4216 "parser_bison.y"
                        {
				compound_expr_add((yyvsp[-2].expr), (yyvsp[0].expr));
				(yyval.expr) = (yyvsp[-2].expr);
			}
#line 12517 "parser_bison.c"
    break;

  case 718: /* set_list_member_expr: opt_newline set_expr opt_newline  */
#line 4224 "parser_bison.y"
                        {
				(yyval.expr) = (yyvsp[-1].expr);
			}
#line 12525 "parser_bison.c"
    break;

  case 719: /* set_list_member_expr: opt_newline set_elem_expr opt_newline  */
#line 4228 "parser_bison.y"
                        {
				(yyval.expr) = (yyvsp[-1].expr);
			}
#line 12533 "parser_bison.c"
    break;

  case 720: /* set_list_member_expr: opt_newline set_elem_expr "colon" set_rhs_expr opt_newline  */
#line 4232 "parser_bison.y"
                        {
				(yyval.expr) = mapping_expr_alloc(&(yyloc), (yyvsp[-3].expr), (yyvsp[-1].expr));
			}
#line 12541 "parser_bison.c"
    break;

  case 722: /* meter_key_expr: meter_key_expr_alloc set_elem_options  */
#line 4239 "parser_bison.y"
                        {
				(yyval.expr)->location = (yyloc);
				(yyval.expr) = (yyvsp[-1].expr);
			}
#line 12550 "parser_bison.c"
    break;

  case 723: /* meter_key_expr_alloc: concat_expr  */
#line 4246 "parser_bison.y"
                        {
				(yyval.expr) = set_elem_expr_alloc(&(yylsp[0]), (yyvsp[0].expr));
			}
#line 12558 "parser_bison.c"
    break;

  case 726: /* set_elem_key_expr: set_lhs_expr  */
#line 4255 "parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 12564 "parser_bison.c"
    break;

  case 727: /* set_elem_key_expr: "*"  */
#line 4256 "parser_bison.y"
                                                        { (yyval.expr) = set_elem_catchall_expr_alloc(&(yylsp[0])); }
#line 12570 "parser_bison.c"
    break;

  case 728: /* set_elem_expr_alloc: set_elem_key_expr set_elem_stmt_list  */
#line 4260 "parser_bison.y"
                        {
				(yyval.expr) = set_elem_expr_alloc(&(yylsp[-1]), (yyvsp[-1].expr));
				list_splice_tail((yyvsp[0].list), &(yyval.expr)->stmt_list);
				xfree((yyvsp[0].list));
			}
#line 12580 "parser_bison.c"
    break;

  case 729: /* set_elem_expr_alloc: set_elem_key_expr  */
#line 4266 "parser_bison.y"
                        {
				(yyval.expr) = set_elem_expr_alloc(&(yylsp[0]), (yyvsp[0].expr));
			}
#line 12588 "parser_bison.c"
    break;

  case 730: /* set_elem_options: set_elem_option  */
#line 4272 "parser_bison.y"
                        {
				(yyval.expr)	= (yyvsp[-1].expr);
			}
#line 12596 "parser_bison.c"
    break;

  case 732: /* set_elem_option: "timeout" time_spec  */
#line 4279 "parser_bison.y"
                        {
				(yyvsp[-2].expr)->timeout = (yyvsp[0].val);
			}
#line 12604 "parser_bison.c"
    break;

  case 733: /* set_elem_option: "expires" time_spec  */
#line 4283 "parser_bison.y"
                        {
				(yyvsp[-2].expr)->expiration = (yyvsp[0].val);
			}
#line 12612 "parser_bison.c"
    break;

  case 734: /* set_elem_option: comment_spec  */
#line 4287 "parser_bison.y"
                        {
				if (already_set((yyvsp[-1].expr)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].expr)->comment = (yyvsp[0].string);
			}
#line 12624 "parser_bison.c"
    break;

  case 735: /* set_elem_expr_options: set_elem_expr_option  */
#line 4297 "parser_bison.y"
                        {
				(yyval.expr)	= (yyvsp[-1].expr);
			}
#line 12632 "parser_bison.c"
    break;

  case 737: /* set_elem_stmt_list: set_elem_stmt  */
#line 4304 "parser_bison.y"
                        {
				(yyval.list) = xmalloc(sizeof(*(yyval.list)));
				init_list_head((yyval.list));
				list_add_tail(&(yyvsp[0].stmt)->list, (yyval.list));
			}
#line 12642 "parser_bison.c"
    break;

  case 738: /* set_elem_stmt_list: set_elem_stmt_list set_elem_stmt  */
#line 4310 "parser_bison.y"
                        {
				(yyval.list) = (yyvsp[-1].list);
				list_add_tail(&(yyvsp[0].stmt)->list, (yyvsp[-1].list));
			}
#line 12651 "parser_bison.c"
    break;

  case 739: /* set_elem_stmt: "counter" close_scope_counter  */
#line 4317 "parser_bison.y"
                        {
				(yyval.stmt) = counter_stmt_alloc(&(yyloc));
			}
#line 12659 "parser_bison.c"
    break;

  case 740: /* set_elem_stmt: "counter" "packets" "number" "bytes" "number" close_scope_counter  */
#line 4321 "parser_bison.y"
                        {
				(yyval.stmt) = counter_stmt_alloc(&(yyloc));
				(yyval.stmt)->counter.packets = (yyvsp[-3].val);
				(yyval.stmt)->counter.bytes = (yyvsp[-1].val);
			}
#line 12669 "parser_bison.c"
    break;

  case 741: /* set_elem_stmt: "limit" "rate" limit_mode limit_rate_pkts limit_burst_pkts close_scope_limit  */
#line 4327 "parser_bison.y"
                        {
				if ((yyvsp[-1].val) == 0) {
					erec_queue(error(&(yylsp[-1]), "limit burst must be > 0"),
						   state->msgs);
					YYERROR;
				}
				(yyval.stmt) = limit_stmt_alloc(&(yyloc));
				(yyval.stmt)->limit.rate  = (yyvsp[-2].limit_rate).rate;
				(yyval.stmt)->limit.unit  = (yyvsp[-2].limit_rate).unit;
				(yyval.stmt)->limit.burst = (yyvsp[-1].val);
				(yyval.stmt)->limit.type  = NFT_LIMIT_PKTS;
				(yyval.stmt)->limit.flags = (yyvsp[-3].val);
			}
#line 12687 "parser_bison.c"
    break;

  case 742: /* set_elem_stmt: "limit" "rate" limit_mode limit_rate_bytes limit_burst_bytes close_scope_limit  */
#line 4341 "parser_bison.y"
                        {
				if ((yyvsp[-1].val) == 0) {
					erec_queue(error(&(yylsp[0]), "limit burst must be > 0"),
						   state->msgs);
					YYERROR;
				}
				(yyval.stmt) = limit_stmt_alloc(&(yyloc));
				(yyval.stmt)->limit.rate  = (yyvsp[-2].limit_rate).rate;
				(yyval.stmt)->limit.unit  = (yyvsp[-2].limit_rate).unit;
				(yyval.stmt)->limit.burst = (yyvsp[-1].val);
				(yyval.stmt)->limit.type  = NFT_LIMIT_PKT_BYTES;
				(yyval.stmt)->limit.flags = (yyvsp[-3].val);
			}
#line 12705 "parser_bison.c"
    break;

  case 743: /* set_elem_stmt: "ct" "count" "number" close_scope_ct  */
#line 4355 "parser_bison.y"
                        {
				(yyval.stmt) = connlimit_stmt_alloc(&(yyloc));
				(yyval.stmt)->connlimit.count	= (yyvsp[-1].val);
			}
#line 12714 "parser_bison.c"
    break;

  case 744: /* set_elem_stmt: "ct" "count" "over" "number" close_scope_ct  */
#line 4360 "parser_bison.y"
                        {
				(yyval.stmt) = connlimit_stmt_alloc(&(yyloc));
				(yyval.stmt)->connlimit.count = (yyvsp[-1].val);
				(yyval.stmt)->connlimit.flags = NFT_CONNLIMIT_F_INV;
			}
#line 12724 "parser_bison.c"
    break;

  case 745: /* set_elem_expr_option: "timeout" time_spec  */
#line 4368 "parser_bison.y"
                        {
				(yyvsp[-2].expr)->timeout = (yyvsp[0].val);
			}
#line 12732 "parser_bison.c"
    break;

  case 746: /* set_elem_expr_option: "expires" time_spec  */
#line 4372 "parser_bison.y"
                        {
				(yyvsp[-2].expr)->expiration = (yyvsp[0].val);
			}
#line 12740 "parser_bison.c"
    break;

  case 747: /* set_elem_expr_option: comment_spec  */
#line 4376 "parser_bison.y"
                        {
				if (already_set((yyvsp[-1].expr)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].expr)->comment = (yyvsp[0].string);
			}
#line 12752 "parser_bison.c"
    break;

  case 753: /* initializer_expr: '{' '}'  */
#line 4394 "parser_bison.y"
                                                { (yyval.expr) = compound_expr_alloc(&(yyloc), EXPR_SET); }
#line 12758 "parser_bison.c"
    break;

  case 754: /* initializer_expr: "-" "number"  */
#line 4396 "parser_bison.y"
                        {
				int32_t num = -(yyvsp[0].val);

				(yyval.expr) = constant_expr_alloc(&(yyloc), &integer_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(num) * BITS_PER_BYTE,
							 &num);
			}
#line 12771 "parser_bison.c"
    break;

  case 755: /* counter_config: "packets" "number" "bytes" "number"  */
#line 4407 "parser_bison.y"
                        {
				struct counter *counter;

				counter = &(yyvsp[-4].obj)->counter;
				counter->packets = (yyvsp[-2].val);
				counter->bytes = (yyvsp[0].val);
			}
#line 12783 "parser_bison.c"
    break;

  case 756: /* counter_obj: %empty  */
#line 4417 "parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(&(yyloc));
				(yyval.obj)->type = NFT_OBJECT_COUNTER;
			}
#line 12792 "parser_bison.c"
    break;

  case 757: /* quota_config: quota_mode "number" quota_unit quota_used  */
#line 4424 "parser_bison.y"
                        {
				struct error_record *erec;
				struct quota *quota;
				uint64_t rate;

				erec = data_unit_parse(&(yyloc), (yyvsp[-1].string), &rate);
				xfree((yyvsp[-1].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}

				quota = &(yyvsp[-4].obj)->quota;
				quota->bytes	= (yyvsp[-2].val) * rate;
				quota->used	= (yyvsp[0].val);
				quota->flags	= (yyvsp[-3].val);
			}
#line 12814 "parser_bison.c"
    break;

  case 758: /* quota_obj: %empty  */
#line 4444 "parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(&(yyloc));
				(yyval.obj)->type = NFT_OBJECT_QUOTA;
			}
#line 12823 "parser_bison.c"
    break;

  case 759: /* secmark_config: string  */
#line 4451 "parser_bison.y"
                        {
				int ret;
				struct secmark *secmark;

				secmark = &(yyvsp[-1].obj)->secmark;
				ret = snprintf(secmark->ctx, sizeof(secmark->ctx), "%s", (yyvsp[0].string));
				if (ret <= 0 || ret >= (int)sizeof(secmark->ctx)) {
					erec_queue(error(&(yylsp[0]), "invalid context '%s', max length is %u\n", (yyvsp[0].string), (int)sizeof(secmark->ctx)), state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
				xfree((yyvsp[0].string));
			}
#line 12841 "parser_bison.c"
    break;

  case 760: /* secmark_obj: %empty  */
#line 4467 "parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(&(yyloc));
				(yyval.obj)->type = NFT_OBJECT_SECMARK;
			}
#line 12850 "parser_bison.c"
    break;

  case 761: /* ct_obj_type: "helper"  */
#line 4473 "parser_bison.y"
                                                { (yyval.val) = NFT_OBJECT_CT_HELPER; }
#line 12856 "parser_bison.c"
    break;

  case 762: /* ct_obj_type: "timeout"  */
#line 4474 "parser_bison.y"
                                                { (yyval.val) = NFT_OBJECT_CT_TIMEOUT; }
#line 12862 "parser_bison.c"
    break;

  case 763: /* ct_obj_type: "expectation"  */
#line 4475 "parser_bison.y"
                                                { (yyval.val) = NFT_OBJECT_CT_EXPECT; }
#line 12868 "parser_bison.c"
    break;

  case 764: /* ct_cmd_type: "helpers"  */
#line 4478 "parser_bison.y"
                                                { (yyval.val) = CMD_OBJ_CT_HELPERS; }
#line 12874 "parser_bison.c"
    break;

  case 765: /* ct_cmd_type: "timeout"  */
#line 4479 "parser_bison.y"
                                                { (yyval.val) = CMD_OBJ_CT_TIMEOUT; }
#line 12880 "parser_bison.c"
    break;

  case 766: /* ct_cmd_type: "expectation"  */
#line 4480 "parser_bison.y"
                                                { (yyval.val) = CMD_OBJ_CT_EXPECT; }
#line 12886 "parser_bison.c"
    break;

  case 767: /* ct_l4protoname: "tcp" close_scope_tcp  */
#line 4483 "parser_bison.y"
                                                        { (yyval.val) = IPPROTO_TCP; }
#line 12892 "parser_bison.c"
    break;

  case 768: /* ct_l4protoname: "udp"  */
#line 4484 "parser_bison.y"
                                        { (yyval.val) = IPPROTO_UDP; }
#line 12898 "parser_bison.c"
    break;

  case 769: /* ct_helper_config: "type" "quoted string" "protocol" ct_l4protoname stmt_separator  */
#line 4488 "parser_bison.y"
                        {
				struct ct_helper *ct;
				int ret;

				ct = &(yyvsp[-5].obj)->ct_helper;

				ret = snprintf(ct->name, sizeof(ct->name), "%s", (yyvsp[-3].string));
				if (ret <= 0 || ret >= (int)sizeof(ct->name)) {
					erec_queue(error(&(yylsp[-3]), "invalid name '%s', max length is %u\n", (yyvsp[-3].string), (int)sizeof(ct->name)), state->msgs);
					YYERROR;
				}
				xfree((yyvsp[-3].string));

				ct->l4proto = (yyvsp[-1].val);
			}
#line 12918 "parser_bison.c"
    break;

  case 770: /* ct_helper_config: "l3proto" family_spec_explicit stmt_separator  */
#line 4504 "parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_helper.l3proto = (yyvsp[-1].val);
			}
#line 12926 "parser_bison.c"
    break;

  case 771: /* timeout_states: timeout_state  */
#line 4510 "parser_bison.y"
                        {
				(yyval.list) = xmalloc(sizeof(*(yyval.list)));
				init_list_head((yyval.list));
				list_add_tail((yyvsp[0].list), (yyval.list));
			}
#line 12936 "parser_bison.c"
    break;

  case 772: /* timeout_states: timeout_states "comma" timeout_state  */
#line 4516 "parser_bison.y"
                        {
				list_add_tail((yyvsp[0].list), (yyvsp[-2].list));
				(yyval.list) = (yyvsp[-2].list);
			}
#line 12945 "parser_bison.c"
    break;

  case 773: /* timeout_state: "string" "colon" "number"  */
#line 4524 "parser_bison.y"
                        {
				struct timeout_state *ts;

				ts = xzalloc(sizeof(*ts));
				ts->timeout_str = (yyvsp[-2].string);
				ts->timeout_value = (yyvsp[0].val);
				ts->location = (yylsp[-2]);
				init_list_head(&ts->head);
				(yyval.list) = &ts->head;
			}
#line 12960 "parser_bison.c"
    break;

  case 774: /* ct_timeout_config: "protocol" ct_l4protoname stmt_separator  */
#line 4537 "parser_bison.y"
                        {
				struct ct_timeout *ct;
				int l4proto = (yyvsp[-1].val);

				ct = &(yyvsp[-3].obj)->ct_timeout;
				ct->l4proto = l4proto;
			}
#line 12972 "parser_bison.c"
    break;

  case 775: /* ct_timeout_config: "policy" '=' '{' timeout_states '}' stmt_separator  */
#line 4545 "parser_bison.y"
                        {
				struct ct_timeout *ct;

				ct = &(yyvsp[-6].obj)->ct_timeout;
				list_splice_tail((yyvsp[-2].list), &ct->timeout_list);
				xfree((yyvsp[-2].list));
			}
#line 12984 "parser_bison.c"
    break;

  case 776: /* ct_timeout_config: "l3proto" family_spec_explicit stmt_separator  */
#line 4553 "parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_timeout.l3proto = (yyvsp[-1].val);
			}
#line 12992 "parser_bison.c"
    break;

  case 777: /* ct_expect_config: "protocol" ct_l4protoname stmt_separator  */
#line 4559 "parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_expect.l4proto = (yyvsp[-1].val);
			}
#line 13000 "parser_bison.c"
    break;

  case 778: /* ct_expect_config: "dport" "number" stmt_separator  */
#line 4563 "parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_expect.dport = (yyvsp[-1].val);
			}
#line 13008 "parser_bison.c"
    break;

  case 779: /* ct_expect_config: "timeout" time_spec stmt_separator  */
#line 4567 "parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_expect.timeout = (yyvsp[-1].val);
			}
#line 13016 "parser_bison.c"
    break;

  case 780: /* ct_expect_config: "size" "number" stmt_separator  */
#line 4571 "parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_expect.size = (yyvsp[-1].val);
			}
#line 13024 "parser_bison.c"
    break;

  case 781: /* ct_expect_config: "l3proto" family_spec_explicit stmt_separator  */
#line 4575 "parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_expect.l3proto = (yyvsp[-1].val);
			}
#line 13032 "parser_bison.c"
    break;

  case 782: /* ct_obj_alloc: %empty  */
#line 4581 "parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(&(yyloc));
			}
#line 13040 "parser_bison.c"
    break;

  case 783: /* limit_config: "rate" limit_mode limit_rate_pkts limit_burst_pkts  */
#line 4587 "parser_bison.y"
                        {
				struct limit *limit;

				limit = &(yyvsp[-4].obj)->limit;
				limit->rate	= (yyvsp[-1].limit_rate).rate;
				limit->unit	= (yyvsp[-1].limit_rate).unit;
				limit->burst	= (yyvsp[0].val);
				limit->type	= NFT_LIMIT_PKTS;
				limit->flags	= (yyvsp[-2].val);
			}
#line 13055 "parser_bison.c"
    break;

  case 784: /* limit_config: "rate" limit_mode limit_rate_bytes limit_burst_bytes  */
#line 4598 "parser_bison.y"
                        {
				struct limit *limit;

				limit = &(yyvsp[-4].obj)->limit;
				limit->rate	= (yyvsp[-1].limit_rate).rate;
				limit->unit	= (yyvsp[-1].limit_rate).unit;
				limit->burst	= (yyvsp[0].val);
				limit->type	= NFT_LIMIT_PKT_BYTES;
				limit->flags	= (yyvsp[-2].val);
			}
#line 13070 "parser_bison.c"
    break;

  case 785: /* limit_obj: %empty  */
#line 4611 "parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(&(yyloc));
				(yyval.obj)->type = NFT_OBJECT_LIMIT;
			}
#line 13079 "parser_bison.c"
    break;

  case 786: /* relational_expr: expr rhs_expr  */
#line 4618 "parser_bison.y"
                        {
				(yyval.expr) = relational_expr_alloc(&(yyloc), OP_IMPLICIT, (yyvsp[-1].expr), (yyvsp[0].expr));
			}
#line 13087 "parser_bison.c"
    break;

  case 787: /* relational_expr: expr list_rhs_expr  */
#line 4622 "parser_bison.y"
                        {
				(yyval.expr) = relational_expr_alloc(&(yyloc), OP_IMPLICIT, (yyvsp[-1].expr), (yyvsp[0].expr));
			}
#line 13095 "parser_bison.c"
    break;

  case 788: /* relational_expr: expr basic_rhs_expr "/" list_rhs_expr  */
#line 4626 "parser_bison.y"
                        {
				(yyval.expr) = flagcmp_expr_alloc(&(yyloc), OP_EQ, (yyvsp[-3].expr), (yyvsp[0].expr), (yyvsp[-2].expr));
			}
#line 13103 "parser_bison.c"
    break;

  case 789: /* relational_expr: expr list_rhs_expr "/" list_rhs_expr  */
#line 4630 "parser_bison.y"
                        {
				(yyval.expr) = flagcmp_expr_alloc(&(yyloc), OP_EQ, (yyvsp[-3].expr), (yyvsp[0].expr), (yyvsp[-2].expr));
			}
#line 13111 "parser_bison.c"
    break;

  case 790: /* relational_expr: expr relational_op basic_rhs_expr "/" list_rhs_expr  */
#line 4634 "parser_bison.y"
                        {
				(yyval.expr) = flagcmp_expr_alloc(&(yyloc), (yyvsp[-3].val), (yyvsp[-4].expr), (yyvsp[0].expr), (yyvsp[-2].expr));
			}
#line 13119 "parser_bison.c"
    break;

  case 791: /* relational_expr: expr relational_op list_rhs_expr "/" list_rhs_expr  */
#line 4638 "parser_bison.y"
                        {
				(yyval.expr) = flagcmp_expr_alloc(&(yyloc), (yyvsp[-3].val), (yyvsp[-4].expr), (yyvsp[0].expr), (yyvsp[-2].expr));
			}
#line 13127 "parser_bison.c"
    break;

  case 792: /* relational_expr: expr relational_op rhs_expr  */
#line 4642 "parser_bison.y"
                        {
				(yyval.expr) = relational_expr_alloc(&(yylsp[-1]), (yyvsp[-1].val), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13135 "parser_bison.c"
    break;

  case 793: /* relational_expr: expr relational_op list_rhs_expr  */
#line 4646 "parser_bison.y"
                        {
				(yyval.expr) = relational_expr_alloc(&(yylsp[-1]), (yyvsp[-1].val), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13143 "parser_bison.c"
    break;

  case 794: /* list_rhs_expr: basic_rhs_expr "comma" basic_rhs_expr  */
#line 4652 "parser_bison.y"
                        {
				(yyval.expr) = list_expr_alloc(&(yyloc));
				compound_expr_add((yyval.expr), (yyvsp[-2].expr));
				compound_expr_add((yyval.expr), (yyvsp[0].expr));
			}
#line 13153 "parser_bison.c"
    break;

  case 795: /* list_rhs_expr: list_rhs_expr "comma" basic_rhs_expr  */
#line 4658 "parser_bison.y"
                        {
				(yyvsp[-2].expr)->location = (yyloc);
				compound_expr_add((yyvsp[-2].expr), (yyvsp[0].expr));
				(yyval.expr) = (yyvsp[-2].expr);
			}
#line 13163 "parser_bison.c"
    break;

  case 796: /* rhs_expr: concat_rhs_expr  */
#line 4665 "parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13169 "parser_bison.c"
    break;

  case 797: /* rhs_expr: set_expr  */
#line 4666 "parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13175 "parser_bison.c"
    break;

  case 798: /* rhs_expr: set_ref_symbol_expr  */
#line 4667 "parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13181 "parser_bison.c"
    break;

  case 800: /* shift_rhs_expr: shift_rhs_expr "<<" primary_rhs_expr  */
#line 4672 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_LSHIFT, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13189 "parser_bison.c"
    break;

  case 801: /* shift_rhs_expr: shift_rhs_expr ">>" primary_rhs_expr  */
#line 4676 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_RSHIFT, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13197 "parser_bison.c"
    break;

  case 803: /* and_rhs_expr: and_rhs_expr "&" shift_rhs_expr  */
#line 4683 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_AND, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13205 "parser_bison.c"
    break;

  case 805: /* exclusive_or_rhs_expr: exclusive_or_rhs_expr "^" and_rhs_expr  */
#line 4690 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_XOR, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13213 "parser_bison.c"
    break;

  case 807: /* inclusive_or_rhs_expr: inclusive_or_rhs_expr '|' exclusive_or_rhs_expr  */
#line 4697 "parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_OR, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13221 "parser_bison.c"
    break;

  case 811: /* concat_rhs_expr: concat_rhs_expr "." multiton_rhs_expr  */
#line 4708 "parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 13234 "parser_bison.c"
    break;

  case 812: /* concat_rhs_expr: concat_rhs_expr "." basic_rhs_expr  */
#line 4717 "parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 13247 "parser_bison.c"
    break;

  case 813: /* boolean_keys: "exists"  */
#line 4727 "parser_bison.y"
                                                { (yyval.val8) = true; }
#line 13253 "parser_bison.c"
    break;

  case 814: /* boolean_keys: "missing"  */
#line 4728 "parser_bison.y"
                                                { (yyval.val8) = false; }
#line 13259 "parser_bison.c"
    break;

  case 815: /* boolean_expr: boolean_keys  */
#line 4732 "parser_bison.y"
                        {
				(yyval.expr) = constant_expr_alloc(&(yyloc), &boolean_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof((yyvsp[0].val8)) * BITS_PER_BYTE, &(yyvsp[0].val8));
			}
#line 13269 "parser_bison.c"
    break;

  case 816: /* keyword_expr: "ether" close_scope_eth  */
#line 4739 "parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "ether"); }
#line 13275 "parser_bison.c"
    break;

  case 817: /* keyword_expr: "ip" close_scope_ip  */
#line 4740 "parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "ip"); }
#line 13281 "parser_bison.c"
    break;

  case 818: /* keyword_expr: "ip6" close_scope_ip6  */
#line 4741 "parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "ip6"); }
#line 13287 "parser_bison.c"
    break;

  case 819: /* keyword_expr: "vlan" close_scope_vlan  */
#line 4742 "parser_bison.y"
                                                         { (yyval.expr) = symbol_value(&(yyloc), "vlan"); }
#line 13293 "parser_bison.c"
    break;

  case 820: /* keyword_expr: "arp" close_scope_arp  */
#line 4743 "parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "arp"); }
#line 13299 "parser_bison.c"
    break;

  case 821: /* keyword_expr: "dnat"  */
#line 4744 "parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "dnat"); }
#line 13305 "parser_bison.c"
    break;

  case 822: /* keyword_expr: "snat"  */
#line 4745 "parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "snat"); }
#line 13311 "parser_bison.c"
    break;

  case 823: /* keyword_expr: "ecn"  */
#line 4746 "parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "ecn"); }
#line 13317 "parser_bison.c"
    break;

  case 824: /* keyword_expr: "reset"  */
#line 4747 "parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "reset"); }
#line 13323 "parser_bison.c"
    break;

  case 825: /* keyword_expr: "original"  */
#line 4748 "parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "original"); }
#line 13329 "parser_bison.c"
    break;

  case 826: /* keyword_expr: "reply"  */
#line 4749 "parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "reply"); }
#line 13335 "parser_bison.c"
    break;

  case 827: /* keyword_expr: "label"  */
#line 4750 "parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "label"); }
#line 13341 "parser_bison.c"
    break;

  case 828: /* primary_rhs_expr: symbol_expr  */
#line 4753 "parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13347 "parser_bison.c"
    break;

  case 829: /* primary_rhs_expr: integer_expr  */
#line 4754 "parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13353 "parser_bison.c"
    break;

  case 830: /* primary_rhs_expr: boolean_expr  */
#line 4755 "parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13359 "parser_bison.c"
    break;

  case 831: /* primary_rhs_expr: keyword_expr  */
#line 4756 "parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13365 "parser_bison.c"
    break;

  case 832: /* primary_rhs_expr: "tcp" close_scope_tcp  */
#line 4758 "parser_bison.y"
                        {
				uint8_t data = IPPROTO_TCP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13376 "parser_bison.c"
    break;

  case 833: /* primary_rhs_expr: "udp"  */
#line 4765 "parser_bison.y"
                        {
				uint8_t data = IPPROTO_UDP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13387 "parser_bison.c"
    break;

  case 834: /* primary_rhs_expr: "udplite"  */
#line 4772 "parser_bison.y"
                        {
				uint8_t data = IPPROTO_UDPLITE;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13398 "parser_bison.c"
    break;

  case 835: /* primary_rhs_expr: "esp"  */
#line 4779 "parser_bison.y"
                        {
				uint8_t data = IPPROTO_ESP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13409 "parser_bison.c"
    break;

  case 836: /* primary_rhs_expr: "ah"  */
#line 4786 "parser_bison.y"
                        {
				uint8_t data = IPPROTO_AH;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13420 "parser_bison.c"
    break;

  case 837: /* primary_rhs_expr: "icmp"  */
#line 4793 "parser_bison.y"
                        {
				uint8_t data = IPPROTO_ICMP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13431 "parser_bison.c"
    break;

  case 838: /* primary_rhs_expr: "igmp"  */
#line 4800 "parser_bison.y"
                        {
				uint8_t data = IPPROTO_IGMP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13442 "parser_bison.c"
    break;

  case 839: /* primary_rhs_expr: "icmpv6"  */
#line 4807 "parser_bison.y"
                        {
				uint8_t data = IPPROTO_ICMPV6;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13453 "parser_bison.c"
    break;

  case 840: /* primary_rhs_expr: "comp"  */
#line 4814 "parser_bison.y"
                        {
				uint8_t data = IPPROTO_COMP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13464 "parser_bison.c"
    break;

  case 841: /* primary_rhs_expr: "dccp"  */
#line 4821 "parser_bison.y"
                        {
				uint8_t data = IPPROTO_DCCP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13475 "parser_bison.c"
    break;

  case 842: /* primary_rhs_expr: "sctp" close_scope_sctp  */
#line 4828 "parser_bison.y"
                        {
				uint8_t data = IPPROTO_SCTP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13486 "parser_bison.c"
    break;

  case 843: /* primary_rhs_expr: "redirect"  */
#line 4835 "parser_bison.y"
                        {
				uint8_t data = ICMP_REDIRECT;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &icmp_type_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13497 "parser_bison.c"
    break;

  case 844: /* primary_rhs_expr: '(' basic_rhs_expr ')'  */
#line 4841 "parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[-1].expr); }
#line 13503 "parser_bison.c"
    break;

  case 845: /* relational_op: "=="  */
#line 4844 "parser_bison.y"
                                                { (yyval.val) = OP_EQ; }
#line 13509 "parser_bison.c"
    break;

  case 846: /* relational_op: "!="  */
#line 4845 "parser_bison.y"
                                                { (yyval.val) = OP_NEQ; }
#line 13515 "parser_bison.c"
    break;

  case 847: /* relational_op: "<"  */
#line 4846 "parser_bison.y"
                                                { (yyval.val) = OP_LT; }
#line 13521 "parser_bison.c"
    break;

  case 848: /* relational_op: ">"  */
#line 4847 "parser_bison.y"
                                                { (yyval.val) = OP_GT; }
#line 13527 "parser_bison.c"
    break;

  case 849: /* relational_op: ">="  */
#line 4848 "parser_bison.y"
                                                { (yyval.val) = OP_GTE; }
#line 13533 "parser_bison.c"
    break;

  case 850: /* relational_op: "<="  */
#line 4849 "parser_bison.y"
                                                { (yyval.val) = OP_LTE; }
#line 13539 "parser_bison.c"
    break;

  case 851: /* relational_op: "!"  */
#line 4850 "parser_bison.y"
                                                { (yyval.val) = OP_NEG; }
#line 13545 "parser_bison.c"
    break;

  case 852: /* verdict_expr: "accept"  */
#line 4854 "parser_bison.y"
                        {
				(yyval.expr) = verdict_expr_alloc(&(yyloc), NF_ACCEPT, NULL);
			}
#line 13553 "parser_bison.c"
    break;

  case 853: /* verdict_expr: "drop"  */
#line 4858 "parser_bison.y"
                        {
				(yyval.expr) = verdict_expr_alloc(&(yyloc), NF_DROP, NULL);
			}
#line 13561 "parser_bison.c"
    break;

  case 854: /* verdict_expr: "continue"  */
#line 4862 "parser_bison.y"
                        {
				(yyval.expr) = verdict_expr_alloc(&(yyloc), NFT_CONTINUE, NULL);
			}
#line 13569 "parser_bison.c"
    break;

  case 855: /* verdict_expr: "jump" chain_expr  */
#line 4866 "parser_bison.y"
                        {
				(yyval.expr) = verdict_expr_alloc(&(yyloc), NFT_JUMP, (yyvsp[0].expr));
			}
#line 13577 "parser_bison.c"
    break;

  case 856: /* verdict_expr: "goto" chain_expr  */
#line 4870 "parser_bison.y"
                        {
				(yyval.expr) = verdict_expr_alloc(&(yyloc), NFT_GOTO, (yyvsp[0].expr));
			}
#line 13585 "parser_bison.c"
    break;

  case 857: /* verdict_expr: "return"  */
#line 4874 "parser_bison.y"
                        {
				(yyval.expr) = verdict_expr_alloc(&(yyloc), NFT_RETURN, NULL);
			}
#line 13593 "parser_bison.c"
    break;

  case 859: /* chain_expr: identifier  */
#line 4881 "parser_bison.y"
                        {
				(yyval.expr) = constant_expr_alloc(&(yyloc), &string_type,
							 BYTEORDER_HOST_ENDIAN,
							 strlen((yyvsp[0].string)) * BITS_PER_BYTE,
							 (yyvsp[0].string));
				xfree((yyvsp[0].string));
			}
#line 13605 "parser_bison.c"
    break;

  case 860: /* meta_expr: "meta" meta_key  */
#line 4891 "parser_bison.y"
                        {
				(yyval.expr) = meta_expr_alloc(&(yyloc), (yyvsp[0].val));
			}
#line 13613 "parser_bison.c"
    break;

  case 861: /* meta_expr: meta_key_unqualified  */
#line 4895 "parser_bison.y"
                        {
				(yyval.expr) = meta_expr_alloc(&(yyloc), (yyvsp[0].val));
			}
#line 13621 "parser_bison.c"
    break;

  case 862: /* meta_expr: "meta" "string"  */
#line 4899 "parser_bison.y"
                        {
				struct error_record *erec;
				unsigned int key;

				erec = meta_key_parse(&(yyloc), (yyvsp[0].string), &key);
				xfree((yyvsp[0].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}

				(yyval.expr) = meta_expr_alloc(&(yyloc), key);
			}
#line 13639 "parser_bison.c"
    break;

  case 865: /* meta_key_qualified: "length"  */
#line 4918 "parser_bison.y"
                                                { (yyval.val) = NFT_META_LEN; }
#line 13645 "parser_bison.c"
    break;

  case 866: /* meta_key_qualified: "protocol"  */
#line 4919 "parser_bison.y"
                                                { (yyval.val) = NFT_META_PROTOCOL; }
#line 13651 "parser_bison.c"
    break;

  case 867: /* meta_key_qualified: "priority"  */
#line 4920 "parser_bison.y"
                                                { (yyval.val) = NFT_META_PRIORITY; }
#line 13657 "parser_bison.c"
    break;

  case 868: /* meta_key_qualified: "random"  */
#line 4921 "parser_bison.y"
                                                { (yyval.val) = NFT_META_PRANDOM; }
#line 13663 "parser_bison.c"
    break;

  case 869: /* meta_key_qualified: "secmark" close_scope_secmark  */
#line 4922 "parser_bison.y"
                                                            { (yyval.val) = NFT_META_SECMARK; }
#line 13669 "parser_bison.c"
    break;

  case 870: /* meta_key_unqualified: "mark"  */
#line 4925 "parser_bison.y"
                                                { (yyval.val) = NFT_META_MARK; }
#line 13675 "parser_bison.c"
    break;

  case 871: /* meta_key_unqualified: "iif"  */
#line 4926 "parser_bison.y"
                                                { (yyval.val) = NFT_META_IIF; }
#line 13681 "parser_bison.c"
    break;

  case 872: /* meta_key_unqualified: "iifname"  */
#line 4927 "parser_bison.y"
                                                { (yyval.val) = NFT_META_IIFNAME; }
#line 13687 "parser_bison.c"
    break;

  case 873: /* meta_key_unqualified: "iiftype"  */
#line 4928 "parser_bison.y"
                                                { (yyval.val) = NFT_META_IIFTYPE; }
#line 13693 "parser_bison.c"
    break;

  case 874: /* meta_key_unqualified: "oif"  */
#line 4929 "parser_bison.y"
                                                { (yyval.val) = NFT_META_OIF; }
#line 13699 "parser_bison.c"
    break;

  case 875: /* meta_key_unqualified: "oifname"  */
#line 4930 "parser_bison.y"
                                                { (yyval.val) = NFT_META_OIFNAME; }
#line 13705 "parser_bison.c"
    break;

  case 876: /* meta_key_unqualified: "oiftype"  */
#line 4931 "parser_bison.y"
                                                { (yyval.val) = NFT_META_OIFTYPE; }
#line 13711 "parser_bison.c"
    break;

  case 877: /* meta_key_unqualified: "skuid"  */
#line 4932 "parser_bison.y"
                                                { (yyval.val) = NFT_META_SKUID; }
#line 13717 "parser_bison.c"
    break;

  case 878: /* meta_key_unqualified: "skgid"  */
#line 4933 "parser_bison.y"
                                                { (yyval.val) = NFT_META_SKGID; }
#line 13723 "parser_bison.c"
    break;

  case 879: /* meta_key_unqualified: "nftrace"  */
#line 4934 "parser_bison.y"
                                                { (yyval.val) = NFT_META_NFTRACE; }
#line 13729 "parser_bison.c"
    break;

  case 880: /* meta_key_unqualified: "rtclassid"  */
#line 4935 "parser_bison.y"
                                                { (yyval.val) = NFT_META_RTCLASSID; }
#line 13735 "parser_bison.c"
    break;

  case 881: /* meta_key_unqualified: "ibriport"  */
#line 4936 "parser_bison.y"
                                                { (yyval.val) = NFT_META_BRI_IIFNAME; }
#line 13741 "parser_bison.c"
    break;

  case 882: /* meta_key_unqualified: "obriport"  */
#line 4937 "parser_bison.y"
                                                { (yyval.val) = NFT_META_BRI_OIFNAME; }
#line 13747 "parser_bison.c"
    break;

  case 883: /* meta_key_unqualified: "ibrname"  */
#line 4938 "parser_bison.y"
                                                { (yyval.val) = NFT_META_BRI_IIFNAME; }
#line 13753 "parser_bison.c"
    break;

  case 884: /* meta_key_unqualified: "obrname"  */
#line 4939 "parser_bison.y"
                                                { (yyval.val) = NFT_META_BRI_OIFNAME; }
#line 13759 "parser_bison.c"
    break;

  case 885: /* meta_key_unqualified: "pkttype"  */
#line 4940 "parser_bison.y"
                                                { (yyval.val) = NFT_META_PKTTYPE; }
#line 13765 "parser_bison.c"
    break;

  case 886: /* meta_key_unqualified: "cpu"  */
#line 4941 "parser_bison.y"
                                                { (yyval.val) = NFT_META_CPU; }
#line 13771 "parser_bison.c"
    break;

  case 887: /* meta_key_unqualified: "iifgroup"  */
#line 4942 "parser_bison.y"
                                                { (yyval.val) = NFT_META_IIFGROUP; }
#line 13777 "parser_bison.c"
    break;

  case 888: /* meta_key_unqualified: "oifgroup"  */
#line 4943 "parser_bison.y"
                                                { (yyval.val) = NFT_META_OIFGROUP; }
#line 13783 "parser_bison.c"
    break;

  case 889: /* meta_key_unqualified: "cgroup"  */
#line 4944 "parser_bison.y"
                                                { (yyval.val) = NFT_META_CGROUP; }
#line 13789 "parser_bison.c"
    break;

  case 890: /* meta_key_unqualified: "ipsec" close_scope_ipsec  */
#line 4945 "parser_bison.y"
                                                          { (yyval.val) = NFT_META_SECPATH; }
#line 13795 "parser_bison.c"
    break;

  case 891: /* meta_key_unqualified: "time"  */
#line 4946 "parser_bison.y"
                                                { (yyval.val) = NFT_META_TIME_NS; }
#line 13801 "parser_bison.c"
    break;

  case 892: /* meta_key_unqualified: "day"  */
#line 4947 "parser_bison.y"
                                                { (yyval.val) = NFT_META_TIME_DAY; }
#line 13807 "parser_bison.c"
    break;

  case 893: /* meta_key_unqualified: "hour"  */
#line 4948 "parser_bison.y"
                                                { (yyval.val) = NFT_META_TIME_HOUR; }
#line 13813 "parser_bison.c"
    break;

  case 894: /* meta_stmt: "meta" meta_key "set" stmt_expr  */
#line 4952 "parser_bison.y"
                        {
				switch ((yyvsp[-2].val)) {
				case NFT_META_SECMARK:
					switch ((yyvsp[0].expr)->etype) {
					case EXPR_CT:
						(yyval.stmt) = meta_stmt_alloc(&(yyloc), (yyvsp[-2].val), (yyvsp[0].expr));
						break;
					default:
						(yyval.stmt) = objref_stmt_alloc(&(yyloc));
						(yyval.stmt)->objref.type = NFT_OBJECT_SECMARK;
						(yyval.stmt)->objref.expr = (yyvsp[0].expr);
						break;
					}
					break;
				default:
					(yyval.stmt) = meta_stmt_alloc(&(yyloc), (yyvsp[-2].val), (yyvsp[0].expr));
					break;
				}
			}
#line 13837 "parser_bison.c"
    break;

  case 895: /* meta_stmt: meta_key_unqualified "set" stmt_expr  */
#line 4972 "parser_bison.y"
                        {
				(yyval.stmt) = meta_stmt_alloc(&(yyloc), (yyvsp[-2].val), (yyvsp[0].expr));
			}
#line 13845 "parser_bison.c"
    break;

  case 896: /* meta_stmt: "meta" "string" "set" stmt_expr  */
#line 4976 "parser_bison.y"
                        {
				struct error_record *erec;
				unsigned int key;

				erec = meta_key_parse(&(yyloc), (yyvsp[-2].string), &key);
				xfree((yyvsp[-2].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}

				(yyval.stmt) = meta_stmt_alloc(&(yyloc), key, (yyvsp[0].expr));
			}
#line 13863 "parser_bison.c"
    break;

  case 897: /* meta_stmt: "notrack"  */
#line 4990 "parser_bison.y"
                        {
				(yyval.stmt) = notrack_stmt_alloc(&(yyloc));
			}
#line 13871 "parser_bison.c"
    break;

  case 898: /* meta_stmt: "flow" "offload" "@" string  */
#line 4994 "parser_bison.y"
                        {
				(yyval.stmt) = flow_offload_stmt_alloc(&(yyloc), (yyvsp[0].string));
			}
#line 13879 "parser_bison.c"
    break;

  case 899: /* meta_stmt: "flow" "add" "@" string  */
#line 4998 "parser_bison.y"
                        {
				(yyval.stmt) = flow_offload_stmt_alloc(&(yyloc), (yyvsp[0].string));
			}
#line 13887 "parser_bison.c"
    break;

  case 900: /* socket_expr: "socket" socket_key close_scope_socket  */
#line 5004 "parser_bison.y"
                        {
				(yyval.expr) = socket_expr_alloc(&(yyloc), (yyvsp[-1].val), 0);
			}
#line 13895 "parser_bison.c"
    break;

  case 901: /* socket_expr: "socket" "cgroupv2" "level" "number" close_scope_socket  */
#line 5008 "parser_bison.y"
                        {
				(yyval.expr) = socket_expr_alloc(&(yyloc), NFT_SOCKET_CGROUPV2, (yyvsp[-1].val));
			}
#line 13903 "parser_bison.c"
    break;

  case 902: /* socket_key: "transparent"  */
#line 5013 "parser_bison.y"
                                                { (yyval.val) = NFT_SOCKET_TRANSPARENT; }
#line 13909 "parser_bison.c"
    break;

  case 903: /* socket_key: "mark"  */
#line 5014 "parser_bison.y"
                                                { (yyval.val) = NFT_SOCKET_MARK; }
#line 13915 "parser_bison.c"
    break;

  case 904: /* socket_key: "wildcard"  */
#line 5015 "parser_bison.y"
                                                { (yyval.val) = NFT_SOCKET_WILDCARD; }
#line 13921 "parser_bison.c"
    break;

  case 905: /* offset_opt: %empty  */
#line 5018 "parser_bison.y"
                                                { (yyval.val) = 0; }
#line 13927 "parser_bison.c"
    break;

  case 906: /* offset_opt: "offset" "number"  */
#line 5019 "parser_bison.y"
                                                { (yyval.val) = (yyvsp[0].val); }
#line 13933 "parser_bison.c"
    break;

  case 907: /* numgen_type: "inc"  */
#line 5022 "parser_bison.y"
                                                { (yyval.val) = NFT_NG_INCREMENTAL; }
#line 13939 "parser_bison.c"
    break;

  case 908: /* numgen_type: "random"  */
#line 5023 "parser_bison.y"
                                                { (yyval.val) = NFT_NG_RANDOM; }
#line 13945 "parser_bison.c"
    break;

  case 909: /* numgen_expr: "numgen" numgen_type "mod" "number" offset_opt close_scope_numgen  */
#line 5027 "parser_bison.y"
                        {
				(yyval.expr) = numgen_expr_alloc(&(yyloc), (yyvsp[-4].val), (yyvsp[-2].val), (yyvsp[-1].val));
			}
#line 13953 "parser_bison.c"
    break;

  case 910: /* xfrm_spnum: "spnum" "number"  */
#line 5032 "parser_bison.y"
                                            { (yyval.val) = (yyvsp[0].val); }
#line 13959 "parser_bison.c"
    break;

  case 911: /* xfrm_spnum: %empty  */
#line 5033 "parser_bison.y"
                                            { (yyval.val) = 0; }
#line 13965 "parser_bison.c"
    break;

  case 912: /* xfrm_dir: "in"  */
#line 5036 "parser_bison.y"
                                        { (yyval.val) = XFRM_POLICY_IN; }
#line 13971 "parser_bison.c"
    break;

  case 913: /* xfrm_dir: "out"  */
#line 5037 "parser_bison.y"
                                        { (yyval.val) = XFRM_POLICY_OUT; }
#line 13977 "parser_bison.c"
    break;

  case 914: /* xfrm_state_key: "spi"  */
#line 5040 "parser_bison.y"
                                    { (yyval.val) = NFT_XFRM_KEY_SPI; }
#line 13983 "parser_bison.c"
    break;

  case 915: /* xfrm_state_key: "reqid"  */
#line 5041 "parser_bison.y"
                                      { (yyval.val) = NFT_XFRM_KEY_REQID; }
#line 13989 "parser_bison.c"
    break;

  case 916: /* xfrm_state_proto_key: "daddr"  */
#line 5044 "parser_bison.y"
                                                { (yyval.val) = NFT_XFRM_KEY_DADDR_IP4; }
#line 13995 "parser_bison.c"
    break;

  case 917: /* xfrm_state_proto_key: "saddr"  */
#line 5045 "parser_bison.y"
                                                { (yyval.val) = NFT_XFRM_KEY_SADDR_IP4; }
#line 14001 "parser_bison.c"
    break;

  case 918: /* xfrm_expr: "ipsec" xfrm_dir xfrm_spnum xfrm_state_key close_scope_ipsec  */
#line 5049 "parser_bison.y"
                        {
				if ((yyvsp[-2].val) > 255) {
					erec_queue(error(&(yylsp[-2]), "value too large"), state->msgs);
					YYERROR;
				}
				(yyval.expr) = xfrm_expr_alloc(&(yyloc), (yyvsp[-3].val), (yyvsp[-2].val), (yyvsp[-1].val));
			}
#line 14013 "parser_bison.c"
    break;

  case 919: /* xfrm_expr: "ipsec" xfrm_dir xfrm_spnum nf_key_proto xfrm_state_proto_key close_scope_ipsec  */
#line 5057 "parser_bison.y"
                        {
				enum nft_xfrm_keys xfrmk = (yyvsp[-1].val);

				switch ((yyvsp[-2].val)) {
				case NFPROTO_IPV4:
					break;
				case NFPROTO_IPV6:
					if ((yyvsp[-1].val) == NFT_XFRM_KEY_SADDR_IP4)
						xfrmk = NFT_XFRM_KEY_SADDR_IP6;
					else if ((yyvsp[-1].val) == NFT_XFRM_KEY_DADDR_IP4)
						xfrmk = NFT_XFRM_KEY_DADDR_IP6;
					break;
				default:
					YYERROR;
					break;
				}

				if ((yyvsp[-3].val) > 255) {
					erec_queue(error(&(yylsp[-3]), "value too large"), state->msgs);
					YYERROR;
				}

				(yyval.expr) = xfrm_expr_alloc(&(yyloc), (yyvsp[-4].val), (yyvsp[-3].val), xfrmk);
			}
#line 14042 "parser_bison.c"
    break;

  case 920: /* hash_expr: "jhash" expr "mod" "number" "seed" "number" offset_opt close_scope_hash  */
#line 5084 "parser_bison.y"
                        {
				(yyval.expr) = hash_expr_alloc(&(yyloc), (yyvsp[-4].val), true, (yyvsp[-2].val), (yyvsp[-1].val), NFT_HASH_JENKINS);
				(yyval.expr)->hash.expr = (yyvsp[-6].expr);
			}
#line 14051 "parser_bison.c"
    break;

  case 921: /* hash_expr: "jhash" expr "mod" "number" offset_opt close_scope_hash  */
#line 5089 "parser_bison.y"
                        {
				(yyval.expr) = hash_expr_alloc(&(yyloc), (yyvsp[-2].val), false, 0, (yyvsp[-1].val), NFT_HASH_JENKINS);
				(yyval.expr)->hash.expr = (yyvsp[-4].expr);
			}
#line 14060 "parser_bison.c"
    break;

  case 922: /* hash_expr: "symhash" "mod" "number" offset_opt close_scope_hash  */
#line 5094 "parser_bison.y"
                        {
				(yyval.expr) = hash_expr_alloc(&(yyloc), (yyvsp[-2].val), false, 0, (yyvsp[-1].val), NFT_HASH_SYM);
			}
#line 14068 "parser_bison.c"
    break;

  case 923: /* nf_key_proto: "ip" close_scope_ip  */
#line 5099 "parser_bison.y"
                                                       { (yyval.val) = NFPROTO_IPV4; }
#line 14074 "parser_bison.c"
    break;

  case 924: /* nf_key_proto: "ip6" close_scope_ip6  */
#line 5100 "parser_bison.y"
                                                        { (yyval.val) = NFPROTO_IPV6; }
#line 14080 "parser_bison.c"
    break;

  case 925: /* rt_expr: "rt" rt_key close_scope_rt  */
#line 5104 "parser_bison.y"
                        {
				(yyval.expr) = rt_expr_alloc(&(yyloc), (yyvsp[-1].val), true);
			}
#line 14088 "parser_bison.c"
    break;

  case 926: /* rt_expr: "rt" nf_key_proto rt_key close_scope_rt  */
#line 5108 "parser_bison.y"
                        {
				enum nft_rt_keys rtk = (yyvsp[-1].val);

				switch ((yyvsp[-2].val)) {
				case NFPROTO_IPV4:
					break;
				case NFPROTO_IPV6:
					if ((yyvsp[-1].val) == NFT_RT_NEXTHOP4)
						rtk = NFT_RT_NEXTHOP6;
					break;
				default:
					YYERROR;
					break;
				}

				(yyval.expr) = rt_expr_alloc(&(yyloc), rtk, false);
			}
#line 14110 "parser_bison.c"
    break;

  case 927: /* rt_key: "classid"  */
#line 5127 "parser_bison.y"
                                                { (yyval.val) = NFT_RT_CLASSID; }
#line 14116 "parser_bison.c"
    break;

  case 928: /* rt_key: "nexthop"  */
#line 5128 "parser_bison.y"
                                                { (yyval.val) = NFT_RT_NEXTHOP4; }
#line 14122 "parser_bison.c"
    break;

  case 929: /* rt_key: "mtu"  */
#line 5129 "parser_bison.y"
                                                { (yyval.val) = NFT_RT_TCPMSS; }
#line 14128 "parser_bison.c"
    break;

  case 930: /* rt_key: "ipsec" close_scope_ipsec  */
#line 5130 "parser_bison.y"
                                                          { (yyval.val) = NFT_RT_XFRM; }
#line 14134 "parser_bison.c"
    break;

  case 931: /* ct_expr: "ct" ct_key close_scope_ct  */
#line 5134 "parser_bison.y"
                        {
				(yyval.expr) = ct_expr_alloc(&(yyloc), (yyvsp[-1].val), -1);
			}
#line 14142 "parser_bison.c"
    break;

  case 932: /* ct_expr: "ct" ct_dir ct_key_dir close_scope_ct  */
#line 5138 "parser_bison.y"
                        {
				(yyval.expr) = ct_expr_alloc(&(yyloc), (yyvsp[-1].val), (yyvsp[-2].val));
			}
#line 14150 "parser_bison.c"
    break;

  case 933: /* ct_expr: "ct" ct_dir ct_key_proto_field close_scope_ct  */
#line 5142 "parser_bison.y"
                        {
				(yyval.expr) = ct_expr_alloc(&(yyloc), (yyvsp[-1].val), (yyvsp[-2].val));
			}
#line 14158 "parser_bison.c"
    break;

  case 934: /* ct_dir: "original"  */
#line 5147 "parser_bison.y"
                                                { (yyval.val) = IP_CT_DIR_ORIGINAL; }
#line 14164 "parser_bison.c"
    break;

  case 935: /* ct_dir: "reply"  */
#line 5148 "parser_bison.y"
                                                { (yyval.val) = IP_CT_DIR_REPLY; }
#line 14170 "parser_bison.c"
    break;

  case 936: /* ct_key: "l3proto"  */
#line 5151 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_L3PROTOCOL; }
#line 14176 "parser_bison.c"
    break;

  case 937: /* ct_key: "protocol"  */
#line 5152 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_PROTOCOL; }
#line 14182 "parser_bison.c"
    break;

  case 938: /* ct_key: "mark"  */
#line 5153 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_MARK; }
#line 14188 "parser_bison.c"
    break;

  case 939: /* ct_key: "state"  */
#line 5154 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_STATE; }
#line 14194 "parser_bison.c"
    break;

  case 940: /* ct_key: "direction"  */
#line 5155 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_DIRECTION; }
#line 14200 "parser_bison.c"
    break;

  case 941: /* ct_key: "status"  */
#line 5156 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_STATUS; }
#line 14206 "parser_bison.c"
    break;

  case 942: /* ct_key: "expiration"  */
#line 5157 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_EXPIRATION; }
#line 14212 "parser_bison.c"
    break;

  case 943: /* ct_key: "helper"  */
#line 5158 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_HELPER; }
#line 14218 "parser_bison.c"
    break;

  case 944: /* ct_key: "saddr"  */
#line 5159 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_SRC; }
#line 14224 "parser_bison.c"
    break;

  case 945: /* ct_key: "daddr"  */
#line 5160 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_DST; }
#line 14230 "parser_bison.c"
    break;

  case 946: /* ct_key: "proto-src"  */
#line 5161 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_PROTO_SRC; }
#line 14236 "parser_bison.c"
    break;

  case 947: /* ct_key: "proto-dst"  */
#line 5162 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_PROTO_DST; }
#line 14242 "parser_bison.c"
    break;

  case 948: /* ct_key: "label"  */
#line 5163 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_LABELS; }
#line 14248 "parser_bison.c"
    break;

  case 949: /* ct_key: "event"  */
#line 5164 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_EVENTMASK; }
#line 14254 "parser_bison.c"
    break;

  case 950: /* ct_key: "secmark" close_scope_secmark  */
#line 5165 "parser_bison.y"
                                                            { (yyval.val) = NFT_CT_SECMARK; }
#line 14260 "parser_bison.c"
    break;

  case 951: /* ct_key: "id"  */
#line 5166 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_ID; }
#line 14266 "parser_bison.c"
    break;

  case 953: /* ct_key_dir: "saddr"  */
#line 5170 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_SRC; }
#line 14272 "parser_bison.c"
    break;

  case 954: /* ct_key_dir: "daddr"  */
#line 5171 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_DST; }
#line 14278 "parser_bison.c"
    break;

  case 955: /* ct_key_dir: "l3proto"  */
#line 5172 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_L3PROTOCOL; }
#line 14284 "parser_bison.c"
    break;

  case 956: /* ct_key_dir: "protocol"  */
#line 5173 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_PROTOCOL; }
#line 14290 "parser_bison.c"
    break;

  case 957: /* ct_key_dir: "proto-src"  */
#line 5174 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_PROTO_SRC; }
#line 14296 "parser_bison.c"
    break;

  case 958: /* ct_key_dir: "proto-dst"  */
#line 5175 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_PROTO_DST; }
#line 14302 "parser_bison.c"
    break;

  case 960: /* ct_key_proto_field: "ip" "saddr" close_scope_ip  */
#line 5179 "parser_bison.y"
                                                               { (yyval.val) = NFT_CT_SRC_IP; }
#line 14308 "parser_bison.c"
    break;

  case 961: /* ct_key_proto_field: "ip" "daddr" close_scope_ip  */
#line 5180 "parser_bison.y"
                                                               { (yyval.val) = NFT_CT_DST_IP; }
#line 14314 "parser_bison.c"
    break;

  case 962: /* ct_key_proto_field: "ip6" "saddr" close_scope_ip6  */
#line 5181 "parser_bison.y"
                                                                { (yyval.val) = NFT_CT_SRC_IP6; }
#line 14320 "parser_bison.c"
    break;

  case 963: /* ct_key_proto_field: "ip6" "daddr" close_scope_ip6  */
#line 5182 "parser_bison.y"
                                                                { (yyval.val) = NFT_CT_DST_IP6; }
#line 14326 "parser_bison.c"
    break;

  case 964: /* ct_key_dir_optional: "bytes"  */
#line 5185 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_BYTES; }
#line 14332 "parser_bison.c"
    break;

  case 965: /* ct_key_dir_optional: "packets"  */
#line 5186 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_PKTS; }
#line 14338 "parser_bison.c"
    break;

  case 966: /* ct_key_dir_optional: "avgpkt"  */
#line 5187 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_AVGPKT; }
#line 14344 "parser_bison.c"
    break;

  case 967: /* ct_key_dir_optional: "zone"  */
#line 5188 "parser_bison.y"
                                                { (yyval.val) = NFT_CT_ZONE; }
#line 14350 "parser_bison.c"
    break;

  case 970: /* list_stmt_expr: symbol_stmt_expr "comma" symbol_stmt_expr  */
#line 5196 "parser_bison.y"
                        {
				(yyval.expr) = list_expr_alloc(&(yyloc));
				compound_expr_add((yyval.expr), (yyvsp[-2].expr));
				compound_expr_add((yyval.expr), (yyvsp[0].expr));
			}
#line 14360 "parser_bison.c"
    break;

  case 971: /* list_stmt_expr: list_stmt_expr "comma" symbol_stmt_expr  */
#line 5202 "parser_bison.y"
                        {
				(yyvsp[-2].expr)->location = (yyloc);
				compound_expr_add((yyvsp[-2].expr), (yyvsp[0].expr));
				(yyval.expr) = (yyvsp[-2].expr);
			}
#line 14370 "parser_bison.c"
    break;

  case 972: /* ct_stmt: "ct" ct_key "set" stmt_expr close_scope_ct  */
#line 5210 "parser_bison.y"
                        {
				switch ((yyvsp[-3].val)) {
				case NFT_CT_HELPER:
					(yyval.stmt) = objref_stmt_alloc(&(yyloc));
					(yyval.stmt)->objref.type = NFT_OBJECT_CT_HELPER;
					(yyval.stmt)->objref.expr = (yyvsp[-1].expr);
					break;
				default:
					(yyval.stmt) = ct_stmt_alloc(&(yyloc), (yyvsp[-3].val), -1, (yyvsp[-1].expr));
					break;
				}
			}
#line 14387 "parser_bison.c"
    break;

  case 973: /* ct_stmt: "ct" "timeout" "set" stmt_expr close_scope_ct  */
#line 5223 "parser_bison.y"
                        {
				(yyval.stmt) = objref_stmt_alloc(&(yyloc));
				(yyval.stmt)->objref.type = NFT_OBJECT_CT_TIMEOUT;
				(yyval.stmt)->objref.expr = (yyvsp[-1].expr);

			}
#line 14398 "parser_bison.c"
    break;

  case 974: /* ct_stmt: "ct" "expectation" "set" stmt_expr close_scope_ct  */
#line 5230 "parser_bison.y"
                        {
				(yyval.stmt) = objref_stmt_alloc(&(yyloc));
				(yyval.stmt)->objref.type = NFT_OBJECT_CT_EXPECT;
				(yyval.stmt)->objref.expr = (yyvsp[-1].expr);
			}
#line 14408 "parser_bison.c"
    break;

  case 975: /* ct_stmt: "ct" ct_dir ct_key_dir_optional "set" stmt_expr close_scope_ct  */
#line 5236 "parser_bison.y"
                        {
				(yyval.stmt) = ct_stmt_alloc(&(yyloc), (yyvsp[-3].val), (yyvsp[-4].val), (yyvsp[-1].expr));
			}
#line 14416 "parser_bison.c"
    break;

  case 976: /* payload_stmt: payload_expr "set" stmt_expr  */
#line 5242 "parser_bison.y"
                        {
				if ((yyvsp[-2].expr)->etype == EXPR_EXTHDR)
					(yyval.stmt) = exthdr_stmt_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
				else
					(yyval.stmt) = payload_stmt_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 14427 "parser_bison.c"
    break;

  case 995: /* payload_raw_expr: "@" payload_base_spec "comma" "number" "comma" "number"  */
#line 5271 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), NULL, 0);
				payload_init_raw((yyval.expr), (yyvsp[-4].val), (yyvsp[-2].val), (yyvsp[0].val));
				(yyval.expr)->byteorder		= BYTEORDER_BIG_ENDIAN;
				(yyval.expr)->payload.is_raw	= true;
			}
#line 14438 "parser_bison.c"
    break;

  case 996: /* payload_base_spec: "ll"  */
#line 5279 "parser_bison.y"
                                                { (yyval.val) = PROTO_BASE_LL_HDR; }
#line 14444 "parser_bison.c"
    break;

  case 997: /* payload_base_spec: "nh"  */
#line 5280 "parser_bison.y"
                                                { (yyval.val) = PROTO_BASE_NETWORK_HDR; }
#line 14450 "parser_bison.c"
    break;

  case 998: /* payload_base_spec: "th"  */
#line 5281 "parser_bison.y"
                                                { (yyval.val) = PROTO_BASE_TRANSPORT_HDR; }
#line 14456 "parser_bison.c"
    break;

  case 999: /* payload_base_spec: "string"  */
#line 5283 "parser_bison.y"
                        {
				if (!strcmp((yyvsp[0].string), "ih")) {
					(yyval.val) = PROTO_BASE_INNER_HDR;
				} else {
					erec_queue(error(&(yylsp[0]), "unknown raw payload base"), state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
				xfree((yyvsp[0].string));
			}
#line 14471 "parser_bison.c"
    break;

  case 1000: /* eth_hdr_expr: "ether" eth_hdr_field close_scope_eth  */
#line 5296 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_eth, (yyvsp[-1].val));
			}
#line 14479 "parser_bison.c"
    break;

  case 1001: /* eth_hdr_field: "saddr"  */
#line 5301 "parser_bison.y"
                                                { (yyval.val) = ETHHDR_SADDR; }
#line 14485 "parser_bison.c"
    break;

  case 1002: /* eth_hdr_field: "daddr"  */
#line 5302 "parser_bison.y"
                                                { (yyval.val) = ETHHDR_DADDR; }
#line 14491 "parser_bison.c"
    break;

  case 1003: /* eth_hdr_field: "type"  */
#line 5303 "parser_bison.y"
                                                { (yyval.val) = ETHHDR_TYPE; }
#line 14497 "parser_bison.c"
    break;

  case 1004: /* vlan_hdr_expr: "vlan" vlan_hdr_field close_scope_vlan  */
#line 5307 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_vlan, (yyvsp[-1].val));
			}
#line 14505 "parser_bison.c"
    break;

  case 1005: /* vlan_hdr_field: "id"  */
#line 5312 "parser_bison.y"
                                                { (yyval.val) = VLANHDR_VID; }
#line 14511 "parser_bison.c"
    break;

  case 1006: /* vlan_hdr_field: "cfi"  */
#line 5313 "parser_bison.y"
                                                { (yyval.val) = VLANHDR_CFI; }
#line 14517 "parser_bison.c"
    break;

  case 1007: /* vlan_hdr_field: "dei"  */
#line 5314 "parser_bison.y"
                                                { (yyval.val) = VLANHDR_DEI; }
#line 14523 "parser_bison.c"
    break;

  case 1008: /* vlan_hdr_field: "pcp"  */
#line 5315 "parser_bison.y"
                                                { (yyval.val) = VLANHDR_PCP; }
#line 14529 "parser_bison.c"
    break;

  case 1009: /* vlan_hdr_field: "type"  */
#line 5316 "parser_bison.y"
                                                { (yyval.val) = VLANHDR_TYPE; }
#line 14535 "parser_bison.c"
    break;

  case 1010: /* arp_hdr_expr: "arp" arp_hdr_field close_scope_arp  */
#line 5320 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_arp, (yyvsp[-1].val));
			}
#line 14543 "parser_bison.c"
    break;

  case 1011: /* arp_hdr_field: "htype"  */
#line 5325 "parser_bison.y"
                                                { (yyval.val) = ARPHDR_HRD; }
#line 14549 "parser_bison.c"
    break;

  case 1012: /* arp_hdr_field: "ptype"  */
#line 5326 "parser_bison.y"
                                                { (yyval.val) = ARPHDR_PRO; }
#line 14555 "parser_bison.c"
    break;

  case 1013: /* arp_hdr_field: "hlen"  */
#line 5327 "parser_bison.y"
                                                { (yyval.val) = ARPHDR_HLN; }
#line 14561 "parser_bison.c"
    break;

  case 1014: /* arp_hdr_field: "plen"  */
#line 5328 "parser_bison.y"
                                                { (yyval.val) = ARPHDR_PLN; }
#line 14567 "parser_bison.c"
    break;

  case 1015: /* arp_hdr_field: "operation"  */
#line 5329 "parser_bison.y"
                                                { (yyval.val) = ARPHDR_OP; }
#line 14573 "parser_bison.c"
    break;

  case 1016: /* arp_hdr_field: "saddr" "ether" close_scope_eth  */
#line 5330 "parser_bison.y"
                                                                { (yyval.val) = ARPHDR_SADDR_ETHER; }
#line 14579 "parser_bison.c"
    break;

  case 1017: /* arp_hdr_field: "daddr" "ether" close_scope_eth  */
#line 5331 "parser_bison.y"
                                                                { (yyval.val) = ARPHDR_DADDR_ETHER; }
#line 14585 "parser_bison.c"
    break;

  case 1018: /* arp_hdr_field: "saddr" "ip" close_scope_ip  */
#line 5332 "parser_bison.y"
                                                                { (yyval.val) = ARPHDR_SADDR_IP; }
#line 14591 "parser_bison.c"
    break;

  case 1019: /* arp_hdr_field: "daddr" "ip" close_scope_ip  */
#line 5333 "parser_bison.y"
                                                                { (yyval.val) = ARPHDR_DADDR_IP; }
#line 14597 "parser_bison.c"
    break;

  case 1020: /* ip_hdr_expr: "ip" ip_hdr_field close_scope_ip  */
#line 5337 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_ip, (yyvsp[-1].val));
			}
#line 14605 "parser_bison.c"
    break;

  case 1021: /* ip_hdr_expr: "ip" "option" ip_option_type ip_option_field close_scope_ip  */
#line 5341 "parser_bison.y"
                        {
				(yyval.expr) = ipopt_expr_alloc(&(yyloc), (yyvsp[-2].val), (yyvsp[-1].val));
				if (!(yyval.expr)) {
					erec_queue(error(&(yylsp[-4]), "unknown ip option type/field"), state->msgs);
					YYERROR;
				}
			}
#line 14617 "parser_bison.c"
    break;

  case 1022: /* ip_hdr_expr: "ip" "option" ip_option_type close_scope_ip  */
#line 5349 "parser_bison.y"
                        {
				(yyval.expr) = ipopt_expr_alloc(&(yyloc), (yyvsp[-1].val), IPOPT_FIELD_TYPE);
				(yyval.expr)->exthdr.flags = NFT_EXTHDR_F_PRESENT;
			}
#line 14626 "parser_bison.c"
    break;

  case 1023: /* ip_hdr_field: "version"  */
#line 5355 "parser_bison.y"
                                                { (yyval.val) = IPHDR_VERSION; }
#line 14632 "parser_bison.c"
    break;

  case 1024: /* ip_hdr_field: "hdrlength"  */
#line 5356 "parser_bison.y"
                                                { (yyval.val) = IPHDR_HDRLENGTH; }
#line 14638 "parser_bison.c"
    break;

  case 1025: /* ip_hdr_field: "dscp"  */
#line 5357 "parser_bison.y"
                                                { (yyval.val) = IPHDR_DSCP; }
#line 14644 "parser_bison.c"
    break;

  case 1026: /* ip_hdr_field: "ecn"  */
#line 5358 "parser_bison.y"
                                                { (yyval.val) = IPHDR_ECN; }
#line 14650 "parser_bison.c"
    break;

  case 1027: /* ip_hdr_field: "length"  */
#line 5359 "parser_bison.y"
                                                { (yyval.val) = IPHDR_LENGTH; }
#line 14656 "parser_bison.c"
    break;

  case 1028: /* ip_hdr_field: "id"  */
#line 5360 "parser_bison.y"
                                                { (yyval.val) = IPHDR_ID; }
#line 14662 "parser_bison.c"
    break;

  case 1029: /* ip_hdr_field: "frag-off"  */
#line 5361 "parser_bison.y"
                                                { (yyval.val) = IPHDR_FRAG_OFF; }
#line 14668 "parser_bison.c"
    break;

  case 1030: /* ip_hdr_field: "ttl"  */
#line 5362 "parser_bison.y"
                                                { (yyval.val) = IPHDR_TTL; }
#line 14674 "parser_bison.c"
    break;

  case 1031: /* ip_hdr_field: "protocol"  */
#line 5363 "parser_bison.y"
                                                { (yyval.val) = IPHDR_PROTOCOL; }
#line 14680 "parser_bison.c"
    break;

  case 1032: /* ip_hdr_field: "checksum"  */
#line 5364 "parser_bison.y"
                                                { (yyval.val) = IPHDR_CHECKSUM; }
#line 14686 "parser_bison.c"
    break;

  case 1033: /* ip_hdr_field: "saddr"  */
#line 5365 "parser_bison.y"
                                                { (yyval.val) = IPHDR_SADDR; }
#line 14692 "parser_bison.c"
    break;

  case 1034: /* ip_hdr_field: "daddr"  */
#line 5366 "parser_bison.y"
                                                { (yyval.val) = IPHDR_DADDR; }
#line 14698 "parser_bison.c"
    break;

  case 1035: /* ip_option_type: "lsrr"  */
#line 5369 "parser_bison.y"
                                                { (yyval.val) = IPOPT_LSRR; }
#line 14704 "parser_bison.c"
    break;

  case 1036: /* ip_option_type: "rr"  */
#line 5370 "parser_bison.y"
                                                { (yyval.val) = IPOPT_RR; }
#line 14710 "parser_bison.c"
    break;

  case 1037: /* ip_option_type: "ssrr"  */
#line 5371 "parser_bison.y"
                                                { (yyval.val) = IPOPT_SSRR; }
#line 14716 "parser_bison.c"
    break;

  case 1038: /* ip_option_type: "ra"  */
#line 5372 "parser_bison.y"
                                                { (yyval.val) = IPOPT_RA; }
#line 14722 "parser_bison.c"
    break;

  case 1039: /* ip_option_field: "type"  */
#line 5375 "parser_bison.y"
                                                { (yyval.val) = IPOPT_FIELD_TYPE; }
#line 14728 "parser_bison.c"
    break;

  case 1040: /* ip_option_field: "length"  */
#line 5376 "parser_bison.y"
                                                { (yyval.val) = IPOPT_FIELD_LENGTH; }
#line 14734 "parser_bison.c"
    break;

  case 1041: /* ip_option_field: "value"  */
#line 5377 "parser_bison.y"
                                                { (yyval.val) = IPOPT_FIELD_VALUE; }
#line 14740 "parser_bison.c"
    break;

  case 1042: /* ip_option_field: "ptr"  */
#line 5378 "parser_bison.y"
                                                { (yyval.val) = IPOPT_FIELD_PTR; }
#line 14746 "parser_bison.c"
    break;

  case 1043: /* ip_option_field: "addr"  */
#line 5379 "parser_bison.y"
                                                { (yyval.val) = IPOPT_FIELD_ADDR_0; }
#line 14752 "parser_bison.c"
    break;

  case 1044: /* icmp_hdr_expr: "icmp" icmp_hdr_field  */
#line 5383 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_icmp, (yyvsp[0].val));
			}
#line 14760 "parser_bison.c"
    break;

  case 1045: /* icmp_hdr_field: "type"  */
#line 5388 "parser_bison.y"
                                                { (yyval.val) = ICMPHDR_TYPE; }
#line 14766 "parser_bison.c"
    break;

  case 1046: /* icmp_hdr_field: "code"  */
#line 5389 "parser_bison.y"
                                                { (yyval.val) = ICMPHDR_CODE; }
#line 14772 "parser_bison.c"
    break;

  case 1047: /* icmp_hdr_field: "checksum"  */
#line 5390 "parser_bison.y"
                                                { (yyval.val) = ICMPHDR_CHECKSUM; }
#line 14778 "parser_bison.c"
    break;

  case 1048: /* icmp_hdr_field: "id"  */
#line 5391 "parser_bison.y"
                                                { (yyval.val) = ICMPHDR_ID; }
#line 14784 "parser_bison.c"
    break;

  case 1049: /* icmp_hdr_field: "seq"  */
#line 5392 "parser_bison.y"
                                                { (yyval.val) = ICMPHDR_SEQ; }
#line 14790 "parser_bison.c"
    break;

  case 1050: /* icmp_hdr_field: "gateway"  */
#line 5393 "parser_bison.y"
                                                { (yyval.val) = ICMPHDR_GATEWAY; }
#line 14796 "parser_bison.c"
    break;

  case 1051: /* icmp_hdr_field: "mtu"  */
#line 5394 "parser_bison.y"
                                                { (yyval.val) = ICMPHDR_MTU; }
#line 14802 "parser_bison.c"
    break;

  case 1052: /* igmp_hdr_expr: "igmp" igmp_hdr_field  */
#line 5398 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_igmp, (yyvsp[0].val));
			}
#line 14810 "parser_bison.c"
    break;

  case 1053: /* igmp_hdr_field: "type"  */
#line 5403 "parser_bison.y"
                                                { (yyval.val) = IGMPHDR_TYPE; }
#line 14816 "parser_bison.c"
    break;

  case 1054: /* igmp_hdr_field: "checksum"  */
#line 5404 "parser_bison.y"
                                                { (yyval.val) = IGMPHDR_CHECKSUM; }
#line 14822 "parser_bison.c"
    break;

  case 1055: /* igmp_hdr_field: "mrt"  */
#line 5405 "parser_bison.y"
                                                { (yyval.val) = IGMPHDR_MRT; }
#line 14828 "parser_bison.c"
    break;

  case 1056: /* igmp_hdr_field: "group"  */
#line 5406 "parser_bison.y"
                                                { (yyval.val) = IGMPHDR_GROUP; }
#line 14834 "parser_bison.c"
    break;

  case 1057: /* ip6_hdr_expr: "ip6" ip6_hdr_field close_scope_ip6  */
#line 5410 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_ip6, (yyvsp[-1].val));
			}
#line 14842 "parser_bison.c"
    break;

  case 1058: /* ip6_hdr_field: "version"  */
#line 5415 "parser_bison.y"
                                                { (yyval.val) = IP6HDR_VERSION; }
#line 14848 "parser_bison.c"
    break;

  case 1059: /* ip6_hdr_field: "dscp"  */
#line 5416 "parser_bison.y"
                                                { (yyval.val) = IP6HDR_DSCP; }
#line 14854 "parser_bison.c"
    break;

  case 1060: /* ip6_hdr_field: "ecn"  */
#line 5417 "parser_bison.y"
                                                { (yyval.val) = IP6HDR_ECN; }
#line 14860 "parser_bison.c"
    break;

  case 1061: /* ip6_hdr_field: "flowlabel"  */
#line 5418 "parser_bison.y"
                                                { (yyval.val) = IP6HDR_FLOWLABEL; }
#line 14866 "parser_bison.c"
    break;

  case 1062: /* ip6_hdr_field: "length"  */
#line 5419 "parser_bison.y"
                                                { (yyval.val) = IP6HDR_LENGTH; }
#line 14872 "parser_bison.c"
    break;

  case 1063: /* ip6_hdr_field: "nexthdr"  */
#line 5420 "parser_bison.y"
                                                { (yyval.val) = IP6HDR_NEXTHDR; }
#line 14878 "parser_bison.c"
    break;

  case 1064: /* ip6_hdr_field: "hoplimit"  */
#line 5421 "parser_bison.y"
                                                { (yyval.val) = IP6HDR_HOPLIMIT; }
#line 14884 "parser_bison.c"
    break;

  case 1065: /* ip6_hdr_field: "saddr"  */
#line 5422 "parser_bison.y"
                                                { (yyval.val) = IP6HDR_SADDR; }
#line 14890 "parser_bison.c"
    break;

  case 1066: /* ip6_hdr_field: "daddr"  */
#line 5423 "parser_bison.y"
                                                { (yyval.val) = IP6HDR_DADDR; }
#line 14896 "parser_bison.c"
    break;

  case 1067: /* icmp6_hdr_expr: "icmpv6" icmp6_hdr_field  */
#line 5426 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_icmp6, (yyvsp[0].val));
			}
#line 14904 "parser_bison.c"
    break;

  case 1068: /* icmp6_hdr_field: "type"  */
#line 5431 "parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_TYPE; }
#line 14910 "parser_bison.c"
    break;

  case 1069: /* icmp6_hdr_field: "code"  */
#line 5432 "parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_CODE; }
#line 14916 "parser_bison.c"
    break;

  case 1070: /* icmp6_hdr_field: "checksum"  */
#line 5433 "parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_CHECKSUM; }
#line 14922 "parser_bison.c"
    break;

  case 1071: /* icmp6_hdr_field: "param-problem"  */
#line 5434 "parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_PPTR; }
#line 14928 "parser_bison.c"
    break;

  case 1072: /* icmp6_hdr_field: "mtu"  */
#line 5435 "parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_MTU; }
#line 14934 "parser_bison.c"
    break;

  case 1073: /* icmp6_hdr_field: "id"  */
#line 5436 "parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_ID; }
#line 14940 "parser_bison.c"
    break;

  case 1074: /* icmp6_hdr_field: "seq"  */
#line 5437 "parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_SEQ; }
#line 14946 "parser_bison.c"
    break;

  case 1075: /* icmp6_hdr_field: "max-delay"  */
#line 5438 "parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_MAXDELAY; }
#line 14952 "parser_bison.c"
    break;

  case 1076: /* auth_hdr_expr: "ah" auth_hdr_field  */
#line 5442 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_ah, (yyvsp[0].val));
			}
#line 14960 "parser_bison.c"
    break;

  case 1077: /* auth_hdr_field: "nexthdr"  */
#line 5447 "parser_bison.y"
                                                { (yyval.val) = AHHDR_NEXTHDR; }
#line 14966 "parser_bison.c"
    break;

  case 1078: /* auth_hdr_field: "hdrlength"  */
#line 5448 "parser_bison.y"
                                                { (yyval.val) = AHHDR_HDRLENGTH; }
#line 14972 "parser_bison.c"
    break;

  case 1079: /* auth_hdr_field: "reserved"  */
#line 5449 "parser_bison.y"
                                                { (yyval.val) = AHHDR_RESERVED; }
#line 14978 "parser_bison.c"
    break;

  case 1080: /* auth_hdr_field: "spi"  */
#line 5450 "parser_bison.y"
                                                { (yyval.val) = AHHDR_SPI; }
#line 14984 "parser_bison.c"
    break;

  case 1081: /* auth_hdr_field: "seq"  */
#line 5451 "parser_bison.y"
                                                { (yyval.val) = AHHDR_SEQUENCE; }
#line 14990 "parser_bison.c"
    break;

  case 1082: /* esp_hdr_expr: "esp" esp_hdr_field  */
#line 5455 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_esp, (yyvsp[0].val));
			}
#line 14998 "parser_bison.c"
    break;

  case 1083: /* esp_hdr_field: "spi"  */
#line 5460 "parser_bison.y"
                                                { (yyval.val) = ESPHDR_SPI; }
#line 15004 "parser_bison.c"
    break;

  case 1084: /* esp_hdr_field: "seq"  */
#line 5461 "parser_bison.y"
                                                { (yyval.val) = ESPHDR_SEQUENCE; }
#line 15010 "parser_bison.c"
    break;

  case 1085: /* comp_hdr_expr: "comp" comp_hdr_field  */
#line 5465 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_comp, (yyvsp[0].val));
			}
#line 15018 "parser_bison.c"
    break;

  case 1086: /* comp_hdr_field: "nexthdr"  */
#line 5470 "parser_bison.y"
                                                { (yyval.val) = COMPHDR_NEXTHDR; }
#line 15024 "parser_bison.c"
    break;

  case 1087: /* comp_hdr_field: "flags"  */
#line 5471 "parser_bison.y"
                                                { (yyval.val) = COMPHDR_FLAGS; }
#line 15030 "parser_bison.c"
    break;

  case 1088: /* comp_hdr_field: "cpi"  */
#line 5472 "parser_bison.y"
                                                { (yyval.val) = COMPHDR_CPI; }
#line 15036 "parser_bison.c"
    break;

  case 1089: /* udp_hdr_expr: "udp" udp_hdr_field  */
#line 5476 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_udp, (yyvsp[0].val));
			}
#line 15044 "parser_bison.c"
    break;

  case 1090: /* udp_hdr_field: "sport"  */
#line 5481 "parser_bison.y"
                                                { (yyval.val) = UDPHDR_SPORT; }
#line 15050 "parser_bison.c"
    break;

  case 1091: /* udp_hdr_field: "dport"  */
#line 5482 "parser_bison.y"
                                                { (yyval.val) = UDPHDR_DPORT; }
#line 15056 "parser_bison.c"
    break;

  case 1092: /* udp_hdr_field: "length"  */
#line 5483 "parser_bison.y"
                                                { (yyval.val) = UDPHDR_LENGTH; }
#line 15062 "parser_bison.c"
    break;

  case 1093: /* udp_hdr_field: "checksum"  */
#line 5484 "parser_bison.y"
                                                { (yyval.val) = UDPHDR_CHECKSUM; }
#line 15068 "parser_bison.c"
    break;

  case 1094: /* udplite_hdr_expr: "udplite" udplite_hdr_field  */
#line 5488 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_udplite, (yyvsp[0].val));
			}
#line 15076 "parser_bison.c"
    break;

  case 1095: /* udplite_hdr_field: "sport"  */
#line 5493 "parser_bison.y"
                                                { (yyval.val) = UDPHDR_SPORT; }
#line 15082 "parser_bison.c"
    break;

  case 1096: /* udplite_hdr_field: "dport"  */
#line 5494 "parser_bison.y"
                                                { (yyval.val) = UDPHDR_DPORT; }
#line 15088 "parser_bison.c"
    break;

  case 1097: /* udplite_hdr_field: "csumcov"  */
#line 5495 "parser_bison.y"
                                                { (yyval.val) = UDPHDR_LENGTH; }
#line 15094 "parser_bison.c"
    break;

  case 1098: /* udplite_hdr_field: "checksum"  */
#line 5496 "parser_bison.y"
                                                { (yyval.val) = UDPHDR_CHECKSUM; }
#line 15100 "parser_bison.c"
    break;

  case 1099: /* tcp_hdr_expr: "tcp" tcp_hdr_field  */
#line 5500 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_tcp, (yyvsp[0].val));
			}
#line 15108 "parser_bison.c"
    break;

  case 1100: /* tcp_hdr_expr: "tcp" "option" tcp_hdr_option_type  */
#line 5504 "parser_bison.y"
                        {
				(yyval.expr) = tcpopt_expr_alloc(&(yyloc), (yyvsp[0].val), TCPOPT_COMMON_KIND);
				(yyval.expr)->exthdr.flags = NFT_EXTHDR_F_PRESENT;
			}
#line 15117 "parser_bison.c"
    break;

  case 1101: /* tcp_hdr_expr: "tcp" "option" tcp_hdr_option_kind_and_field  */
#line 5509 "parser_bison.y"
                        {
				(yyval.expr) = tcpopt_expr_alloc(&(yyloc), (yyvsp[0].tcp_kind_field).kind, (yyvsp[0].tcp_kind_field).field);
			}
#line 15125 "parser_bison.c"
    break;

  case 1102: /* tcp_hdr_expr: "tcp" "option" "@" tcp_hdr_option_type "comma" "number" "comma" "number"  */
#line 5513 "parser_bison.y"
                        {
				(yyval.expr) = tcpopt_expr_alloc(&(yyloc), (yyvsp[-4].val), 0);
				tcpopt_init_raw((yyval.expr), (yyvsp[-4].val), (yyvsp[-2].val), (yyvsp[0].val), 0);
			}
#line 15134 "parser_bison.c"
    break;

  case 1103: /* tcp_hdr_field: "sport"  */
#line 5519 "parser_bison.y"
                                                { (yyval.val) = TCPHDR_SPORT; }
#line 15140 "parser_bison.c"
    break;

  case 1104: /* tcp_hdr_field: "dport"  */
#line 5520 "parser_bison.y"
                                                { (yyval.val) = TCPHDR_DPORT; }
#line 15146 "parser_bison.c"
    break;

  case 1105: /* tcp_hdr_field: "seq"  */
#line 5521 "parser_bison.y"
                                                { (yyval.val) = TCPHDR_SEQ; }
#line 15152 "parser_bison.c"
    break;

  case 1106: /* tcp_hdr_field: "ackseq"  */
#line 5522 "parser_bison.y"
                                                { (yyval.val) = TCPHDR_ACKSEQ; }
#line 15158 "parser_bison.c"
    break;

  case 1107: /* tcp_hdr_field: "doff"  */
#line 5523 "parser_bison.y"
                                                { (yyval.val) = TCPHDR_DOFF; }
#line 15164 "parser_bison.c"
    break;

  case 1108: /* tcp_hdr_field: "reserved"  */
#line 5524 "parser_bison.y"
                                                { (yyval.val) = TCPHDR_RESERVED; }
#line 15170 "parser_bison.c"
    break;

  case 1109: /* tcp_hdr_field: "flags"  */
#line 5525 "parser_bison.y"
                                                { (yyval.val) = TCPHDR_FLAGS; }
#line 15176 "parser_bison.c"
    break;

  case 1110: /* tcp_hdr_field: "window"  */
#line 5526 "parser_bison.y"
                                                { (yyval.val) = TCPHDR_WINDOW; }
#line 15182 "parser_bison.c"
    break;

  case 1111: /* tcp_hdr_field: "checksum"  */
#line 5527 "parser_bison.y"
                                                { (yyval.val) = TCPHDR_CHECKSUM; }
#line 15188 "parser_bison.c"
    break;

  case 1112: /* tcp_hdr_field: "urgptr"  */
#line 5528 "parser_bison.y"
                                                { (yyval.val) = TCPHDR_URGPTR; }
#line 15194 "parser_bison.c"
    break;

  case 1113: /* tcp_hdr_option_kind_and_field: "mss" tcpopt_field_maxseg  */
#line 5532 "parser_bison.y"
                                {
					struct tcp_kind_field kind_field = { .kind = TCPOPT_KIND_MAXSEG, .field = (yyvsp[0].val) };
					(yyval.tcp_kind_field) = kind_field;
				}
#line 15203 "parser_bison.c"
    break;

  case 1114: /* tcp_hdr_option_kind_and_field: tcp_hdr_option_sack tcpopt_field_sack  */
#line 5537 "parser_bison.y"
                                {
					struct tcp_kind_field kind_field = { .kind = (yyvsp[-1].val), .field = (yyvsp[0].val) };
					(yyval.tcp_kind_field) = kind_field;
				}
#line 15212 "parser_bison.c"
    break;

  case 1115: /* tcp_hdr_option_kind_and_field: "window" tcpopt_field_window  */
#line 5542 "parser_bison.y"
                                {
					struct tcp_kind_field kind_field = { .kind = TCPOPT_KIND_WINDOW, .field = (yyvsp[0].val) };
					(yyval.tcp_kind_field) = kind_field;
				}
#line 15221 "parser_bison.c"
    break;

  case 1116: /* tcp_hdr_option_kind_and_field: "timestamp" tcpopt_field_tsopt  */
#line 5547 "parser_bison.y"
                                {
					struct tcp_kind_field kind_field = { .kind = TCPOPT_KIND_TIMESTAMP, .field = (yyvsp[0].val) };
					(yyval.tcp_kind_field) = kind_field;
				}
#line 15230 "parser_bison.c"
    break;

  case 1117: /* tcp_hdr_option_kind_and_field: tcp_hdr_option_type "length"  */
#line 5552 "parser_bison.y"
                                {
					struct tcp_kind_field kind_field = { .kind = (yyvsp[-1].val), .field = TCPOPT_COMMON_LENGTH };
					(yyval.tcp_kind_field) = kind_field;
				}
#line 15239 "parser_bison.c"
    break;

  case 1118: /* tcp_hdr_option_kind_and_field: "mptcp" tcpopt_field_mptcp  */
#line 5557 "parser_bison.y"
                                {
					struct tcp_kind_field kind_field = { .kind = TCPOPT_KIND_MPTCP, .field = (yyvsp[0].val) };
					(yyval.tcp_kind_field) = kind_field;
				}
#line 15248 "parser_bison.c"
    break;

  case 1119: /* tcp_hdr_option_sack: "sack"  */
#line 5563 "parser_bison.y"
                                                { (yyval.val) = TCPOPT_KIND_SACK; }
#line 15254 "parser_bison.c"
    break;

  case 1120: /* tcp_hdr_option_sack: "sack0"  */
#line 5564 "parser_bison.y"
                                                { (yyval.val) = TCPOPT_KIND_SACK; }
#line 15260 "parser_bison.c"
    break;

  case 1121: /* tcp_hdr_option_sack: "sack1"  */
#line 5565 "parser_bison.y"
                                                { (yyval.val) = TCPOPT_KIND_SACK1; }
#line 15266 "parser_bison.c"
    break;

  case 1122: /* tcp_hdr_option_sack: "sack2"  */
#line 5566 "parser_bison.y"
                                                { (yyval.val) = TCPOPT_KIND_SACK2; }
#line 15272 "parser_bison.c"
    break;

  case 1123: /* tcp_hdr_option_sack: "sack3"  */
#line 5567 "parser_bison.y"
                                                { (yyval.val) = TCPOPT_KIND_SACK3; }
#line 15278 "parser_bison.c"
    break;

  case 1124: /* tcp_hdr_option_type: "echo"  */
#line 5570 "parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_ECHO; }
#line 15284 "parser_bison.c"
    break;

  case 1125: /* tcp_hdr_option_type: "eol"  */
#line 5571 "parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_EOL; }
#line 15290 "parser_bison.c"
    break;

  case 1126: /* tcp_hdr_option_type: "fastopen"  */
#line 5572 "parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_FASTOPEN; }
#line 15296 "parser_bison.c"
    break;

  case 1127: /* tcp_hdr_option_type: "md5sig"  */
#line 5573 "parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_MD5SIG; }
#line 15302 "parser_bison.c"
    break;

  case 1128: /* tcp_hdr_option_type: "mptcp"  */
#line 5574 "parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_MPTCP; }
#line 15308 "parser_bison.c"
    break;

  case 1129: /* tcp_hdr_option_type: "mss"  */
#line 5575 "parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_MAXSEG; }
#line 15314 "parser_bison.c"
    break;

  case 1130: /* tcp_hdr_option_type: "nop"  */
#line 5576 "parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_NOP; }
#line 15320 "parser_bison.c"
    break;

  case 1131: /* tcp_hdr_option_type: "sack-permitted"  */
#line 5577 "parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_SACK_PERMITTED; }
#line 15326 "parser_bison.c"
    break;

  case 1132: /* tcp_hdr_option_type: "timestamp"  */
#line 5578 "parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_TIMESTAMP; }
#line 15332 "parser_bison.c"
    break;

  case 1133: /* tcp_hdr_option_type: "window"  */
#line 5579 "parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_WINDOW; }
#line 15338 "parser_bison.c"
    break;

  case 1134: /* tcp_hdr_option_type: tcp_hdr_option_sack  */
#line 5580 "parser_bison.y"
                                                        { (yyval.val) = (yyvsp[0].val); }
#line 15344 "parser_bison.c"
    break;

  case 1135: /* tcp_hdr_option_type: "number"  */
#line 5581 "parser_bison.y"
                                                        {
				if ((yyvsp[0].val) > 255) {
					erec_queue(error(&(yylsp[0]), "value too large"), state->msgs);
					YYERROR;
				}
				(yyval.val) = (yyvsp[0].val);
			}
#line 15356 "parser_bison.c"
    break;

  case 1136: /* tcpopt_field_sack: "left"  */
#line 5590 "parser_bison.y"
                                                { (yyval.val) = TCPOPT_SACK_LEFT; }
#line 15362 "parser_bison.c"
    break;

  case 1137: /* tcpopt_field_sack: "right"  */
#line 5591 "parser_bison.y"
                                                { (yyval.val) = TCPOPT_SACK_RIGHT; }
#line 15368 "parser_bison.c"
    break;

  case 1138: /* tcpopt_field_window: "count"  */
#line 5594 "parser_bison.y"
                                                { (yyval.val) = TCPOPT_WINDOW_COUNT; }
#line 15374 "parser_bison.c"
    break;

  case 1139: /* tcpopt_field_tsopt: "tsval"  */
#line 5597 "parser_bison.y"
                                                { (yyval.val) = TCPOPT_TS_TSVAL; }
#line 15380 "parser_bison.c"
    break;

  case 1140: /* tcpopt_field_tsopt: "tsecr"  */
#line 5598 "parser_bison.y"
                                                { (yyval.val) = TCPOPT_TS_TSECR; }
#line 15386 "parser_bison.c"
    break;

  case 1141: /* tcpopt_field_maxseg: "size"  */
#line 5601 "parser_bison.y"
                                                { (yyval.val) = TCPOPT_MAXSEG_SIZE; }
#line 15392 "parser_bison.c"
    break;

  case 1142: /* tcpopt_field_mptcp: "subtype"  */
#line 5604 "parser_bison.y"
                                                { (yyval.val) = TCPOPT_MPTCP_SUBTYPE; }
#line 15398 "parser_bison.c"
    break;

  case 1143: /* dccp_hdr_expr: "dccp" dccp_hdr_field  */
#line 5608 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_dccp, (yyvsp[0].val));
			}
#line 15406 "parser_bison.c"
    break;

  case 1144: /* dccp_hdr_field: "sport"  */
#line 5613 "parser_bison.y"
                                                { (yyval.val) = DCCPHDR_SPORT; }
#line 15412 "parser_bison.c"
    break;

  case 1145: /* dccp_hdr_field: "dport"  */
#line 5614 "parser_bison.y"
                                                { (yyval.val) = DCCPHDR_DPORT; }
#line 15418 "parser_bison.c"
    break;

  case 1146: /* dccp_hdr_field: "type"  */
#line 5615 "parser_bison.y"
                                                { (yyval.val) = DCCPHDR_TYPE; }
#line 15424 "parser_bison.c"
    break;

  case 1147: /* sctp_chunk_type: "data"  */
#line 5618 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_DATA; }
#line 15430 "parser_bison.c"
    break;

  case 1148: /* sctp_chunk_type: "init"  */
#line 5619 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_INIT; }
#line 15436 "parser_bison.c"
    break;

  case 1149: /* sctp_chunk_type: "init-ack"  */
#line 5620 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_INIT_ACK; }
#line 15442 "parser_bison.c"
    break;

  case 1150: /* sctp_chunk_type: "sack"  */
#line 5621 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_SACK; }
#line 15448 "parser_bison.c"
    break;

  case 1151: /* sctp_chunk_type: "heartbeat"  */
#line 5622 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_HEARTBEAT; }
#line 15454 "parser_bison.c"
    break;

  case 1152: /* sctp_chunk_type: "heartbeat-ack"  */
#line 5623 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_HEARTBEAT_ACK; }
#line 15460 "parser_bison.c"
    break;

  case 1153: /* sctp_chunk_type: "abort"  */
#line 5624 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_ABORT; }
#line 15466 "parser_bison.c"
    break;

  case 1154: /* sctp_chunk_type: "shutdown"  */
#line 5625 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_SHUTDOWN; }
#line 15472 "parser_bison.c"
    break;

  case 1155: /* sctp_chunk_type: "shutdown-ack"  */
#line 5626 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_SHUTDOWN_ACK; }
#line 15478 "parser_bison.c"
    break;

  case 1156: /* sctp_chunk_type: "error"  */
#line 5627 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_ERROR; }
#line 15484 "parser_bison.c"
    break;

  case 1157: /* sctp_chunk_type: "cookie-echo"  */
#line 5628 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_COOKIE_ECHO; }
#line 15490 "parser_bison.c"
    break;

  case 1158: /* sctp_chunk_type: "cookie-ack"  */
#line 5629 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_COOKIE_ACK; }
#line 15496 "parser_bison.c"
    break;

  case 1159: /* sctp_chunk_type: "ecne"  */
#line 5630 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_ECNE; }
#line 15502 "parser_bison.c"
    break;

  case 1160: /* sctp_chunk_type: "cwr"  */
#line 5631 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_CWR; }
#line 15508 "parser_bison.c"
    break;

  case 1161: /* sctp_chunk_type: "shutdown-complete"  */
#line 5632 "parser_bison.y"
                                                  { (yyval.val) = SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE; }
#line 15514 "parser_bison.c"
    break;

  case 1162: /* sctp_chunk_type: "asconf-ack"  */
#line 5633 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_ASCONF_ACK; }
#line 15520 "parser_bison.c"
    break;

  case 1163: /* sctp_chunk_type: "forward-tsn"  */
#line 5634 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_FORWARD_TSN; }
#line 15526 "parser_bison.c"
    break;

  case 1164: /* sctp_chunk_type: "asconf"  */
#line 5635 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_ASCONF; }
#line 15532 "parser_bison.c"
    break;

  case 1165: /* sctp_chunk_common_field: "type"  */
#line 5638 "parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_COMMON_TYPE; }
#line 15538 "parser_bison.c"
    break;

  case 1166: /* sctp_chunk_common_field: "flags"  */
#line 5639 "parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_COMMON_FLAGS; }
#line 15544 "parser_bison.c"
    break;

  case 1167: /* sctp_chunk_common_field: "length"  */
#line 5640 "parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_COMMON_LENGTH; }
#line 15550 "parser_bison.c"
    break;

  case 1168: /* sctp_chunk_data_field: "tsn"  */
#line 5643 "parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_DATA_TSN; }
#line 15556 "parser_bison.c"
    break;

  case 1169: /* sctp_chunk_data_field: "stream"  */
#line 5644 "parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_DATA_STREAM; }
#line 15562 "parser_bison.c"
    break;

  case 1170: /* sctp_chunk_data_field: "ssn"  */
#line 5645 "parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_DATA_SSN; }
#line 15568 "parser_bison.c"
    break;

  case 1171: /* sctp_chunk_data_field: "ppid"  */
#line 5646 "parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_DATA_PPID; }
#line 15574 "parser_bison.c"
    break;

  case 1172: /* sctp_chunk_init_field: "init-tag"  */
#line 5649 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_INIT_TAG; }
#line 15580 "parser_bison.c"
    break;

  case 1173: /* sctp_chunk_init_field: "a-rwnd"  */
#line 5650 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_INIT_RWND; }
#line 15586 "parser_bison.c"
    break;

  case 1174: /* sctp_chunk_init_field: "num-outbound-streams"  */
#line 5651 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_INIT_OSTREAMS; }
#line 15592 "parser_bison.c"
    break;

  case 1175: /* sctp_chunk_init_field: "num-inbound-streams"  */
#line 5652 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_INIT_ISTREAMS; }
#line 15598 "parser_bison.c"
    break;

  case 1176: /* sctp_chunk_init_field: "initial-tsn"  */
#line 5653 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_INIT_TSN; }
#line 15604 "parser_bison.c"
    break;

  case 1177: /* sctp_chunk_sack_field: "cum-tsn-ack"  */
#line 5656 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_SACK_CTSN_ACK; }
#line 15610 "parser_bison.c"
    break;

  case 1178: /* sctp_chunk_sack_field: "a-rwnd"  */
#line 5657 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_SACK_RWND; }
#line 15616 "parser_bison.c"
    break;

  case 1179: /* sctp_chunk_sack_field: "num-gap-ack-blocks"  */
#line 5658 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_SACK_GACK_BLOCKS; }
#line 15622 "parser_bison.c"
    break;

  case 1180: /* sctp_chunk_sack_field: "num-dup-tsns"  */
#line 5659 "parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_SACK_DUP_TSNS; }
#line 15628 "parser_bison.c"
    break;

  case 1181: /* sctp_chunk_alloc: sctp_chunk_type  */
#line 5663 "parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), (yyvsp[0].val), SCTP_CHUNK_COMMON_TYPE);
				(yyval.expr)->exthdr.flags = NFT_EXTHDR_F_PRESENT;
			}
#line 15637 "parser_bison.c"
    break;

  case 1182: /* sctp_chunk_alloc: sctp_chunk_type sctp_chunk_common_field  */
#line 5668 "parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), (yyvsp[-1].val), (yyvsp[0].val));
			}
#line 15645 "parser_bison.c"
    break;

  case 1183: /* sctp_chunk_alloc: "data" sctp_chunk_data_field  */
#line 5672 "parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_DATA, (yyvsp[0].val));
			}
#line 15653 "parser_bison.c"
    break;

  case 1184: /* sctp_chunk_alloc: "init" sctp_chunk_init_field  */
#line 5676 "parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_INIT, (yyvsp[0].val));
			}
#line 15661 "parser_bison.c"
    break;

  case 1185: /* sctp_chunk_alloc: "init-ack" sctp_chunk_init_field  */
#line 5680 "parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_INIT_ACK, (yyvsp[0].val));
			}
#line 15669 "parser_bison.c"
    break;

  case 1186: /* sctp_chunk_alloc: "sack" sctp_chunk_sack_field  */
#line 5684 "parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_SACK, (yyvsp[0].val));
			}
#line 15677 "parser_bison.c"
    break;

  case 1187: /* sctp_chunk_alloc: "shutdown" "cum-tsn-ack"  */
#line 5688 "parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_SHUTDOWN,
							   SCTP_CHUNK_SHUTDOWN_CTSN_ACK);
			}
#line 15686 "parser_bison.c"
    break;

  case 1188: /* sctp_chunk_alloc: "ecne" "lowest-tsn"  */
#line 5693 "parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_ECNE,
							   SCTP_CHUNK_ECNE_CWR_MIN_TSN);
			}
#line 15695 "parser_bison.c"
    break;

  case 1189: /* sctp_chunk_alloc: "cwr" "lowest-tsn"  */
#line 5698 "parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_CWR,
							   SCTP_CHUNK_ECNE_CWR_MIN_TSN);
			}
#line 15704 "parser_bison.c"
    break;

  case 1190: /* sctp_chunk_alloc: "asconf-ack" "seqno"  */
#line 5703 "parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_ASCONF_ACK,
							   SCTP_CHUNK_ASCONF_SEQNO);
			}
#line 15713 "parser_bison.c"
    break;

  case 1191: /* sctp_chunk_alloc: "forward-tsn" "new-cum-tsn"  */
#line 5708 "parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_FORWARD_TSN,
							   SCTP_CHUNK_FORWARD_TSN_NCTSN);
			}
#line 15722 "parser_bison.c"
    break;

  case 1192: /* sctp_chunk_alloc: "asconf" "seqno"  */
#line 5713 "parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_ASCONF,
							   SCTP_CHUNK_ASCONF_SEQNO);
			}
#line 15731 "parser_bison.c"
    break;

  case 1193: /* sctp_hdr_expr: "sctp" sctp_hdr_field close_scope_sctp  */
#line 5720 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_sctp, (yyvsp[-1].val));
			}
#line 15739 "parser_bison.c"
    break;

  case 1194: /* sctp_hdr_expr: "sctp" "chunk" sctp_chunk_alloc close_scope_sctp_chunk close_scope_sctp  */
#line 5724 "parser_bison.y"
                        {
				(yyval.expr) = (yyvsp[-2].expr);
			}
#line 15747 "parser_bison.c"
    break;

  case 1195: /* sctp_hdr_field: "sport"  */
#line 5729 "parser_bison.y"
                                                { (yyval.val) = SCTPHDR_SPORT; }
#line 15753 "parser_bison.c"
    break;

  case 1196: /* sctp_hdr_field: "dport"  */
#line 5730 "parser_bison.y"
                                                { (yyval.val) = SCTPHDR_DPORT; }
#line 15759 "parser_bison.c"
    break;

  case 1197: /* sctp_hdr_field: "vtag"  */
#line 5731 "parser_bison.y"
                                                { (yyval.val) = SCTPHDR_VTAG; }
#line 15765 "parser_bison.c"
    break;

  case 1198: /* sctp_hdr_field: "checksum"  */
#line 5732 "parser_bison.y"
                                                { (yyval.val) = SCTPHDR_CHECKSUM; }
#line 15771 "parser_bison.c"
    break;

  case 1199: /* th_hdr_expr: "th" th_hdr_field  */
#line 5736 "parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_th, (yyvsp[0].val));
				if ((yyval.expr))
					(yyval.expr)->payload.is_raw = true;
			}
#line 15781 "parser_bison.c"
    break;

  case 1200: /* th_hdr_field: "sport"  */
#line 5743 "parser_bison.y"
                                                { (yyval.val) = THDR_SPORT; }
#line 15787 "parser_bison.c"
    break;

  case 1201: /* th_hdr_field: "dport"  */
#line 5744 "parser_bison.y"
                                                { (yyval.val) = THDR_DPORT; }
#line 15793 "parser_bison.c"
    break;

  case 1210: /* hbh_hdr_expr: "hbh" hbh_hdr_field  */
#line 5758 "parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_hbh, (yyvsp[0].val));
			}
#line 15801 "parser_bison.c"
    break;

  case 1211: /* hbh_hdr_field: "nexthdr"  */
#line 5763 "parser_bison.y"
                                                { (yyval.val) = HBHHDR_NEXTHDR; }
#line 15807 "parser_bison.c"
    break;

  case 1212: /* hbh_hdr_field: "hdrlength"  */
#line 5764 "parser_bison.y"
                                                { (yyval.val) = HBHHDR_HDRLENGTH; }
#line 15813 "parser_bison.c"
    break;

  case 1213: /* rt_hdr_expr: "rt" rt_hdr_field close_scope_rt  */
#line 5768 "parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_rt, (yyvsp[-1].val));
			}
#line 15821 "parser_bison.c"
    break;

  case 1214: /* rt_hdr_field: "nexthdr"  */
#line 5773 "parser_bison.y"
                                                { (yyval.val) = RTHDR_NEXTHDR; }
#line 15827 "parser_bison.c"
    break;

  case 1215: /* rt_hdr_field: "hdrlength"  */
#line 5774 "parser_bison.y"
                                                { (yyval.val) = RTHDR_HDRLENGTH; }
#line 15833 "parser_bison.c"
    break;

  case 1216: /* rt_hdr_field: "type"  */
#line 5775 "parser_bison.y"
                                                { (yyval.val) = RTHDR_TYPE; }
#line 15839 "parser_bison.c"
    break;

  case 1217: /* rt_hdr_field: "seg-left"  */
#line 5776 "parser_bison.y"
                                                { (yyval.val) = RTHDR_SEG_LEFT; }
#line 15845 "parser_bison.c"
    break;

  case 1218: /* rt0_hdr_expr: "rt0" rt0_hdr_field  */
#line 5780 "parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_rt0, (yyvsp[0].val));
			}
#line 15853 "parser_bison.c"
    break;

  case 1219: /* rt0_hdr_field: "addr" '[' "number" ']'  */
#line 5786 "parser_bison.y"
                        {
				(yyval.val) = RT0HDR_ADDR_1 + (yyvsp[-1].val) - 1;
			}
#line 15861 "parser_bison.c"
    break;

  case 1220: /* rt2_hdr_expr: "rt2" rt2_hdr_field  */
#line 5792 "parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_rt2, (yyvsp[0].val));
			}
#line 15869 "parser_bison.c"
    break;

  case 1221: /* rt2_hdr_field: "addr"  */
#line 5797 "parser_bison.y"
                                                { (yyval.val) = RT2HDR_ADDR; }
#line 15875 "parser_bison.c"
    break;

  case 1222: /* rt4_hdr_expr: "srh" rt4_hdr_field  */
#line 5801 "parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_rt4, (yyvsp[0].val));
			}
#line 15883 "parser_bison.c"
    break;

  case 1223: /* rt4_hdr_field: "last-entry"  */
#line 5806 "parser_bison.y"
                                                { (yyval.val) = RT4HDR_LASTENT; }
#line 15889 "parser_bison.c"
    break;

  case 1224: /* rt4_hdr_field: "flags"  */
#line 5807 "parser_bison.y"
                                                { (yyval.val) = RT4HDR_FLAGS; }
#line 15895 "parser_bison.c"
    break;

  case 1225: /* rt4_hdr_field: "tag"  */
#line 5808 "parser_bison.y"
                                                { (yyval.val) = RT4HDR_TAG; }
#line 15901 "parser_bison.c"
    break;

  case 1226: /* rt4_hdr_field: "sid" '[' "number" ']'  */
#line 5810 "parser_bison.y"
                        {
				(yyval.val) = RT4HDR_SID_1 + (yyvsp[-1].val) - 1;
			}
#line 15909 "parser_bison.c"
    break;

  case 1227: /* frag_hdr_expr: "frag" frag_hdr_field  */
#line 5816 "parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_frag, (yyvsp[0].val));
			}
#line 15917 "parser_bison.c"
    break;

  case 1228: /* frag_hdr_field: "nexthdr"  */
#line 5821 "parser_bison.y"
                                                { (yyval.val) = FRAGHDR_NEXTHDR; }
#line 15923 "parser_bison.c"
    break;

  case 1229: /* frag_hdr_field: "reserved"  */
#line 5822 "parser_bison.y"
                                                { (yyval.val) = FRAGHDR_RESERVED; }
#line 15929 "parser_bison.c"
    break;

  case 1230: /* frag_hdr_field: "frag-off"  */
#line 5823 "parser_bison.y"
                                                { (yyval.val) = FRAGHDR_FRAG_OFF; }
#line 15935 "parser_bison.c"
    break;

  case 1231: /* frag_hdr_field: "reserved2"  */
#line 5824 "parser_bison.y"
                                                { (yyval.val) = FRAGHDR_RESERVED2; }
#line 15941 "parser_bison.c"
    break;

  case 1232: /* frag_hdr_field: "more-fragments"  */
#line 5825 "parser_bison.y"
                                                { (yyval.val) = FRAGHDR_MFRAGS; }
#line 15947 "parser_bison.c"
    break;

  case 1233: /* frag_hdr_field: "id"  */
#line 5826 "parser_bison.y"
                                                { (yyval.val) = FRAGHDR_ID; }
#line 15953 "parser_bison.c"
    break;

  case 1234: /* dst_hdr_expr: "dst" dst_hdr_field  */
#line 5830 "parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_dst, (yyvsp[0].val));
			}
#line 15961 "parser_bison.c"
    break;

  case 1235: /* dst_hdr_field: "nexthdr"  */
#line 5835 "parser_bison.y"
                                                { (yyval.val) = DSTHDR_NEXTHDR; }
#line 15967 "parser_bison.c"
    break;

  case 1236: /* dst_hdr_field: "hdrlength"  */
#line 5836 "parser_bison.y"
                                                { (yyval.val) = DSTHDR_HDRLENGTH; }
#line 15973 "parser_bison.c"
    break;

  case 1237: /* mh_hdr_expr: "mh" mh_hdr_field  */
#line 5840 "parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_mh, (yyvsp[0].val));
			}
#line 15981 "parser_bison.c"
    break;

  case 1238: /* mh_hdr_field: "nexthdr"  */
#line 5845 "parser_bison.y"
                                                { (yyval.val) = MHHDR_NEXTHDR; }
#line 15987 "parser_bison.c"
    break;

  case 1239: /* mh_hdr_field: "hdrlength"  */
#line 5846 "parser_bison.y"
                                                { (yyval.val) = MHHDR_HDRLENGTH; }
#line 15993 "parser_bison.c"
    break;

  case 1240: /* mh_hdr_field: "type"  */
#line 5847 "parser_bison.y"
                                                { (yyval.val) = MHHDR_TYPE; }
#line 15999 "parser_bison.c"
    break;

  case 1241: /* mh_hdr_field: "reserved"  */
#line 5848 "parser_bison.y"
                                                { (yyval.val) = MHHDR_RESERVED; }
#line 16005 "parser_bison.c"
    break;

  case 1242: /* mh_hdr_field: "checksum"  */
#line 5849 "parser_bison.y"
                                                { (yyval.val) = MHHDR_CHECKSUM; }
#line 16011 "parser_bison.c"
    break;

  case 1243: /* exthdr_exists_expr: "exthdr" exthdr_key  */
#line 5853 "parser_bison.y"
                        {
				const struct exthdr_desc *desc;

				desc = exthdr_find_proto((yyvsp[0].val));

				/* Assume that NEXTHDR template is always
				 * the fist one in list of templates.
				 */
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), desc, 1);
				(yyval.expr)->exthdr.flags = NFT_EXTHDR_F_PRESENT;
			}
#line 16027 "parser_bison.c"
    break;

  case 1244: /* exthdr_key: "hbh"  */
#line 5866 "parser_bison.y"
                                        { (yyval.val) = IPPROTO_HOPOPTS; }
#line 16033 "parser_bison.c"
    break;

  case 1245: /* exthdr_key: "rt" close_scope_rt  */
#line 5867 "parser_bison.y"
                                                        { (yyval.val) = IPPROTO_ROUTING; }
#line 16039 "parser_bison.c"
    break;

  case 1246: /* exthdr_key: "frag"  */
#line 5868 "parser_bison.y"
                                        { (yyval.val) = IPPROTO_FRAGMENT; }
#line 16045 "parser_bison.c"
    break;

  case 1247: /* exthdr_key: "dst"  */
#line 5869 "parser_bison.y"
                                        { (yyval.val) = IPPROTO_DSTOPTS; }
#line 16051 "parser_bison.c"
    break;

  case 1248: /* exthdr_key: "mh"  */
#line 5870 "parser_bison.y"
                                        { (yyval.val) = IPPROTO_MH; }
#line 16057 "parser_bison.c"
    break;


#line 16061 "parser_bison.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;
  *++yylsp = yyloc;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      {
        yypcontext_t yyctx
          = {yyssp, yytoken, &yylloc};
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == -1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *,
                             YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (yymsg)
              {
                yysyntax_error_status
                  = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
                yymsgp = yymsg;
              }
            else
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = YYENOMEM;
              }
          }
        yyerror (&yylloc, nft, scanner, state, yymsgp);
        if (yysyntax_error_status == YYENOMEM)
          goto yyexhaustedlab;
      }
    }

  yyerror_range[1] = yylloc;
  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= TOKEN_EOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == TOKEN_EOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, &yylloc, nft, scanner, state);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;

      yyerror_range[1] = *yylsp;
      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp, yylsp, nft, scanner, state);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  yyerror_range[2] = yylloc;
  ++yylsp;
  YYLLOC_DEFAULT (*yylsp, yyerror_range, 2);

  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;


#if 1
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (&yylloc, nft, scanner, state, YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturn;
#endif


/*-------------------------------------------------------.
| yyreturn -- parsing is finished, clean up and return.  |
`-------------------------------------------------------*/
yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, &yylloc, nft, scanner, state);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp, yylsp, nft, scanner, state);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
  return yyresult;
}

#line 5873 "parser_bison.y"

