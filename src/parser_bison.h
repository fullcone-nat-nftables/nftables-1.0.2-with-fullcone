/* A Bison parser, made by GNU Bison 3.7.5.  */

/* Bison interface for Yacc-like parsers in C

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

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

#line 800 "parser_bison.h"

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
