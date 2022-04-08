/*
 * Meta expression/statement related definition and types.
 *
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/pkt_sched.h>
#include <linux/if_packet.h>

#include <nftables.h>
#include <expression.h>
#include <statement.h>
#include <datatype.h>
#include <meta.h>
#include <gmputil.h>
#include <utils.h>
#include <erec.h>
#include <iface.h>
#include <json.h>

#define _XOPEN_SOURCE
#define __USE_XOPEN
#include <time.h>

static void tchandle_type_print(const struct expr *expr,
				struct output_ctx *octx)
{
	uint32_t handle = mpz_get_uint32(expr->value);

	switch(handle) {
	case TC_H_ROOT:
		nft_print(octx, "root");
		break;
	case TC_H_UNSPEC:
		nft_print(octx, "none");
		break;
	default:
		nft_print(octx, "%0x:%0x",
			  TC_H_MAJ(handle) >> 16,
			  TC_H_MIN(handle));
		break;
	}
}

static struct error_record *tchandle_type_parse(struct parse_ctx *ctx,
						const struct expr *sym,
						struct expr **res)
{
	uint32_t handle;
	char *str = NULL;

	if (strcmp(sym->identifier, "root") == 0)
		handle = TC_H_ROOT;
	else if (strcmp(sym->identifier, "none") == 0)
		handle = TC_H_UNSPEC;
	else if (strchr(sym->identifier, ':')) {
		uint32_t tmp;
		char *colon;

		str = xstrdup(sym->identifier);

		colon = strchr(str, ':');
		if (!colon)
			goto err;

		*colon = '\0';

		errno = 0;
		tmp = strtoull(str, NULL, 16);
		if (errno != 0)
			goto err;

		handle = (tmp << 16);
		if (str[strlen(str) - 1] == ':')
			goto out;

		errno = 0;
		tmp = strtoull(colon + 1, NULL, 16);
		if (errno != 0)
			goto err;

		handle |= tmp;
	} else {
		handle = strtoull(sym->identifier, NULL, 0);
	}
out:
	xfree(str);
	*res = constant_expr_alloc(&sym->location, sym->dtype,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(handle) * BITS_PER_BYTE, &handle);
	return NULL;
err:
	xfree(str);
	return error(&sym->location, "Could not parse %s", sym->dtype->desc);
}

const struct datatype tchandle_type = {
	.type		= TYPE_CLASSID,
	.name		= "classid",
	.desc		= "TC classid",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= tchandle_type_print,
	.parse		= tchandle_type_parse,
};

static void ifindex_type_print(const struct expr *expr, struct output_ctx *octx)
{
	char name[IFNAMSIZ];
	int ifindex;

	ifindex = mpz_get_uint32(expr->value);
	if (nft_if_indextoname(ifindex, name))
		nft_print(octx, "\"%s\"", name);
	else
		nft_print(octx, "%d", ifindex);
}

static struct error_record *ifindex_type_parse(struct parse_ctx *ctx,
					       const struct expr *sym,
					       struct expr **res)
{
	int ifindex;

	ifindex = nft_if_nametoindex(sym->identifier);
	if (ifindex == 0) {
		char *end;
		long res;

		errno = 0;
		res = strtol(sym->identifier, &end, 10);

		if (res < 0 || res > INT_MAX || *end || errno)
			return error(&sym->location, "Interface does not exist");

		ifindex = (int)res;
	}

	*res = constant_expr_alloc(&sym->location, sym->dtype,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(ifindex) * BITS_PER_BYTE, &ifindex);
	return NULL;
}

const struct datatype ifindex_type = {
	.type		= TYPE_IFINDEX,
	.name		= "iface_index",
	.desc		= "network interface index",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= ifindex_type_print,
	.parse		= ifindex_type_parse,
};

static const struct symbol_table arphrd_tbl = {
	.base		= BASE_HEXADECIMAL,
	.symbols	= {
		SYMBOL("ether",		ARPHRD_ETHER),
		SYMBOL("ppp",		ARPHRD_PPP),
		/* dummy types */
		SYMBOL("ipip",		ARPHRD_TUNNEL),
		SYMBOL("ipip6",		ARPHRD_TUNNEL6),
		SYMBOL("loopback",	ARPHRD_LOOPBACK),
		SYMBOL("sit",		ARPHRD_SIT),
		SYMBOL("ipgre",		ARPHRD_IPGRE),
		SYMBOL_LIST_END,
	},
};

const struct datatype arphrd_type = {
	.type		= TYPE_ARPHRD,
	.name		= "iface_type",
	.desc		= "network interface type",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 2 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.sym_tbl	= &arphrd_tbl,
};

static void uid_type_print(const struct expr *expr, struct output_ctx *octx)
{
	struct passwd *pw;

	if (nft_output_guid(octx)) {
		uint32_t uid = mpz_get_uint32(expr->value);

		pw = getpwuid(uid);
		if (pw != NULL)
			nft_print(octx, "\"%s\"", pw->pw_name);
		else
			nft_print(octx, "%d", uid);
		return;
	}
	expr_basetype(expr)->print(expr, octx);
}

static struct error_record *uid_type_parse(struct parse_ctx *ctx,
					   const struct expr *sym,
					   struct expr **res)
{
	struct passwd *pw;
	uid_t uid;
	char *endptr = NULL;

	pw = getpwnam(sym->identifier);
	if (pw != NULL)
		uid = pw->pw_uid;
	else {
		uint64_t _uid = strtoull(sym->identifier, &endptr, 10);

		if (_uid > UINT32_MAX)
			return error(&sym->location, "Value too large");
		else if (*endptr)
			return error(&sym->location, "User does not exist");
		uid = _uid;
	}

	*res = constant_expr_alloc(&sym->location, sym->dtype,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(pw->pw_uid) * BITS_PER_BYTE, &uid);
	return NULL;
}

const struct datatype uid_type = {
	.type		= TYPE_UID,
	.name		= "uid",
	.desc		= "user ID",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= sizeof(uid_t) * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= uid_type_print,
	.json		= uid_type_json,
	.parse		= uid_type_parse,
};

static void gid_type_print(const struct expr *expr, struct output_ctx *octx)
{
	struct group *gr;

	if (nft_output_guid(octx)) {
		uint32_t gid = mpz_get_uint32(expr->value);

		gr = getgrgid(gid);
		if (gr != NULL)
			nft_print(octx, "\"%s\"", gr->gr_name);
		else
			nft_print(octx, "%u", gid);
		return;
	}
	expr_basetype(expr)->print(expr, octx);
}

static struct error_record *gid_type_parse(struct parse_ctx *ctx,
					   const struct expr *sym,
					   struct expr **res)
{
	struct group *gr;
	gid_t gid;
	char *endptr = NULL;

	gr = getgrnam(sym->identifier);
	if (gr != NULL)
		gid = gr->gr_gid;
	else {
		uint64_t _gid = strtoull(sym->identifier, &endptr, 0);

		if (_gid > UINT32_MAX)
			return error(&sym->location, "Value too large");
		else if (*endptr)
			return error(&sym->location, "Group does not exist");
		gid = _gid;
	}

	*res = constant_expr_alloc(&sym->location, sym->dtype,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(gr->gr_gid) * BITS_PER_BYTE, &gid);
	return NULL;
}

const struct datatype gid_type = {
	.type		= TYPE_GID,
	.name		= "gid",
	.desc		= "group ID",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= sizeof(gid_t) * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= gid_type_print,
	.json		= gid_type_json,
	.parse		= gid_type_parse,
};

static const struct symbol_table pkttype_type_tbl = {
	.base		= BASE_DECIMAL,
	.symbols	= {
		SYMBOL("host", PACKET_HOST),
		SYMBOL("unicast", PACKET_HOST), /* backwards compat */
		SYMBOL("broadcast", PACKET_BROADCAST),
		SYMBOL("multicast", PACKET_MULTICAST),
		SYMBOL("other", PACKET_OTHERHOST),
		SYMBOL_LIST_END,
	},
};

static void pkttype_type_print(const struct expr *expr, struct output_ctx *octx)
{
	return symbolic_constant_print(&pkttype_type_tbl, expr, false, octx);
}

const struct datatype pkttype_type = {
	.type		= TYPE_PKTTYPE,
	.name		= "pkt_type",
	.desc		= "packet type",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= pkttype_type_print,
	.sym_tbl	= &pkttype_type_tbl,
};

void devgroup_table_init(struct nft_ctx *ctx)
{
	ctx->output.tbl.devgroup = rt_symbol_table_init("/etc/iproute2/group");
}

void devgroup_table_exit(struct nft_ctx *ctx)
{
	rt_symbol_table_free(ctx->output.tbl.devgroup);
}

static void devgroup_type_print(const struct expr *expr,
				struct output_ctx *octx)
{
	return symbolic_constant_print(octx->tbl.devgroup, expr, true, octx);
}

static struct error_record *devgroup_type_parse(struct parse_ctx *ctx,
						const struct expr *sym,
						struct expr **res)
{
	return symbolic_constant_parse(ctx, sym, ctx->tbl->devgroup, res);
}

const struct datatype devgroup_type = {
	.type		= TYPE_DEVGROUP,
	.name		= "devgroup",
	.desc		= "devgroup name",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= devgroup_type_print,
	.json		= devgroup_type_json,
	.parse		= devgroup_type_parse,
	.flags		= DTYPE_F_PREFIX,
};

const struct datatype ifname_type = {
	.type		= TYPE_IFNAME,
	.name		= "ifname",
	.desc		= "network interface name",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= IFNAMSIZ * BITS_PER_BYTE,
	.basetype	= &string_type,
};

static void date_type_print(const struct expr *expr, struct output_ctx *octx)
{
	uint64_t tstamp = mpz_get_uint64(expr->value);
	struct tm *tm, *cur_tm;
	char timestr[21];

	/* Convert from nanoseconds to seconds */
	tstamp /= 1000000000L;

	/* Obtain current tm, to add tm_gmtoff to the timestamp */
	cur_tm = localtime((time_t *) &tstamp);

	if (cur_tm)
		tstamp += cur_tm->tm_gmtoff;

	if ((tm = gmtime((time_t *) &tstamp)) != NULL &&
	     strftime(timestr, sizeof(timestr) - 1, "%F %T", tm))
		nft_print(octx, "\"%s\"", timestr);
	else
		nft_print(octx, "Error converting timestamp to printed time");
}

static time_t parse_iso_date(const char *sym)
{
	struct tm tm, *cur_tm;
	time_t ts;

	memset(&tm, 0, sizeof(struct tm));

	if (strptime(sym, "%F %T", &tm))
		goto success;
	if (strptime(sym, "%F %R", &tm))
		goto success;
	if (strptime(sym, "%F", &tm))
		goto success;

	return -1;

success:
	/*
	 * Overwriting TZ is problematic if we're parsing hour types in this same process,
	 * hence I'd rather use timegm() which doesn't take into account the TZ env variable,
	 * even though it's Linux-specific.
	 */
	ts = timegm(&tm);

	/* Obtain current tm as well (at the specified time), so that we can substract tm_gmtoff */
	cur_tm = localtime(&ts);

	if (ts == (time_t) -1 || cur_tm == NULL)
		return ts;

	/* Substract tm_gmtoff to get the current time */
	return ts - cur_tm->tm_gmtoff;
}

static struct error_record *date_type_parse(struct parse_ctx *ctx,
					    const struct expr *sym,
					    struct expr **res)
{
	const char *endptr = sym->identifier;
	time_t tstamp;

	if ((tstamp = parse_iso_date(sym->identifier)) != -1)
		goto success;

	tstamp = strtoul(sym->identifier, (char **) &endptr, 10);
	if (*endptr == '\0' && endptr != sym->identifier)
		goto success;

	return error(&sym->location, "Cannot parse date");

success:
	/* Convert to nanoseconds */
	tstamp *= 1000000000L;
	*res = constant_expr_alloc(&sym->location, sym->dtype,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(uint64_t) * BITS_PER_BYTE,
				   &tstamp);
	return NULL;
}

static const struct symbol_table day_type_tbl = {
	.base		= BASE_DECIMAL,
	.symbols	= {
		SYMBOL("Sunday", 0),
		SYMBOL("Monday", 1),
		SYMBOL("Tuesday", 2),
		SYMBOL("Wednesday", 3),
		SYMBOL("Thursday", 4),
		SYMBOL("Friday", 5),
		SYMBOL("Saturday", 6),
		SYMBOL_LIST_END,
	},
};

static void day_type_print(const struct expr *expr, struct output_ctx *octx)
{
	return symbolic_constant_print(&day_type_tbl, expr, true, octx);
}

#define SECONDS_PER_DAY	(60 * 60 * 24)

static void hour_type_print(const struct expr *expr, struct output_ctx *octx)
{
	uint32_t seconds = mpz_get_uint32(expr->value), minutes, hours;
	struct tm *cur_tm;
	time_t ts;

	/* Obtain current tm, so that we can add tm_gmtoff */
	ts = time(NULL);
	cur_tm = localtime(&ts);

	if (cur_tm)
		seconds = (seconds + cur_tm->tm_gmtoff) % SECONDS_PER_DAY;

	minutes = seconds / 60;
	seconds %= 60;
	hours = minutes / 60;
	minutes %= 60;

	nft_print(octx, "\"%02d:%02d", hours, minutes);
	if (seconds)
		nft_print(octx, ":%02d", seconds);
	nft_print(octx, "\"");
}

static struct error_record *hour_type_parse(struct parse_ctx *ctx,
					    const struct expr *sym,
					    struct expr **res)
{
	struct error_record *er;
	struct tm tm, *cur_tm;
	uint32_t result;
	uint64_t tmp;
	char *endptr;
	time_t ts;

	memset(&tm, 0, sizeof(struct tm));

	/* First, try to parse it as a number */
	result = strtoul(sym->identifier, (char **) &endptr, 10);
	if (*endptr == '\0' && endptr != sym->identifier)
		goto success;

	result = 0;

	/* Obtain current tm, so that we can substract tm_gmtoff */
	ts = time(NULL);
	cur_tm = localtime(&ts);

	endptr = strptime(sym->identifier, "%T", &tm);
	if (endptr && *endptr == '\0')
		goto convert;

	endptr = strptime(sym->identifier, "%R", &tm);
	if (endptr && *endptr == '\0')
		goto convert;

	if (endptr && *endptr)
		return error(&sym->location, "Can't parse trailing input: \"%s\"\n", endptr);

	if ((er = time_parse(&sym->location, sym->identifier, &tmp)) == NULL) {
		result = tmp / 1000;
		goto convert;
	}

	return er;

convert:
	/* Convert the hour to the number of seconds since midnight */
	if (result == 0)
		result = tm.tm_hour * 3600 + tm.tm_min * 60 + tm.tm_sec;

	/* Substract tm_gmtoff to get the current time */
	if (cur_tm) {
		if ((long int) result >= cur_tm->tm_gmtoff)
			result = (result - cur_tm->tm_gmtoff) % 86400;
		else
			result = 86400 - cur_tm->tm_gmtoff + result;
	}

success:
	*res = constant_expr_alloc(&sym->location, sym->dtype,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(uint32_t) * BITS_PER_BYTE,
				   &result);
	return NULL;
}

const struct datatype date_type = {
	.type = TYPE_TIME_DATE,
	.name = "time",
	.desc = "Relative time of packet reception",
	.byteorder = BYTEORDER_HOST_ENDIAN,
	.size = sizeof(uint64_t) * BITS_PER_BYTE,
	.basetype = &integer_type,
	.print = date_type_print,
	.parse = date_type_parse,
};

const struct datatype day_type = {
	.type = TYPE_TIME_DAY,
	.name = "day",
	.desc = "Day of week of packet reception",
	.byteorder = BYTEORDER_HOST_ENDIAN,
	.size = 1 * BITS_PER_BYTE,
	.basetype = &integer_type,
	.print = day_type_print,
	.sym_tbl = &day_type_tbl,
};

const struct datatype hour_type = {
	.type = TYPE_TIME_HOUR,
	.name = "hour",
	.desc = "Hour of day of packet reception",
	.byteorder = BYTEORDER_HOST_ENDIAN,
	.size = sizeof(uint32_t) * BITS_PER_BYTE,
	.basetype = &integer_type,
	.print = hour_type_print,
	.parse = hour_type_parse,
};

const struct meta_template meta_templates[] = {
	[NFT_META_LEN]		= META_TEMPLATE("length",    &integer_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_PROTOCOL]	= META_TEMPLATE("protocol",  &ethertype_type,
						2 * 8, BYTEORDER_BIG_ENDIAN),
	[NFT_META_NFPROTO]	= META_TEMPLATE("nfproto",   &nfproto_type,
						1 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_L4PROTO]	= META_TEMPLATE("l4proto",   &inet_protocol_type,
						1 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_PRIORITY]	= META_TEMPLATE("priority",  &tchandle_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_MARK]		= META_TEMPLATE("mark",      &mark_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_IIF]		= META_TEMPLATE("iif",       &ifindex_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_IIFNAME]	= META_TEMPLATE("iifname",   &ifname_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_IIFTYPE]	= META_TEMPLATE("iiftype",   &arphrd_type,
						2 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_OIF]		= META_TEMPLATE("oif",	     &ifindex_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_OIFNAME]	= META_TEMPLATE("oifname",   &ifname_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_OIFTYPE]	= META_TEMPLATE("oiftype",   &arphrd_type,
						2 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_SKUID]	= META_TEMPLATE("skuid",     &uid_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_SKGID]	= META_TEMPLATE("skgid",     &gid_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_NFTRACE]	= META_TEMPLATE("nftrace",   &integer_type,
						1    , BYTEORDER_HOST_ENDIAN),
	[NFT_META_RTCLASSID]	= META_TEMPLATE("rtclassid", &realm_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_BRI_IIFNAME]	= META_TEMPLATE("ibrname",  &ifname_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_BRI_OIFNAME]	= META_TEMPLATE("obrname",  &ifname_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_PKTTYPE]	= META_TEMPLATE("pkttype",   &pkttype_type,
						BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_CPU]		= META_TEMPLATE("cpu",	     &integer_type,
						4 * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_IIFGROUP]	= META_TEMPLATE("iifgroup",  &devgroup_type,
						4 * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_OIFGROUP]	= META_TEMPLATE("oifgroup",  &devgroup_type,
						4 * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_CGROUP]	= META_TEMPLATE("cgroup",    &integer_type,
						4 * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_PRANDOM]	= META_TEMPLATE("random",    &integer_type,
						4 * BITS_PER_BYTE,
						BYTEORDER_BIG_ENDIAN), /* avoid conversion; doesn't have endianess */
	[NFT_META_SECPATH]	= META_TEMPLATE("ipsec", &boolean_type,
						BITS_PER_BYTE, BYTEORDER_HOST_ENDIAN),
	[NFT_META_IIFKIND]	= META_TEMPLATE("iifkind",   &ifname_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_OIFKIND]	= META_TEMPLATE("oifkind",   &ifname_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_BRI_IIFPVID]	= META_TEMPLATE("ibrpvid",   &integer_type,
						2 * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_BRI_IIFVPROTO] = META_TEMPLATE("ibrvproto",   &ethertype_type,
						 2 * BITS_PER_BYTE,
						 BYTEORDER_BIG_ENDIAN),
	[NFT_META_TIME_NS]	= META_TEMPLATE("time",   &date_type,
						8 * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_TIME_DAY]	= META_TEMPLATE("day", &day_type,
						1 * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_TIME_HOUR]	= META_TEMPLATE("hour", &hour_type,
						4 * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_SECMARK]	= META_TEMPLATE("secmark", &integer_type,
						32, BYTEORDER_HOST_ENDIAN),
	[NFT_META_SDIF]		= META_TEMPLATE("sdif", &ifindex_type,
						sizeof(int) * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_SDIFNAME]	= META_TEMPLATE("sdifname", &ifname_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
};

static bool meta_key_is_unqualified(enum nft_meta_keys key)
{
	switch (key) {
	case NFT_META_IIF:
	case NFT_META_OIF:
	case NFT_META_IIFNAME:
	case NFT_META_OIFNAME:
	case NFT_META_IIFGROUP:
	case NFT_META_OIFGROUP:
		return true;
	default:
		return false;
	}
}

static void meta_expr_print(const struct expr *expr, struct output_ctx *octx)
{
	if (meta_key_is_unqualified(expr->meta.key))
		nft_print(octx, "%s",
			  meta_templates[expr->meta.key].token);
	else
		nft_print(octx, "meta %s",
			  meta_templates[expr->meta.key].token);
}

static bool meta_expr_cmp(const struct expr *e1, const struct expr *e2)
{
	return e1->meta.key == e2->meta.key;
}

static void meta_expr_clone(struct expr *new, const struct expr *expr)
{
	new->meta.key = expr->meta.key;
	new->meta.base = expr->meta.base;
}

/**
 * meta_expr_pctx_update - update protocol context based on meta match
 *
 * @ctx:	protocol context
 * @expr:	relational meta expression
 *
 * Update LL protocol context based on IIFTYPE meta match in non-LL hooks.
 */
static void meta_expr_pctx_update(struct proto_ctx *ctx,
				  const struct location *loc,
				  const struct expr *left,
				  const struct expr *right)
{
	const struct hook_proto_desc *h = &hook_proto_desc[ctx->family];
	const struct proto_desc *desc;
	uint8_t protonum;

	switch (left->meta.key) {
	case NFT_META_IIFTYPE:
		if (h->base < PROTO_BASE_NETWORK_HDR &&
		    ctx->family != NFPROTO_INET &&
		    ctx->family != NFPROTO_NETDEV)
			return;

		desc = proto_dev_desc(mpz_get_uint16(right->value));
		if (desc == NULL)
			desc = &proto_unknown;

		proto_ctx_update(ctx, PROTO_BASE_LL_HDR, loc, desc);
		break;
	case NFT_META_NFPROTO:
		protonum = mpz_get_uint8(right->value);
		desc = proto_find_upper(h->desc, protonum);
		if (desc == NULL) {
			desc = &proto_unknown;

			if (protonum == ctx->family &&
			    h->base == PROTO_BASE_NETWORK_HDR)
				desc = h->desc;
		}

		proto_ctx_update(ctx, PROTO_BASE_NETWORK_HDR, loc, desc);
		break;
	case NFT_META_L4PROTO:
		desc = proto_find_upper(&proto_inet_service,
					mpz_get_uint8(right->value));
		if (desc == NULL)
			desc = &proto_unknown;

		proto_ctx_update(ctx, PROTO_BASE_TRANSPORT_HDR, loc, desc);
		break;
	case NFT_META_PROTOCOL:
		if (h->base != PROTO_BASE_LL_HDR)
			return;

		if (ctx->family != NFPROTO_NETDEV &&
		    ctx->family != NFPROTO_BRIDGE)
			return;

		desc = proto_find_upper(h->desc, ntohs(mpz_get_uint16(right->value)));
		if (desc == NULL)
			desc = &proto_unknown;

		proto_ctx_update(ctx, PROTO_BASE_NETWORK_HDR, loc, desc);
		break;
	default:
		break;
	}
}

#define NFTNL_UDATA_META_KEY 0
#define NFTNL_UDATA_META_MAX 1

static int meta_expr_build_udata(struct nftnl_udata_buf *udbuf,
				 const struct expr *expr)
{
	nftnl_udata_put_u32(udbuf, NFTNL_UDATA_META_KEY, expr->meta.key);

	return 0;
}

static int meta_parse_udata(const struct nftnl_udata *attr, void *data)
{
	const struct nftnl_udata **ud = data;
	uint8_t type = nftnl_udata_type(attr);
	uint8_t len = nftnl_udata_len(attr);

	switch (type) {
	case NFTNL_UDATA_META_KEY:
		if (len != sizeof(uint32_t))
			return -1;
		break;
	default:
		return 0;
	}

	ud[type] = attr;
	return 0;
}

static struct expr *meta_expr_parse_udata(const struct nftnl_udata *attr)
{
	const struct nftnl_udata *ud[NFTNL_UDATA_META_MAX + 1] = {};
	uint32_t key;
	int err;

	err = nftnl_udata_parse(nftnl_udata_get(attr), nftnl_udata_len(attr),
				meta_parse_udata, ud);
	if (err < 0)
		return NULL;

	if (!ud[NFTNL_UDATA_META_KEY])
		return NULL;

	key = nftnl_udata_get_u32(ud[NFTNL_UDATA_META_KEY]);

	return meta_expr_alloc(&internal_location, key);
}

const struct expr_ops meta_expr_ops = {
	.type		= EXPR_META,
	.name		= "meta",
	.print		= meta_expr_print,
	.json		= meta_expr_json,
	.cmp		= meta_expr_cmp,
	.clone		= meta_expr_clone,
	.pctx_update	= meta_expr_pctx_update,
	.build_udata	= meta_expr_build_udata,
	.parse_udata	= meta_expr_parse_udata,
};

struct expr *meta_expr_alloc(const struct location *loc, enum nft_meta_keys key)
{
	const struct meta_template *tmpl = &meta_templates[key];
	struct expr *expr;

	expr = expr_alloc(loc, EXPR_META, tmpl->dtype,
			  tmpl->byteorder, tmpl->len);
	expr->meta.key = key;

	switch (key) {
	case NFT_META_IIFTYPE:
		expr->flags |= EXPR_F_PROTOCOL;
		break;
	case NFT_META_NFPROTO:
		expr->flags |= EXPR_F_PROTOCOL;
		expr->meta.base = PROTO_BASE_LL_HDR;
		break;
	case NFT_META_L4PROTO:
		expr->flags |= EXPR_F_PROTOCOL;
		expr->meta.base = PROTO_BASE_NETWORK_HDR;
		break;
	case NFT_META_PROTOCOL:
		expr->flags |= EXPR_F_PROTOCOL;
		expr->meta.base = PROTO_BASE_LL_HDR;
		break;
	default:
		break;
	}

	return expr;
}

static void meta_stmt_print(const struct stmt *stmt, struct output_ctx *octx)
{
	if (meta_key_is_unqualified(stmt->meta.key))
		nft_print(octx, "%s set ",
			  meta_templates[stmt->meta.key].token);
	else
		nft_print(octx, "meta %s set ",
			  meta_templates[stmt->meta.key].token);

	expr_print(stmt->meta.expr, octx);
}

static void meta_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->meta.expr);
}

static const struct stmt_ops meta_stmt_ops = {
	.type		= STMT_META,
	.name		= "meta",
	.print		= meta_stmt_print,
	.json		= meta_stmt_json,
	.destroy	= meta_stmt_destroy,
};

struct stmt *meta_stmt_alloc(const struct location *loc, enum nft_meta_keys key,
			     struct expr *expr)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &meta_stmt_ops);
	stmt->meta.key	= key;
	stmt->meta.tmpl	= &meta_templates[key];
	stmt->meta.expr	= expr;
	return stmt;
}

/*
 * @expr:	payload expression
 * @res:	dependency expression
 *
 * Generate a NFT_META_IIFTYPE expression to check for ethernet frames.
 * Only works on input path.
 */
struct stmt *meta_stmt_meta_iiftype(const struct location *loc, uint16_t type)
{
	struct expr *dep, *left, *right;

	left = meta_expr_alloc(loc, NFT_META_IIFTYPE);
	right = constant_expr_alloc(loc, &arphrd_type,
				    BYTEORDER_HOST_ENDIAN,
				    2 * BITS_PER_BYTE, &type);

	dep = relational_expr_alloc(loc, OP_EQ, left, right);
	return expr_stmt_alloc(&dep->location, dep);
}

struct error_record *meta_key_parse(const struct location *loc,
                                    const char *str,
                                    unsigned int *value)
{
	int ret, len, offset = 0;
	const char *sep = "";
	unsigned int i;
	char buf[1024];
	size_t size;

	for (i = 0; i < array_size(meta_templates); i++) {
		if (!meta_templates[i].token || strcmp(meta_templates[i].token, str))
			continue;

		*value = i;
		return NULL;
	}

	/* Backwards compat hack */
	if (strcmp(str, "ibriport") == 0) {
		*value = NFT_META_BRI_IIFNAME;
		return NULL;
	} else if (strcmp(str, "obriport") == 0) {
		*value = NFT_META_BRI_OIFNAME;
		return NULL;
	} else if (strcmp(str, "secpath") == 0) {
		*value = NFT_META_SECPATH;
		return NULL;
	}

	len = (int)sizeof(buf);
	size = sizeof(buf);

	for (i = 0; i < array_size(meta_templates); i++) {
		if (!meta_templates[i].token)
			continue;

		if (offset)
			sep = ", ";

		ret = snprintf(buf+offset, len, "%s%s", sep, meta_templates[i].token);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		assert(offset < (int)sizeof(buf));
	}

	return error(loc, "syntax error, unexpected %s, known keys are %s", str, buf);
}
