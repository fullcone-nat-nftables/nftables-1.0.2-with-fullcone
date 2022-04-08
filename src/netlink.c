/*
 * Copyright (c) 2008-2012 Patrick McHardy <kaber@trash.net>
 * Copyright (c) 2013 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <string.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <inttypes.h>

#include <libnftnl/table.h>
#include <libnftnl/trace.h>
#include <libnftnl/chain.h>
#include <libnftnl/expr.h>
#include <libnftnl/object.h>
#include <libnftnl/set.h>
#include <libnftnl/flowtable.h>
#include <libnftnl/udata.h>
#include <libnftnl/ruleset.h>
#include <libnftnl/common.h>
#include <libnftnl/udata.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter.h>

#include <nftables.h>
#include <parser.h>
#include <netlink.h>
#include <mnl.h>
#include <expression.h>
#include <statement.h>
#include <gmputil.h>
#include <utils.h>
#include <erec.h>
#include <iface.h>

#define nft_mon_print(monh, ...) nft_print(&monh->ctx->nft->output, __VA_ARGS__)

const struct input_descriptor indesc_netlink = {
	.name	= "netlink",
	.type	= INDESC_NETLINK,
};

const struct location netlink_location = {
	.indesc	= &indesc_netlink,
};

void __noreturn __netlink_abi_error(const char *file, int line,
				    const char *reason)
{
	fprintf(stderr, "E: Contact urgently your Linux kernel vendor. "
		"Netlink ABI is broken: %s:%d %s\n", file, line, reason);
	abort();
}

int netlink_io_error(struct netlink_ctx *ctx, const struct location *loc,
		     const char *fmt, ...)
{
	struct error_record *erec;
	va_list ap;

	if (loc == NULL)
		loc = &netlink_location;

	va_start(ap, fmt);
	erec = erec_vcreate(EREC_ERROR, loc, fmt, ap);
	va_end(ap);
	erec_queue(erec, ctx->msgs);
	return -1;
}

void __noreturn __netlink_init_error(const char *filename, int line,
				     const char *reason)
{
	fprintf(stderr, "%s:%d: Unable to initialize Netlink socket: %s\n",
		filename, line, reason);
	exit(NFT_EXIT_NONL);
}

struct nftnl_expr *alloc_nft_expr(const char *name)
{
	struct nftnl_expr *nle;

	nle = nftnl_expr_alloc(name);
	if (nle == NULL)
		memory_allocation_error();

	return nle;
}

void __netlink_gen_data(const struct expr *expr,
			struct nft_data_linearize *data, bool expand);

struct nftnl_set_elem *alloc_nftnl_setelem(const struct expr *set,
					   const struct expr *expr)
{
	const struct expr *elem, *data;
	struct nftnl_set_elem *nlse;
	struct nft_data_linearize nld;
	struct nftnl_udata_buf *udbuf = NULL;
	uint32_t flags = 0;
	int num_exprs = 0;
	struct stmt *stmt;
	struct expr *key;

	nlse = nftnl_set_elem_alloc();
	if (nlse == NULL)
		memory_allocation_error();

	data = NULL;
	if (expr->etype == EXPR_MAPPING) {
		elem = expr->left;
		if (!(expr->flags & EXPR_F_INTERVAL_END))
			data = expr->right;
	} else {
		elem = expr;
	}
	if (elem->etype != EXPR_SET_ELEM)
		BUG("Unexpected expression type: got %d\n", elem->etype);

	key = elem->key;

	switch (key->etype) {
	case EXPR_SET_ELEM_CATCHALL:
		break;
	default:
		__netlink_gen_data(key, &nld, false);
		nftnl_set_elem_set(nlse, NFTNL_SET_ELEM_KEY, &nld.value, nld.len);
		if (set->set_flags & NFT_SET_INTERVAL &&
		    key->etype == EXPR_CONCAT && key->field_count > 1) {
			key->flags |= EXPR_F_INTERVAL_END;
			__netlink_gen_data(key, &nld, false);
			key->flags &= ~EXPR_F_INTERVAL_END;

			nftnl_set_elem_set(nlse, NFTNL_SET_ELEM_KEY_END,
					   &nld.value, nld.len);
		}
		break;
	}

	if (elem->timeout)
		nftnl_set_elem_set_u64(nlse, NFTNL_SET_ELEM_TIMEOUT,
				       elem->timeout);
	if (elem->expiration)
		nftnl_set_elem_set_u64(nlse, NFTNL_SET_ELEM_EXPIRATION,
				       elem->expiration);
	list_for_each_entry(stmt, &elem->stmt_list, list)
		num_exprs++;

	if (num_exprs == 1) {
		list_for_each_entry(stmt, &elem->stmt_list, list) {
			nftnl_set_elem_set(nlse, NFTNL_SET_ELEM_EXPR,
					   netlink_gen_stmt_stateful(stmt), 0);
		}
	} else if (num_exprs > 1) {
		list_for_each_entry(stmt, &elem->stmt_list, list) {
			nftnl_set_elem_add_expr(nlse,
						netlink_gen_stmt_stateful(stmt));
		}
	}
	if (elem->comment || expr->elem_flags) {
		udbuf = nftnl_udata_buf_alloc(NFT_USERDATA_MAXLEN);
		if (!udbuf)
			memory_allocation_error();
	}
	if (elem->comment) {
		if (!nftnl_udata_put_strz(udbuf, NFTNL_UDATA_SET_ELEM_COMMENT,
					  elem->comment))
			memory_allocation_error();
	}
	if (expr->elem_flags) {
		if (!nftnl_udata_put_u32(udbuf, NFTNL_UDATA_SET_ELEM_FLAGS,
					 expr->elem_flags))
			memory_allocation_error();
	}
	if (udbuf) {
		nftnl_set_elem_set(nlse, NFTNL_SET_ELEM_USERDATA,
				   nftnl_udata_buf_data(udbuf),
				   nftnl_udata_buf_len(udbuf));
		nftnl_udata_buf_free(udbuf);
	}
	if (set_is_datamap(set->set_flags) && data != NULL) {
		__netlink_gen_data(data, &nld, !(data->flags & EXPR_F_SINGLETON));
		switch (data->etype) {
		case EXPR_VERDICT:
			nftnl_set_elem_set_u32(nlse, NFTNL_SET_ELEM_VERDICT,
					       data->verdict);
			if (data->chain != NULL)
				nftnl_set_elem_set(nlse, NFTNL_SET_ELEM_CHAIN,
						   nld.chain, strlen(nld.chain));
			break;
		case EXPR_CONCAT:
			assert(nld.len > 0);
			/* fallthrough */
		case EXPR_VALUE:
		case EXPR_RANGE:
		case EXPR_PREFIX:
			nftnl_set_elem_set(nlse, NFTNL_SET_ELEM_DATA,
					   nld.value, nld.len);
			break;
		default:
			BUG("unexpected set element expression\n");
			break;
		}
	}
	if (set_is_objmap(set->set_flags) && data != NULL) {
		netlink_gen_data(data, &nld);
		nftnl_set_elem_set(nlse, NFTNL_SET_ELEM_OBJREF,
				   nld.value, nld.len);
	}

	if (expr->flags & EXPR_F_INTERVAL_END)
		flags |= NFT_SET_ELEM_INTERVAL_END;
	if (key->etype == EXPR_SET_ELEM_CATCHALL)
		flags |= NFT_SET_ELEM_CATCHALL;

	if (flags)
		nftnl_set_elem_set_u32(nlse, NFTNL_SET_ELEM_FLAGS, flags);

	return nlse;
}

void netlink_gen_raw_data(const mpz_t value, enum byteorder byteorder,
			  unsigned int len, struct nft_data_linearize *data)
{
	assert(len > 0);
	mpz_export_data(data->value, value, byteorder, len);
	data->len = len;
}

static int netlink_export_pad(unsigned char *data, const mpz_t v,
			      const struct expr *i)
{
	mpz_export_data(data, v, i->byteorder,
			div_round_up(i->len, BITS_PER_BYTE));

	return netlink_padded_len(i->len) / BITS_PER_BYTE;
}

static int netlink_gen_concat_data_expr(int end, const struct expr *i,
					unsigned char *data)
{
	switch (i->etype) {
	case EXPR_RANGE:
		i = end ? i->right : i->left;
		break;
	case EXPR_PREFIX:
		if (end) {
			int count;
			mpz_t v;

			mpz_init_bitmask(v, i->len - i->prefix_len);
			mpz_add(v, i->prefix->value, v);
			count = netlink_export_pad(data, v, i);
			mpz_clear(v);
			return count;
		}
		return netlink_export_pad(data, i->prefix->value, i);
	case EXPR_VALUE:
		break;
	default:
		BUG("invalid expression type '%s' in set", expr_ops(i)->name);
	}

	return netlink_export_pad(data, i->value, i);
}

static void __netlink_gen_concat(const struct expr *expr,
				 struct nft_data_linearize *nld)
{
	unsigned int len = expr->len / BITS_PER_BYTE, offset = 0;
	int end = expr->flags & EXPR_F_INTERVAL_END;
	unsigned char data[len];
	const struct expr *i;

	memset(data, 0, len);

	list_for_each_entry(i, &expr->expressions, list)
		offset += netlink_gen_concat_data_expr(end, i, data + offset);

	memcpy(nld->value, data, len);
	nld->len = len;
}

static void __netlink_gen_concat_expand(const struct expr *expr,
				        struct nft_data_linearize *nld)
{
	unsigned int len = div_round_up(expr->len, BITS_PER_BYTE) * 2, offset = 0;
	unsigned char data[len];
	const struct expr *i;

	memset(data, 0, len);

	list_for_each_entry(i, &expr->expressions, list)
		offset += netlink_gen_concat_data_expr(false, i, data + offset);

	list_for_each_entry(i, &expr->expressions, list)
		offset += netlink_gen_concat_data_expr(true, i, data + offset);

	memcpy(nld->value, data, len);
	nld->len = len;
}

static void netlink_gen_concat_data(const struct expr *expr,
				    struct nft_data_linearize *nld,
				    bool expand)
{
	if (expand)
		__netlink_gen_concat_expand(expr, nld);
	else
		__netlink_gen_concat(expr, nld);
}

static void netlink_gen_constant_data(const struct expr *expr,
				      struct nft_data_linearize *data)
{
	assert(expr->etype == EXPR_VALUE);
	netlink_gen_raw_data(expr->value, expr->byteorder,
			     div_round_up(expr->len, BITS_PER_BYTE), data);
}

static void netlink_gen_chain(const struct expr *expr,
			      struct nft_data_linearize *data)
{
	char chain[NFT_CHAIN_MAXNAMELEN];
	unsigned int len;

	len = expr->chain->len / BITS_PER_BYTE;

	if (!len)
		BUG("chain length is 0");

	if (len > sizeof(chain))
		BUG("chain is too large (%u, %u max)",
		    len, (unsigned int)sizeof(chain));

	memset(chain, 0, sizeof(chain));

	mpz_export_data(chain, expr->chain->value,
			BYTEORDER_HOST_ENDIAN, len);
	snprintf(data->chain, NFT_CHAIN_MAXNAMELEN, "%s", chain);
}

static void netlink_gen_verdict(const struct expr *expr,
				struct nft_data_linearize *data)
{

	data->verdict = expr->verdict;

	switch (expr->verdict) {
	case NFT_JUMP:
	case NFT_GOTO:
		if (expr->chain)
			netlink_gen_chain(expr, data);
		else
			data->chain_id = expr->chain_id;
		break;
	}
}

static void netlink_gen_range(const struct expr *expr,
			      struct nft_data_linearize *nld)
{
	unsigned int len = div_round_up(expr->left->len, BITS_PER_BYTE) * 2;
	unsigned char data[len];
	unsigned int offset = 0;

	memset(data, 0, len);
	offset = netlink_export_pad(data, expr->left->value, expr->left);
	netlink_export_pad(data + offset, expr->right->value, expr->right);
	memcpy(nld->value, data, len);
	nld->len = len;
}

static void netlink_gen_prefix(const struct expr *expr,
			       struct nft_data_linearize *nld)
{
	unsigned int len = div_round_up(expr->len, BITS_PER_BYTE) * 2;
	unsigned char data[len];
	int offset;
	mpz_t v;

	offset = netlink_export_pad(data, expr->prefix->value, expr);
	mpz_init_bitmask(v, expr->len - expr->prefix_len);
	mpz_add(v, expr->prefix->value, v);
	netlink_export_pad(data + offset, v, expr->prefix);
	mpz_clear(v);

	memcpy(nld->value, data, len);
	nld->len = len;
}

void __netlink_gen_data(const struct expr *expr,
			struct nft_data_linearize *data, bool expand)
{
	switch (expr->etype) {
	case EXPR_VALUE:
		return netlink_gen_constant_data(expr, data);
	case EXPR_CONCAT:
		return netlink_gen_concat_data(expr, data, expand);
	case EXPR_VERDICT:
		return netlink_gen_verdict(expr, data);
	case EXPR_RANGE:
		return netlink_gen_range(expr, data);
	case EXPR_PREFIX:
		return netlink_gen_prefix(expr, data);
	default:
		BUG("invalid data expression type %s\n", expr_name(expr));
	}
}

void netlink_gen_data(const struct expr *expr, struct nft_data_linearize *data)
{
	__netlink_gen_data(expr, data, false);
}

struct expr *netlink_alloc_value(const struct location *loc,
				 const struct nft_data_delinearize *nld)
{
	return constant_expr_alloc(loc, &invalid_type, BYTEORDER_INVALID,
				   nld->len * BITS_PER_BYTE, nld->value);
}

static struct expr *netlink_alloc_verdict(const struct location *loc,
					  const struct nft_data_delinearize *nld)
{
	struct expr *chain;

	switch (nld->verdict) {
	case NFT_JUMP:
	case NFT_GOTO:
		chain = constant_expr_alloc(loc, &string_type,
					    BYTEORDER_HOST_ENDIAN,
					    strlen(nld->chain) * BITS_PER_BYTE,
					    nld->chain);
		break;
	default:
		chain = NULL;
		break;
	}

	return verdict_expr_alloc(loc, nld->verdict, chain);
}

struct expr *netlink_alloc_data(const struct location *loc,
				const struct nft_data_delinearize *nld,
				enum nft_registers dreg)
{
	switch (dreg) {
	case NFT_REG_VERDICT:
		return netlink_alloc_verdict(loc, nld);
	default:
		return netlink_alloc_value(loc, nld);
	}
}

void netlink_dump_rule(const struct nftnl_rule *nlr, struct netlink_ctx *ctx)
{
	FILE *fp = ctx->nft->output.output_fp;

	if (!(ctx->nft->debug_mask & NFT_DEBUG_NETLINK) || !fp)
		return;

	nftnl_rule_fprintf(fp, nlr, 0, 0);
	fprintf(fp, "\n");
}

void netlink_dump_expr(const struct nftnl_expr *nle,
		       FILE *fp, unsigned int debug_mask)
{
	if (!(debug_mask & NFT_DEBUG_NETLINK))
		return;

	nftnl_expr_fprintf(fp, nle, 0, 0);
	fprintf(fp, "\n");
}

void netlink_dump_chain(const struct nftnl_chain *nlc, struct netlink_ctx *ctx)
{
	FILE *fp = ctx->nft->output.output_fp;

	if (!(ctx->nft->debug_mask & NFT_DEBUG_NETLINK) || !fp)
		return;

	nftnl_chain_fprintf(fp, nlc, 0, 0);
	fprintf(fp, "\n");
}

static int chain_parse_udata_cb(const struct nftnl_udata *attr, void *data)
{
	unsigned char *value = nftnl_udata_get(attr);
	uint8_t type = nftnl_udata_type(attr);
	const struct nftnl_udata **tb = data;
	uint8_t len = nftnl_udata_len(attr);

	switch (type) {
		case NFTNL_UDATA_CHAIN_COMMENT:
			if (value[len - 1] != '\0')
				return -1;
			break;
		default:
			return 0;
	}
	tb[type] = attr;
	return 0;
}

static int qsort_device_cmp(const void *a, const void *b)
{
	const char **x = (const char **)a;
	const char **y = (const char **)b;

	return strcmp(*x, *y);
}

struct chain *netlink_delinearize_chain(struct netlink_ctx *ctx,
					const struct nftnl_chain *nlc)
{
	const struct nftnl_udata *ud[NFTNL_UDATA_OBJ_MAX + 1] = {};
	int priority, policy, len = 0, i;
	const char * const *dev_array;
	struct chain *chain;
	const char *udata;
	uint32_t ulen;

	chain = chain_alloc(nftnl_chain_get_str(nlc, NFTNL_CHAIN_NAME));
	chain->handle.family =
		nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FAMILY);
	chain->handle.table.name  =
		xstrdup(nftnl_chain_get_str(nlc, NFTNL_CHAIN_TABLE));
	chain->handle.handle.id =
		nftnl_chain_get_u64(nlc, NFTNL_CHAIN_HANDLE);
	if (nftnl_chain_is_set(nlc, NFTNL_CHAIN_FLAGS))
		chain->flags = nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FLAGS);

	if (nftnl_chain_is_set(nlc, NFTNL_CHAIN_HOOKNUM) &&
	    nftnl_chain_is_set(nlc, NFTNL_CHAIN_PRIO) &&
	    nftnl_chain_is_set(nlc, NFTNL_CHAIN_TYPE) &&
	    nftnl_chain_is_set(nlc, NFTNL_CHAIN_POLICY)) {
		chain->hook.num =
			nftnl_chain_get_u32(nlc, NFTNL_CHAIN_HOOKNUM);
		chain->hook.name =
			hooknum2str(chain->handle.family, chain->hook.num);
		priority = nftnl_chain_get_s32(nlc, NFTNL_CHAIN_PRIO);
		chain->priority.expr =
				constant_expr_alloc(&netlink_location,
						    &integer_type,
						    BYTEORDER_HOST_ENDIAN,
						    sizeof(int) * BITS_PER_BYTE,
						    &priority);
		chain->type.str =
			xstrdup(nftnl_chain_get_str(nlc, NFTNL_CHAIN_TYPE));
		policy = nftnl_chain_get_u32(nlc, NFTNL_CHAIN_POLICY);
		chain->policy = constant_expr_alloc(&netlink_location,
						    &integer_type,
						    BYTEORDER_HOST_ENDIAN,
						    sizeof(int) * BITS_PER_BYTE,
						    &policy);
			nftnl_chain_get_u32(nlc, NFTNL_CHAIN_POLICY);
		if (nftnl_chain_is_set(nlc, NFTNL_CHAIN_DEV)) {
			chain->dev_array = xmalloc(sizeof(char *) * 2);
			chain->dev_array_len = 1;
			chain->dev_array[0] =
				xstrdup(nftnl_chain_get_str(nlc, NFTNL_CHAIN_DEV));
			chain->dev_array[1] = NULL;
		} else if (nftnl_chain_is_set(nlc, NFTNL_CHAIN_DEVICES)) {
			dev_array = nftnl_chain_get(nlc, NFTNL_CHAIN_DEVICES);
			while (dev_array[len])
				len++;

			chain->dev_array = xmalloc((len + 1)* sizeof(char *));
			for (i = 0; i < len; i++)
				chain->dev_array[i] = xstrdup(dev_array[i]);

			chain->dev_array[i] = NULL;
			chain->dev_array_len = len;
		}
		chain->flags        |= CHAIN_F_BASECHAIN;

		if (chain->dev_array_len) {
			qsort(chain->dev_array, chain->dev_array_len,
			      sizeof(char *), qsort_device_cmp);
		}
	}

	if (nftnl_chain_is_set(nlc, NFTNL_CHAIN_USERDATA)) {
		udata = nftnl_chain_get_data(nlc, NFTNL_CHAIN_USERDATA, &ulen);
		if (nftnl_udata_parse(udata, ulen, chain_parse_udata_cb, ud) < 0) {
			netlink_io_error(ctx, NULL, "Cannot parse userdata");
			chain_free(chain);
			return NULL;
		}
		if (ud[NFTNL_UDATA_CHAIN_COMMENT])
			chain->comment = xstrdup(nftnl_udata_get(ud[NFTNL_UDATA_CHAIN_COMMENT]));
	}

	return chain;
}

static int table_parse_udata_cb(const struct nftnl_udata *attr, void *data)
{
	unsigned char *value = nftnl_udata_get(attr);
	const struct nftnl_udata **tb = data;
	uint8_t type = nftnl_udata_type(attr);
	uint8_t len = nftnl_udata_len(attr);

	switch (type) {
		case NFTNL_UDATA_TABLE_COMMENT:
			if (value[len - 1] != '\0')
				return -1;
			break;
		default:
			return 0;
	}
	tb[type] = attr;
	return 0;
}

struct table *netlink_delinearize_table(struct netlink_ctx *ctx,
					const struct nftnl_table *nlt)
{
	const struct nftnl_udata *ud[NFTNL_UDATA_TABLE_MAX + 1] = {};
	struct table *table;
	const char *udata;
	uint32_t ulen;

	table = table_alloc();
	table->handle.family = nftnl_table_get_u32(nlt, NFTNL_TABLE_FAMILY);
	table->handle.table.name = xstrdup(nftnl_table_get_str(nlt, NFTNL_TABLE_NAME));
	table->flags	     = nftnl_table_get_u32(nlt, NFTNL_TABLE_FLAGS);
	table->handle.handle.id = nftnl_table_get_u64(nlt, NFTNL_TABLE_HANDLE);
	table->owner	     = nftnl_table_get_u32(nlt, NFTNL_TABLE_OWNER);

	if (nftnl_table_is_set(nlt, NFTNL_TABLE_USERDATA)) {
		udata = nftnl_table_get_data(nlt, NFTNL_TABLE_USERDATA, &ulen);
		if (nftnl_udata_parse(udata, ulen, table_parse_udata_cb, ud) < 0) {
			netlink_io_error(ctx, NULL, "Cannot parse userdata");
			table_free(table);
			return NULL;
		}
		if (ud[NFTNL_UDATA_TABLE_COMMENT])
			table->comment = xstrdup(nftnl_udata_get(ud[NFTNL_UDATA_TABLE_COMMENT]));
	}

	return table;
}

static int list_table_cb(struct nftnl_table *nlt, void *arg)
{
	struct netlink_ctx *ctx = arg;
	struct table *table;

	table = netlink_delinearize_table(ctx, nlt);
	list_add_tail(&table->list, &ctx->list);

	return 0;
}

int netlink_list_tables(struct netlink_ctx *ctx, const struct handle *h,
			const struct nft_cache_filter *filter)
{
	struct nftnl_table_list *table_cache;
	uint32_t family = h->family;
	const char *table = NULL;

	if (filter) {
		family = filter->list.family;
		table = filter->list.table;
	}

	table_cache = mnl_nft_table_dump(ctx, family, table);
	if (table_cache == NULL) {
		if (errno == EINTR)
			return -1;

		return -1;
	}

	ctx->data = h;
	nftnl_table_list_foreach(table_cache, list_table_cb, ctx);
	nftnl_table_list_free(table_cache);
	return 0;
}

enum nft_data_types dtype_map_to_kernel(const struct datatype *dtype)
{
	switch (dtype->type) {
	case TYPE_VERDICT:
		return NFT_DATA_VERDICT;
	default:
		return dtype->type;
	}
}

static const struct datatype *dtype_map_from_kernel(enum nft_data_types type)
{
	switch (type) {
	case NFT_DATA_VERDICT:
		return &verdict_type;
	default:
		if (type & ~TYPE_MASK)
			return concat_type_alloc(type);
		return datatype_lookup(type);
	}
}

void netlink_dump_set(const struct nftnl_set *nls, struct netlink_ctx *ctx)
{
	FILE *fp = ctx->nft->output.output_fp;

	if (!(ctx->nft->debug_mask & NFT_DEBUG_NETLINK) || !fp)
		return;

	nftnl_set_fprintf(fp, nls, 0, 0);
	fprintf(fp, "\n");
}

static int set_parse_udata_cb(const struct nftnl_udata *attr, void *data)
{
	unsigned char *value = nftnl_udata_get(attr);
	const struct nftnl_udata **tb = data;
	uint8_t type = nftnl_udata_type(attr);
	uint8_t len = nftnl_udata_len(attr);

	switch (type) {
	case NFTNL_UDATA_SET_KEYBYTEORDER:
	case NFTNL_UDATA_SET_DATABYTEORDER:
	case NFTNL_UDATA_SET_MERGE_ELEMENTS:
	case NFTNL_UDATA_SET_DATA_INTERVAL:
		if (len != sizeof(uint32_t))
			return -1;
		break;
	case NFTNL_UDATA_SET_KEY_TYPEOF:
	case NFTNL_UDATA_SET_DATA_TYPEOF:
		if (len < 3)
			return -1;
		break;
	case NFTNL_UDATA_SET_COMMENT:
		if (value[len - 1] != '\0')
			return -1;
		break;
	default:
		return 0;
	}
	tb[type] = attr;
	return 0;
}

static int set_key_parse_udata(const struct nftnl_udata *attr, void *data)
{
	const struct nftnl_udata **tb = data;
	uint8_t type = nftnl_udata_type(attr);
	uint8_t len = nftnl_udata_len(attr);

	switch (type) {
	case NFTNL_UDATA_SET_TYPEOF_EXPR:
		if (len != sizeof(uint32_t))
			return -1;
		break;
	case NFTNL_UDATA_SET_TYPEOF_DATA:
		break;
	default:
		return 0;
	}
	tb[type] = attr;
	return 0;
}

static struct expr *set_make_key(const struct nftnl_udata *attr)
{
	const struct nftnl_udata *ud[NFTNL_UDATA_SET_TYPEOF_MAX + 1] = {};
	const struct expr_ops *ops;
	enum expr_types etype;
	struct expr *expr;
	int err;

	if (!attr)
		return NULL;

	err = nftnl_udata_parse(nftnl_udata_get(attr), nftnl_udata_len(attr),
				set_key_parse_udata, ud);
	if (err < 0)
		return NULL;

	if (!ud[NFTNL_UDATA_SET_TYPEOF_EXPR] ||
	    !ud[NFTNL_UDATA_SET_TYPEOF_DATA])
		return NULL;

	etype = nftnl_udata_get_u32(ud[NFTNL_UDATA_SET_TYPEOF_EXPR]);
	ops = expr_ops_by_type(etype);

	expr = ops->parse_udata(ud[NFTNL_UDATA_SET_TYPEOF_DATA]);
	if (!expr)
		return NULL;

	return expr;
}

static bool set_udata_key_valid(const struct expr *e, const struct datatype *d, uint32_t len)
{
	if (!e)
		return false;

	return div_round_up(e->len, BITS_PER_BYTE) == len / BITS_PER_BYTE;
}

struct setelem_parse_ctx {
	struct set			*set;
	struct nft_cache		*cache;
	struct list_head		stmt_list;
};

static int set_elem_parse_expressions(struct nftnl_expr *e, void *data)
{
	struct setelem_parse_ctx *setelem_parse_ctx = data;
	struct nft_cache *cache = setelem_parse_ctx->cache;
	struct set *set = setelem_parse_ctx->set;
	struct stmt *stmt;

	stmt = netlink_parse_set_expr(set, cache, e);
	list_add_tail(&stmt->list, &setelem_parse_ctx->stmt_list);

	return 0;
}

struct set *netlink_delinearize_set(struct netlink_ctx *ctx,
				    const struct nftnl_set *nls)
{
	const struct nftnl_udata *ud[NFTNL_UDATA_SET_MAX + 1] = {};
	enum byteorder keybyteorder = BYTEORDER_INVALID;
	enum byteorder databyteorder = BYTEORDER_INVALID;
	const struct datatype *keytype, *datatype = NULL;
	struct expr *typeof_expr_key, *typeof_expr_data;
	struct setelem_parse_ctx set_parse_ctx;
	const char *udata, *comment = NULL;
	uint32_t flags, key, objtype = 0;
	const struct datatype *dtype;
	uint32_t data_interval = 0;
	bool automerge = false;
	struct set *set;
	uint32_t ulen;
	uint32_t klen;

	typeof_expr_key = NULL;
	typeof_expr_data = NULL;

	if (nftnl_set_is_set(nls, NFTNL_SET_USERDATA)) {
		udata = nftnl_set_get_data(nls, NFTNL_SET_USERDATA, &ulen);
		if (nftnl_udata_parse(udata, ulen, set_parse_udata_cb, ud) < 0) {
			netlink_io_error(ctx, NULL, "Cannot parse userdata");
			return NULL;
		}

#define GET_U32_UDATA(var, attr)				\
		if (ud[attr])					\
			var = nftnl_udata_get_u32(ud[attr])

		GET_U32_UDATA(keybyteorder, NFTNL_UDATA_SET_KEYBYTEORDER);
		GET_U32_UDATA(databyteorder, NFTNL_UDATA_SET_DATABYTEORDER);
		GET_U32_UDATA(automerge, NFTNL_UDATA_SET_MERGE_ELEMENTS);
		GET_U32_UDATA(data_interval, NFTNL_UDATA_SET_DATA_INTERVAL);

#undef GET_U32_UDATA
		typeof_expr_key = set_make_key(ud[NFTNL_UDATA_SET_KEY_TYPEOF]);
		if (ud[NFTNL_UDATA_SET_DATA_TYPEOF])
			typeof_expr_data = set_make_key(ud[NFTNL_UDATA_SET_DATA_TYPEOF]);
		if (ud[NFTNL_UDATA_SET_COMMENT])
			comment = nftnl_udata_get(ud[NFTNL_UDATA_SET_COMMENT]);
	}

	key = nftnl_set_get_u32(nls, NFTNL_SET_KEY_TYPE);
	keytype = dtype_map_from_kernel(key);
	if (keytype == NULL) {
		netlink_io_error(ctx, NULL, "Unknown data type in set key %u",
				 key);
		return NULL;
	}

	flags = nftnl_set_get_u32(nls, NFTNL_SET_FLAGS);
	if (set_is_datamap(flags)) {
		uint32_t data;

		data = nftnl_set_get_u32(nls, NFTNL_SET_DATA_TYPE);
		datatype = dtype_map_from_kernel(data);
		if (datatype == NULL) {
			netlink_io_error(ctx, NULL,
					 "Unknown data type in set key %u",
					 data);
			datatype_free(keytype);
			return NULL;
		}
	}

	if (set_is_objmap(flags)) {
		objtype = nftnl_set_get_u32(nls, NFTNL_SET_OBJ_TYPE);
		assert(!datatype);
		datatype = &string_type;
	}

	set = set_alloc(&netlink_location);
	set->handle.family = nftnl_set_get_u32(nls, NFTNL_SET_FAMILY);
	set->handle.table.name = xstrdup(nftnl_set_get_str(nls, NFTNL_SET_TABLE));
	set->handle.set.name = xstrdup(nftnl_set_get_str(nls, NFTNL_SET_NAME));
	set->automerge	   = automerge;
	if (comment)
		set->comment = xstrdup(comment);

	init_list_head(&set_parse_ctx.stmt_list);

	if (nftnl_set_is_set(nls, NFTNL_SET_EXPR)) {
		const struct nftnl_expr *nle;
		struct stmt *stmt;

		nle = nftnl_set_get(nls, NFTNL_SET_EXPR);
		stmt = netlink_parse_set_expr(set, &ctx->nft->cache, nle);
		list_add_tail(&stmt->list, &set_parse_ctx.stmt_list);
	} else if (nftnl_set_is_set(nls, NFTNL_SET_EXPRESSIONS)) {
		set_parse_ctx.cache = &ctx->nft->cache;
		set_parse_ctx.set = set;
		nftnl_set_expr_foreach(nls, set_elem_parse_expressions,
				       &set_parse_ctx);
	}
	list_splice_tail(&set_parse_ctx.stmt_list, &set->stmt_list);

	if (datatype) {
		dtype = set_datatype_alloc(datatype, databyteorder);
		klen = nftnl_set_get_u32(nls, NFTNL_SET_DATA_LEN) * BITS_PER_BYTE;

		if (set_udata_key_valid(typeof_expr_data, dtype, klen)) {
			datatype_free(datatype_get(dtype));
			set->data = typeof_expr_data;
		} else {
			expr_free(typeof_expr_data);
			set->data = constant_expr_alloc(&netlink_location,
							dtype,
							databyteorder, klen,
							NULL);

			/* Can't use 'typeof' keyword, so discard key too */
			expr_free(typeof_expr_key);
			typeof_expr_key = NULL;
		}

		if (data_interval)
			set->data->flags |= EXPR_F_INTERVAL;

		if (dtype != datatype)
			datatype_free(datatype);
	}

	dtype = set_datatype_alloc(keytype, keybyteorder);
	klen = nftnl_set_get_u32(nls, NFTNL_SET_KEY_LEN) * BITS_PER_BYTE;

	if (set_udata_key_valid(typeof_expr_key, dtype, klen)) {
		datatype_free(datatype_get(dtype));
		set->key = typeof_expr_key;
		set->key_typeof_valid = true;
	} else {
		expr_free(typeof_expr_key);
		set->key = constant_expr_alloc(&netlink_location, dtype,
					       keybyteorder, klen,
					       NULL);
	}

	if (dtype != keytype)
		datatype_free(keytype);

	set->flags   = nftnl_set_get_u32(nls, NFTNL_SET_FLAGS);
	set->handle.handle.id = nftnl_set_get_u64(nls, NFTNL_SET_HANDLE);

	set->objtype = objtype;

	if (nftnl_set_is_set(nls, NFTNL_SET_TIMEOUT))
		set->timeout = nftnl_set_get_u64(nls, NFTNL_SET_TIMEOUT);
	if (nftnl_set_is_set(nls, NFTNL_SET_GC_INTERVAL))
		set->gc_int  = nftnl_set_get_u32(nls, NFTNL_SET_GC_INTERVAL);

	if (nftnl_set_is_set(nls, NFTNL_SET_POLICY))
		set->policy = nftnl_set_get_u32(nls, NFTNL_SET_POLICY);

	if (nftnl_set_is_set(nls, NFTNL_SET_DESC_SIZE))
		set->desc.size = nftnl_set_get_u32(nls, NFTNL_SET_DESC_SIZE);

	if (nftnl_set_is_set(nls, NFTNL_SET_DESC_CONCAT)) {
		uint32_t len = NFT_REG32_COUNT;
		const uint8_t *data;

		data = nftnl_set_get_data(nls, NFTNL_SET_DESC_CONCAT, &len);
		if (data) {
			memcpy(set->desc.field_len, data, len);
			set->desc.field_count = len;
		}
	}

	return set;
}

void alloc_setelem_cache(const struct expr *set, struct nftnl_set *nls)
{
	struct nftnl_set_elem *nlse;
	const struct expr *expr;

	list_for_each_entry(expr, &set->expressions, list) {
		nlse = alloc_nftnl_setelem(set, expr);
		nftnl_set_elem_add(nls, nlse);
	}
}

static bool range_expr_is_prefix(const struct expr *range, uint32_t *prefix_len)
{
	const struct expr *right = range->right;
	const struct expr *left = range->left;
	uint32_t len = left->len;
	unsigned long n1, n2;
	uint32_t plen;
	mpz_t bitmask;

	mpz_init2(bitmask, left->len);
	mpz_xor(bitmask, left->value, right->value);

	n1 = mpz_scan0(bitmask, 0);
	if (n1 == ULONG_MAX)
		goto not_a_prefix;

	n2 = mpz_scan1(bitmask, n1 + 1);
	if (n2 < len)
		goto not_a_prefix;

	plen = len - n1;

	if (mpz_scan1(left->value, 0) < len - plen)
		goto not_a_prefix;

	mpz_clear(bitmask);
	*prefix_len = plen;

	return true;

not_a_prefix:
	mpz_clear(bitmask);

	return false;
}

struct expr *range_expr_to_prefix(struct expr *range)
{
	struct expr *prefix;
	uint32_t prefix_len;

	if (range_expr_is_prefix(range, &prefix_len)) {
		prefix = prefix_expr_alloc(&range->location,
					   expr_get(range->left),
					   prefix_len);
		expr_free(range);
		return prefix;
	}

	return range;
}

static struct expr *range_expr_reduce(struct expr *range)
{
	struct expr *expr;

	if (!mpz_cmp(range->left->value, range->right->value)) {
		expr = expr_get(range->left);
		expr_free(range);
		return expr;
	}

	if (range->left->dtype->type != TYPE_IPADDR &&
	    range->left->dtype->type != TYPE_IP6ADDR)
		return range;

	return range_expr_to_prefix(range);
}

static struct expr *netlink_parse_interval_elem(const struct set *set,
						struct expr *expr)
{
	unsigned int len = div_round_up(expr->len, BITS_PER_BYTE);
	const struct datatype *dtype = set->data->dtype;
	struct expr *range, *left, *right;
	char data[len];

	mpz_export_data(data, expr->value, dtype->byteorder, len);
	left = constant_expr_alloc(&internal_location, dtype,
				   dtype->byteorder,
				   (len / 2) * BITS_PER_BYTE, &data[0]);
	right = constant_expr_alloc(&internal_location, dtype,
				    dtype->byteorder,
				    (len / 2) * BITS_PER_BYTE, &data[len / 2]);
	range = range_expr_alloc(&expr->location, left, right);
	expr_free(expr);

	return range_expr_to_prefix(range);
}

static struct expr *concat_elem_expr(struct expr *expr,
				     const struct datatype *dtype,
				     struct expr *data, int *off)
{
	const struct datatype *subtype;

	subtype = concat_subtype_lookup(dtype->type, --(*off));

	expr = constant_expr_splice(data, subtype->size);
	expr->dtype = subtype;
	expr->byteorder = subtype->byteorder;

	if (expr->byteorder == BYTEORDER_HOST_ENDIAN)
		mpz_switch_byteorder(expr->value, expr->len / BITS_PER_BYTE);

	if (expr->dtype->basetype != NULL &&
	    expr->dtype->basetype->type == TYPE_BITMASK)
		expr = bitmask_expr_to_binops(expr);

	data->len -= netlink_padding_len(expr->len);

	return expr;
}

static struct expr *netlink_parse_concat_elem_key(const struct set *set,
						  struct expr *data)
{
	const struct datatype *dtype = set->key->dtype;
	struct expr *concat, *expr;
	int off = dtype->subtypes;

	concat = concat_expr_alloc(&data->location);
	while (off > 0) {
		expr = concat_elem_expr(expr, dtype, data, &off);
		compound_expr_add(concat, expr);
	}

	expr_free(data);

	return concat;
}

static struct expr *netlink_parse_concat_elem(const struct set *set,
					      struct expr *data)
{
	const struct datatype *dtype = set->data->dtype;
	struct expr *concat, *expr, *left, *range;
	struct list_head expressions;
	int off = dtype->subtypes;

	init_list_head(&expressions);

	concat = concat_expr_alloc(&data->location);
	while (off > 0) {
		expr = concat_elem_expr(expr, dtype, data, &off);
		list_add_tail(&expr->list, &expressions);
	}

	if (set->data->flags & EXPR_F_INTERVAL) {
		assert(!list_empty(&expressions));

		off = dtype->subtypes;

		while (off > 0) {
			left = list_first_entry(&expressions, struct expr, list);

			expr = concat_elem_expr(expr, dtype, data, &off);
			list_del(&left->list);

			range = range_expr_alloc(&data->location, left, expr);
			range = range_expr_reduce(range);
			compound_expr_add(concat, range);
		}
		assert(list_empty(&expressions));
	} else {
		list_splice_tail(&expressions, &concat->expressions);
	}

	expr_free(data);

	return concat;
}

static int set_elem_parse_udata_cb(const struct nftnl_udata *attr, void *data)
{
	const struct nftnl_udata **tb = data;
	unsigned char *value = nftnl_udata_get(attr);
	uint8_t type = nftnl_udata_type(attr);
	uint8_t len = nftnl_udata_len(attr);

	switch (type) {
	case NFTNL_UDATA_SET_ELEM_COMMENT:
		if (value[len - 1] != '\0')
			return -1;
		break;
	case NFTNL_UDATA_SET_ELEM_FLAGS:
		if (len != sizeof(uint32_t))
			return -1;
		break;
	default:
		return 0;
	}
	tb[type] = attr;
	return 0;
}

static void set_elem_parse_udata(struct nftnl_set_elem *nlse,
				 struct expr *expr)
{
	const struct nftnl_udata *ud[NFTNL_UDATA_SET_ELEM_MAX + 1] = {};
	const void *data;
	uint32_t len;

	data = nftnl_set_elem_get(nlse, NFTNL_SET_ELEM_USERDATA, &len);
	if (nftnl_udata_parse(data, len, set_elem_parse_udata_cb, ud))
		return;

	if (ud[NFTNL_UDATA_SET_ELEM_COMMENT])
		expr->comment =
			xstrdup(nftnl_udata_get(ud[NFTNL_UDATA_SET_ELEM_COMMENT]));
	if (ud[NFTNL_UDATA_SET_ELEM_FLAGS])
		expr->elem_flags =
			nftnl_udata_get_u32(ud[NFTNL_UDATA_SET_ELEM_FLAGS]);
}

int netlink_delinearize_setelem(struct nftnl_set_elem *nlse,
				struct set *set, struct nft_cache *cache)
{
	struct setelem_parse_ctx setelem_parse_ctx = {
		.set	= set,
		.cache	= cache,
	};
	struct nft_data_delinearize nld;
	struct expr *expr, *key, *data;
	uint32_t flags = 0;

	init_list_head(&setelem_parse_ctx.stmt_list);

	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_KEY))
		nld.value = nftnl_set_elem_get(nlse, NFTNL_SET_ELEM_KEY, &nld.len);
	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_FLAGS))
		flags = nftnl_set_elem_get_u32(nlse, NFTNL_SET_ELEM_FLAGS);

key_end:
	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_KEY)) {
		key = netlink_alloc_value(&netlink_location, &nld);
		datatype_set(key, set->key->dtype);
		key->byteorder	= set->key->byteorder;
		if (set->key->dtype->subtypes)
			key = netlink_parse_concat_elem_key(set, key);

		if (!(set->flags & NFT_SET_INTERVAL) &&
		    key->byteorder == BYTEORDER_HOST_ENDIAN)
			mpz_switch_byteorder(key->value, key->len / BITS_PER_BYTE);

		if (key->dtype->basetype != NULL &&
		    key->dtype->basetype->type == TYPE_BITMASK)
			key = bitmask_expr_to_binops(key);
	} else if (flags & NFT_SET_ELEM_CATCHALL) {
		key = set_elem_catchall_expr_alloc(&netlink_location);
		datatype_set(key, set->key->dtype);
		key->byteorder = set->key->byteorder;
		key->len = set->key->len;
	} else {
		BUG("Unexpected set element with no key\n");
	}

	expr = set_elem_expr_alloc(&netlink_location, key);

	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_TIMEOUT))
		expr->timeout	 = nftnl_set_elem_get_u64(nlse, NFTNL_SET_ELEM_TIMEOUT);
	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_EXPIRATION))
		expr->expiration = nftnl_set_elem_get_u64(nlse, NFTNL_SET_ELEM_EXPIRATION);
	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_USERDATA))
		set_elem_parse_udata(nlse, expr);
	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_EXPR)) {
		const struct nftnl_expr *nle;
		struct stmt *stmt;

		nle = nftnl_set_elem_get(nlse, NFTNL_SET_ELEM_EXPR, NULL);
		stmt = netlink_parse_set_expr(set, cache, nle);
		list_add_tail(&stmt->list, &setelem_parse_ctx.stmt_list);
	} else if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_EXPRESSIONS)) {
		nftnl_set_elem_expr_foreach(nlse, set_elem_parse_expressions,
					    &setelem_parse_ctx);
	}
	list_splice_tail_init(&setelem_parse_ctx.stmt_list, &expr->stmt_list);

	if (flags & NFT_SET_ELEM_INTERVAL_END) {
		expr->flags |= EXPR_F_INTERVAL_END;
		if (mpz_cmp_ui(set->key->value, 0) == 0)
			set->root = true;
	}

	if (set_is_datamap(set->flags)) {
		if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_DATA)) {
			nld.value = nftnl_set_elem_get(nlse, NFTNL_SET_ELEM_DATA,
						       &nld.len);
		} else if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_CHAIN)) {
			nld.chain = nftnl_set_elem_get_str(nlse, NFTNL_SET_ELEM_CHAIN);
			nld.verdict = nftnl_set_elem_get_u32(nlse, NFTNL_SET_ELEM_VERDICT);
		} else if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_VERDICT)) {
			nld.verdict = nftnl_set_elem_get_u32(nlse, NFTNL_SET_ELEM_VERDICT);
		} else
			goto out;

		data = netlink_alloc_data(&netlink_location, &nld,
					  set->data->dtype->type == TYPE_VERDICT ?
					  NFT_REG_VERDICT : NFT_REG_1);
		datatype_set(data, set->data->dtype);
		data->byteorder = set->data->byteorder;

		if (set->data->dtype->subtypes) {
			data = netlink_parse_concat_elem(set, data);
		} else if (set->data->flags & EXPR_F_INTERVAL)
			data = netlink_parse_interval_elem(set, data);

		if (data->byteorder == BYTEORDER_HOST_ENDIAN)
			mpz_switch_byteorder(data->value, data->len / BITS_PER_BYTE);

		expr = mapping_expr_alloc(&netlink_location, expr, data);
	}
	if (set_is_objmap(set->flags)) {
		if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_OBJREF)) {
			nld.value = nftnl_set_elem_get(nlse,
						       NFTNL_SET_ELEM_OBJREF,
						       &nld.len);
		} else
			goto out;

		data = netlink_alloc_value(&netlink_location, &nld);
		data->dtype = &string_type;
		data->byteorder = BYTEORDER_HOST_ENDIAN;
		mpz_switch_byteorder(data->value, data->len / BITS_PER_BYTE);
		expr = mapping_expr_alloc(&netlink_location, expr, data);
	}
out:
	compound_expr_add(set->init, expr);

	if (!(flags & NFT_SET_ELEM_INTERVAL_END) &&
	    nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_KEY_END)) {
		flags |= NFT_SET_ELEM_INTERVAL_END;
		nld.value = nftnl_set_elem_get(nlse, NFTNL_SET_ELEM_KEY_END,
					       &nld.len);
		goto key_end;
	}

	return 0;
}

static int list_setelem_cb(struct nftnl_set_elem *nlse, void *arg)
{
	struct netlink_ctx *ctx = arg;
	return netlink_delinearize_setelem(nlse, ctx->set, &ctx->nft->cache);
}

static int list_setelem_debug_cb(struct nftnl_set_elem *nlse, void *arg)
{
	int r;

	r = list_setelem_cb(nlse, arg);
	if (r == 0) {
		struct netlink_ctx *ctx = arg;
		FILE *fp = ctx->nft->output.output_fp;

		fprintf(fp, "\t");
		nftnl_set_elem_fprintf(fp, nlse, 0, 0);
		fprintf(fp, "\n");
	}

	return r;
}

static int list_setelements(struct nftnl_set *s, struct netlink_ctx *ctx)
{
	FILE *fp = ctx->nft->output.output_fp;

	if (fp && (ctx->nft->debug_mask & NFT_DEBUG_NETLINK)) {
		const char *table, *name;
		uint32_t family = nftnl_set_get_u32(s, NFTNL_SET_FAMILY);

		table = nftnl_set_get_str(s, NFTNL_SET_TABLE);
		name = nftnl_set_get_str(s, NFTNL_SET_NAME);

		fprintf(fp, "%s %s @%s\n", family2str(family), table, name);

		return nftnl_set_elem_foreach(s, list_setelem_debug_cb, ctx);
	}

	return nftnl_set_elem_foreach(s, list_setelem_cb, ctx);
}

int netlink_list_setelems(struct netlink_ctx *ctx, const struct handle *h,
			  struct set *set)
{
	struct nftnl_set *nls;
	int err;

	nls = nftnl_set_alloc();
	if (nls == NULL)
		memory_allocation_error();

	nftnl_set_set_u32(nls, NFTNL_SET_FAMILY, h->family);
	nftnl_set_set_str(nls, NFTNL_SET_TABLE, h->table.name);
	nftnl_set_set_str(nls, NFTNL_SET_NAME, h->set.name);
	if (h->handle.id)
		nftnl_set_set_u64(nls, NFTNL_SET_HANDLE, h->handle.id);

	err = mnl_nft_setelem_get(ctx, nls);
	if (err < 0) {
		nftnl_set_free(nls);
		if (errno == EINTR)
			return -1;

		return 0;
	}

	ctx->set = set;
	set->init = set_expr_alloc(&internal_location, set);
	list_setelements(nls, ctx);

	if (set->flags & NFT_SET_INTERVAL && set->desc.field_count > 1)
		concat_range_aggregate(set->init);
	else if (set->flags & NFT_SET_INTERVAL)
		interval_map_decompose(set->init);
	else
		list_expr_sort(&ctx->set->init->expressions);

	nftnl_set_free(nls);
	ctx->set = NULL;

	return 0;
}

int netlink_get_setelem(struct netlink_ctx *ctx, const struct handle *h,
			const struct location *loc, struct set *cache_set,
			struct set *set, struct expr *init)
{
	struct nftnl_set *nls, *nls_out = NULL;
	int err = 0;

	nls = nftnl_set_alloc();
	if (nls == NULL)
		memory_allocation_error();

	nftnl_set_set_u32(nls, NFTNL_SET_FAMILY, h->family);
	nftnl_set_set_str(nls, NFTNL_SET_TABLE, h->table.name);
	nftnl_set_set_str(nls, NFTNL_SET_NAME, h->set.name);
	if (h->handle.id)
		nftnl_set_set_u64(nls, NFTNL_SET_HANDLE, h->handle.id);

	alloc_setelem_cache(init, nls);

	netlink_dump_set(nls, ctx);

	nls_out = mnl_nft_setelem_get_one(ctx, nls);
	if (!nls_out) {
		nftnl_set_free(nls);
		return -1;
	}

	ctx->set = set;
	set->init = set_expr_alloc(loc, set);
	list_setelements(nls_out, ctx);

	if (set->flags & NFT_SET_INTERVAL && set->desc.field_count > 1)
		concat_range_aggregate(set->init);
	else if (set->flags & NFT_SET_INTERVAL)
		err = get_set_decompose(cache_set, set);
	else
		list_expr_sort(&ctx->set->init->expressions);

	nftnl_set_free(nls);
	nftnl_set_free(nls_out);
	ctx->set = NULL;

	return err;
}

void netlink_dump_obj(struct nftnl_obj *nln, struct netlink_ctx *ctx)
{
	FILE *fp = ctx->nft->output.output_fp;

	if (!(ctx->nft->debug_mask & NFT_DEBUG_NETLINK) || !fp)
		return;

	nftnl_obj_fprintf(fp, nln, 0, 0);
	fprintf(fp, "\n");
}

static int obj_parse_udata_cb(const struct nftnl_udata *attr, void *data)
{
	unsigned char *value = nftnl_udata_get(attr);
	uint8_t type = nftnl_udata_type(attr);
	const struct nftnl_udata **tb = data;
	uint8_t len = nftnl_udata_len(attr);

	switch (type) {
		case NFTNL_UDATA_OBJ_COMMENT:
			if (value[len - 1] != '\0')
				return -1;
			break;
		default:
			return 0;
	}
	tb[type] = attr;
	return 0;
}

struct obj *netlink_delinearize_obj(struct netlink_ctx *ctx,
				    struct nftnl_obj *nlo)
{
	const struct nftnl_udata *ud[NFTNL_UDATA_OBJ_MAX + 1] = {};
	const char *udata;
	struct obj *obj;
	uint32_t type;
	uint32_t ulen;

	obj = obj_alloc(&netlink_location);
	obj->handle.family = nftnl_obj_get_u32(nlo, NFTNL_OBJ_FAMILY);
	obj->handle.table.name =
		xstrdup(nftnl_obj_get_str(nlo, NFTNL_OBJ_TABLE));
	obj->handle.obj.name =
		xstrdup(nftnl_obj_get_str(nlo, NFTNL_OBJ_NAME));
	obj->handle.handle.id =
		nftnl_obj_get_u64(nlo, NFTNL_OBJ_HANDLE);
	if (nftnl_obj_is_set(nlo, NFTNL_OBJ_USERDATA)) {
		udata = nftnl_obj_get_data(nlo, NFTNL_OBJ_USERDATA, &ulen);
		if (nftnl_udata_parse(udata, ulen, obj_parse_udata_cb, ud) < 0) {
			netlink_io_error(ctx, NULL, "Cannot parse userdata");
			obj_free(obj);
			return NULL;
		}
		if (ud[NFTNL_UDATA_OBJ_COMMENT])
			obj->comment = xstrdup(nftnl_udata_get(ud[NFTNL_UDATA_OBJ_COMMENT]));
	}

	type = nftnl_obj_get_u32(nlo, NFTNL_OBJ_TYPE);
	switch (type) {
	case NFT_OBJECT_COUNTER:
		obj->counter.packets =
			nftnl_obj_get_u64(nlo, NFTNL_OBJ_CTR_PKTS);
		obj->counter.bytes =
			nftnl_obj_get_u64(nlo, NFTNL_OBJ_CTR_BYTES);
		break;
	case NFT_OBJECT_QUOTA:
		obj->quota.bytes =
			nftnl_obj_get_u64(nlo, NFTNL_OBJ_QUOTA_BYTES);
		obj->quota.used =
			nftnl_obj_get_u64(nlo, NFTNL_OBJ_QUOTA_CONSUMED);
		obj->quota.flags =
			nftnl_obj_get_u32(nlo, NFTNL_OBJ_QUOTA_FLAGS);
		break;
	case NFT_OBJECT_SECMARK:
		snprintf(obj->secmark.ctx, sizeof(obj->secmark.ctx), "%s",
			 nftnl_obj_get_str(nlo, NFTNL_OBJ_SECMARK_CTX));
		break;
	case NFT_OBJECT_CT_HELPER:
		snprintf(obj->ct_helper.name, sizeof(obj->ct_helper.name), "%s",
			 nftnl_obj_get_str(nlo, NFTNL_OBJ_CT_HELPER_NAME));
		obj->ct_helper.l3proto = nftnl_obj_get_u16(nlo, NFTNL_OBJ_CT_HELPER_L3PROTO);
		obj->ct_helper.l4proto = nftnl_obj_get_u8(nlo, NFTNL_OBJ_CT_HELPER_L4PROTO);
		break;
	case NFT_OBJECT_CT_TIMEOUT:
		init_list_head(&obj->ct_timeout.timeout_list);
		obj->ct_timeout.l3proto = nftnl_obj_get_u16(nlo, NFTNL_OBJ_CT_TIMEOUT_L3PROTO);
		obj->ct_timeout.l4proto = nftnl_obj_get_u8(nlo, NFTNL_OBJ_CT_TIMEOUT_L4PROTO);
		memcpy(obj->ct_timeout.timeout,
		       nftnl_obj_get(nlo, NFTNL_OBJ_CT_TIMEOUT_ARRAY),
		       NFTNL_CTTIMEOUT_ARRAY_MAX * sizeof(uint32_t));
		break;
	case NFT_OBJECT_LIMIT:
		obj->limit.rate =
			nftnl_obj_get_u64(nlo, NFTNL_OBJ_LIMIT_RATE);
		obj->limit.unit =
			nftnl_obj_get_u64(nlo, NFTNL_OBJ_LIMIT_UNIT);
		obj->limit.burst =
			nftnl_obj_get_u32(nlo, NFTNL_OBJ_LIMIT_BURST);
		obj->limit.type =
			nftnl_obj_get_u32(nlo, NFTNL_OBJ_LIMIT_TYPE);
		obj->limit.flags =
			nftnl_obj_get_u32(nlo, NFTNL_OBJ_LIMIT_FLAGS);
		break;
	case NFT_OBJECT_CT_EXPECT:
		obj->ct_expect.l3proto =
			nftnl_obj_get_u16(nlo, NFTNL_OBJ_CT_EXPECT_L3PROTO);
		obj->ct_expect.l4proto =
			nftnl_obj_get_u8(nlo, NFTNL_OBJ_CT_EXPECT_L4PROTO);
		obj->ct_expect.dport =
			nftnl_obj_get_u16(nlo, NFTNL_OBJ_CT_EXPECT_DPORT);
		obj->ct_expect.timeout =
			nftnl_obj_get_u32(nlo, NFTNL_OBJ_CT_EXPECT_TIMEOUT);
		obj->ct_expect.size =
			nftnl_obj_get_u8(nlo, NFTNL_OBJ_CT_EXPECT_SIZE);
		break;
	case NFT_OBJECT_SYNPROXY:
		obj->synproxy.mss =
			nftnl_obj_get_u16(nlo, NFTNL_OBJ_SYNPROXY_MSS);
		obj->synproxy.wscale =
			nftnl_obj_get_u8(nlo, NFTNL_OBJ_SYNPROXY_WSCALE);
		obj->synproxy.flags =
			nftnl_obj_get_u32(nlo, NFTNL_OBJ_SYNPROXY_FLAGS);
		break;
	}
	obj->type = type;

	return obj;
}

void netlink_dump_flowtable(struct nftnl_flowtable *flo,
			    struct netlink_ctx *ctx)
{
	FILE *fp = ctx->nft->output.output_fp;

	if (!(ctx->nft->debug_mask & NFT_DEBUG_NETLINK) || !fp)
		return;

	nftnl_flowtable_fprintf(fp, flo, 0, 0);
	fprintf(fp, "\n");
}

static int list_obj_cb(struct nftnl_obj *nls, void *arg)
{
	struct netlink_ctx *ctx = arg;
	struct obj *obj;

	obj = netlink_delinearize_obj(ctx, nls);
	if (obj == NULL)
		return -1;
	list_add_tail(&obj->list, &ctx->list);
	return 0;
}

int netlink_reset_objs(struct netlink_ctx *ctx, const struct cmd *cmd,
		       uint32_t type, bool dump)
{
	const struct handle *h = &cmd->handle;
	struct nftnl_obj_list *obj_cache;
	int err;

	obj_cache = mnl_nft_obj_dump(ctx, h->family,
				     h->table.name, h->obj.name, type, dump, true);
	if (obj_cache == NULL)
		return -1;

	err = nftnl_obj_list_foreach(obj_cache, list_obj_cb, ctx);
	nftnl_obj_list_free(obj_cache);
	return err;
}

struct flowtable *
netlink_delinearize_flowtable(struct netlink_ctx *ctx,
			      struct nftnl_flowtable *nlo)
{
	struct flowtable *flowtable;
	const char * const *dev_array;
	int len = 0, i, priority;

	flowtable = flowtable_alloc(&netlink_location);
	flowtable->handle.family =
		nftnl_flowtable_get_u32(nlo, NFTNL_FLOWTABLE_FAMILY);
	flowtable->handle.table.name =
		xstrdup(nftnl_flowtable_get_str(nlo, NFTNL_FLOWTABLE_TABLE));
	flowtable->handle.flowtable.name =
		xstrdup(nftnl_flowtable_get_str(nlo, NFTNL_FLOWTABLE_NAME));
	flowtable->handle.handle.id =
		nftnl_flowtable_get_u64(nlo, NFTNL_FLOWTABLE_HANDLE);
	if (nftnl_flowtable_is_set(nlo, NFTNL_FLOWTABLE_FLAGS))
		flowtable->flags = nftnl_flowtable_get_u32(nlo, NFTNL_FLOWTABLE_FLAGS);
	dev_array = nftnl_flowtable_get(nlo, NFTNL_FLOWTABLE_DEVICES);
	while (dev_array[len])
		len++;

	flowtable->dev_array = calloc(1, len * sizeof(char *));
	for (i = 0; i < len; i++)
		flowtable->dev_array[i] = xstrdup(dev_array[i]);

	flowtable->dev_array_len = len;

	if (flowtable->dev_array_len) {
		qsort(flowtable->dev_array, flowtable->dev_array_len,
		      sizeof(char *), qsort_device_cmp);
	}

	priority = nftnl_flowtable_get_u32(nlo, NFTNL_FLOWTABLE_PRIO);
	flowtable->priority.expr =
				constant_expr_alloc(&netlink_location,
						    &integer_type,
						    BYTEORDER_HOST_ENDIAN,
						    sizeof(int) *
						    BITS_PER_BYTE,
						    &priority);
	flowtable->hook.num =
		nftnl_flowtable_get_u32(nlo, NFTNL_FLOWTABLE_HOOKNUM);
	flowtable->flags =
		nftnl_flowtable_get_u32(nlo, NFTNL_FLOWTABLE_FLAGS);

	return flowtable;
}

static int list_flowtable_cb(struct nftnl_flowtable *nls, void *arg)
{
	struct netlink_ctx *ctx = arg;
	struct flowtable *flowtable;

	flowtable = netlink_delinearize_flowtable(ctx, nls);
	if (flowtable == NULL)
		return -1;
	list_add_tail(&flowtable->list, &ctx->list);
	return 0;
}

int netlink_list_flowtables(struct netlink_ctx *ctx, const struct handle *h)
{
	struct nftnl_flowtable_list *flowtable_cache;
	int err;

	flowtable_cache = mnl_nft_flowtable_dump(ctx, h->family,
						 h->table.name, NULL);
	if (flowtable_cache == NULL) {
		if (errno == EINTR)
			return -1;

		return 0;
	}

	err = nftnl_flowtable_list_foreach(flowtable_cache, list_flowtable_cb, ctx);
	nftnl_flowtable_list_free(flowtable_cache);
	return err;
}

static void trace_print_hdr(const struct nftnl_trace *nlt,
			    struct output_ctx *octx)
{
	nft_print(octx, "trace id %08x %s ",
		  nftnl_trace_get_u32(nlt, NFTNL_TRACE_ID),
		  family2str(nftnl_trace_get_u32(nlt, NFTNL_TRACE_FAMILY)));
	if (nftnl_trace_is_set(nlt, NFTNL_TRACE_TABLE))
		nft_print(octx, "%s ",
			  nftnl_trace_get_str(nlt, NFTNL_TRACE_TABLE));
	if (nftnl_trace_is_set(nlt, NFTNL_TRACE_CHAIN))
		nft_print(octx, "%s ",
			  nftnl_trace_get_str(nlt, NFTNL_TRACE_CHAIN));
}

static void trace_print_expr(const struct nftnl_trace *nlt, unsigned int attr,
			     struct expr *lhs, struct output_ctx *octx)
{
	struct expr *rhs, *rel;
	const void *data;
	uint32_t len;

	data = nftnl_trace_get_data(nlt, attr, &len);
	rhs  = constant_expr_alloc(&netlink_location,
				   lhs->dtype, lhs->byteorder,
				   len * BITS_PER_BYTE, data);
	rel  = relational_expr_alloc(&netlink_location, OP_EQ, lhs, rhs);

	expr_print(rel, octx);
	nft_print(octx, " ");
	expr_free(rel);
}

static void trace_print_verdict(const struct nftnl_trace *nlt,
				 struct output_ctx *octx)
{
	struct expr *chain_expr = NULL;
	const char *chain = NULL;
	unsigned int verdict;
	struct expr *expr;

	verdict = nftnl_trace_get_u32(nlt, NFTNL_TRACE_VERDICT);
	if (nftnl_trace_is_set(nlt, NFTNL_TRACE_JUMP_TARGET)) {
		chain = xstrdup(nftnl_trace_get_str(nlt, NFTNL_TRACE_JUMP_TARGET));
		chain_expr = constant_expr_alloc(&netlink_location,
						 &string_type,
						 BYTEORDER_HOST_ENDIAN,
						 strlen(chain) * BITS_PER_BYTE,
						 chain);
	}
	expr = verdict_expr_alloc(&netlink_location, verdict, chain_expr);

	nft_print(octx, "verdict ");
	expr_print(expr, octx);
	expr_free(expr);
}

static void trace_print_policy(const struct nftnl_trace *nlt,
			       struct output_ctx *octx)
{
	unsigned int policy;
	struct expr *expr;

	policy = nftnl_trace_get_u32(nlt, NFTNL_TRACE_POLICY);

	expr = verdict_expr_alloc(&netlink_location, policy, NULL);

	nft_print(octx, "policy ");
	expr_print(expr, octx);
	expr_free(expr);
}

static struct rule *trace_lookup_rule(const struct nftnl_trace *nlt,
				      uint64_t rule_handle,
				      struct nft_cache *cache)
{
	struct chain *chain;
	struct table *table;
	struct handle h;

	h.family = nftnl_trace_get_u32(nlt, NFTNL_TRACE_FAMILY);
	h.table.name = nftnl_trace_get_str(nlt, NFTNL_TRACE_TABLE);
	h.chain.name = nftnl_trace_get_str(nlt, NFTNL_TRACE_CHAIN);

	if (!h.table.name)
		return NULL;

	table = table_cache_find(&cache->table_cache, h.table.name, h.family);
	if (!table)
		return NULL;

	chain = chain_cache_find(table, h.chain.name);
	if (!chain)
		return NULL;

	return rule_lookup(chain, rule_handle);
}

static void trace_print_rule(const struct nftnl_trace *nlt,
			      struct output_ctx *octx, struct nft_cache *cache)
{
	uint64_t rule_handle;
	struct rule *rule;

	rule_handle = nftnl_trace_get_u64(nlt, NFTNL_TRACE_RULE_HANDLE);
	rule = trace_lookup_rule(nlt, rule_handle, cache);

	trace_print_hdr(nlt, octx);

	if (rule) {
		nft_print(octx, "rule ");
		rule_print(rule, octx);
	} else {
		nft_print(octx, "unknown rule handle %" PRIu64, rule_handle);
	}

	nft_print(octx, " (");
	trace_print_verdict(nlt, octx);
	nft_print(octx, ")\n");
}

static void trace_gen_stmts(struct list_head *stmts,
			    struct proto_ctx *ctx, struct payload_dep_ctx *pctx,
			    const struct nftnl_trace *nlt, unsigned int attr,
			    enum proto_bases base)
{
	struct list_head unordered = LIST_HEAD_INIT(unordered);
	struct list_head list;
	struct expr *rel, *lhs, *rhs, *tmp, *nexpr;
	struct stmt *stmt;
	const struct proto_desc *desc;
	const void *hdr;
	uint32_t hlen;
	unsigned int n;

	if (!nftnl_trace_is_set(nlt, attr))
		return;
	hdr = nftnl_trace_get_data(nlt, attr, &hlen);

	lhs = payload_expr_alloc(&netlink_location, NULL, 0);
	payload_init_raw(lhs, base, 0, hlen * BITS_PER_BYTE);
	rhs = constant_expr_alloc(&netlink_location,
				  &invalid_type, BYTEORDER_INVALID,
				  hlen * BITS_PER_BYTE, hdr);

restart:
	init_list_head(&list);
	payload_expr_expand(&list, lhs, ctx);
	expr_free(lhs);

	desc = NULL;
	list_for_each_entry_safe(lhs, nexpr, &list, list) {
		if (desc && desc != ctx->protocol[base].desc) {
			/* Chained protocols */
			lhs->payload.offset = 0;
			if (ctx->protocol[base].desc == NULL)
				break;
			goto restart;
		}

		tmp = constant_expr_splice(rhs, lhs->len);
		expr_set_type(tmp, lhs->dtype, lhs->byteorder);
		if (tmp->byteorder == BYTEORDER_HOST_ENDIAN)
			mpz_switch_byteorder(tmp->value, tmp->len / BITS_PER_BYTE);

		/* Skip unknown and filtered expressions */
		desc = lhs->payload.desc;
		if (lhs->dtype == &invalid_type ||
		    desc->checksum_key == payload_hdr_field(lhs) ||
		    desc->format.filter & (1 << payload_hdr_field(lhs))) {
			expr_free(lhs);
			expr_free(tmp);
			continue;
		}

		rel  = relational_expr_alloc(&lhs->location, OP_EQ, lhs, tmp);
		stmt = expr_stmt_alloc(&rel->location, rel);
		list_add_tail(&stmt->list, &unordered);

		desc = ctx->protocol[base].desc;
		relational_expr_pctx_update(ctx, rel);
	}

	expr_free(rhs);

	n = 0;
next:
	list_for_each_entry(stmt, &unordered, list) {
		enum proto_bases b = base;

		rel = stmt->expr;
		lhs = rel->left;

		/* Move statements to result list in defined order */
		desc = lhs->payload.desc;
		if (desc->format.order[n] &&
		    desc->format.order[n] != payload_hdr_field(lhs))
			continue;

		list_move_tail(&stmt->list, stmts);
		n++;

		if (payload_is_stacked(desc, rel))
			b--;

		/* Don't strip 'icmp type' from payload dump. */
		if (pctx->icmp_type == 0)
			payload_dependency_kill(pctx, lhs, ctx->family);
		if (lhs->flags & EXPR_F_PROTOCOL)
			payload_dependency_store(pctx, stmt, b);

		goto next;
	}
}

static void trace_print_packet(const struct nftnl_trace *nlt,
			        struct output_ctx *octx)
{
	struct list_head stmts = LIST_HEAD_INIT(stmts);
	const struct proto_desc *ll_desc;
	struct payload_dep_ctx pctx = {};
	struct proto_ctx ctx;
	uint16_t dev_type;
	uint32_t nfproto;
	struct stmt *stmt, *next;

	trace_print_hdr(nlt, octx);

	nft_print(octx, "packet: ");
	if (nftnl_trace_is_set(nlt, NFTNL_TRACE_IIF))
		trace_print_expr(nlt, NFTNL_TRACE_IIF,
				 meta_expr_alloc(&netlink_location,
						 NFT_META_IIF), octx);
	if (nftnl_trace_is_set(nlt, NFTNL_TRACE_OIF))
		trace_print_expr(nlt, NFTNL_TRACE_OIF,
				 meta_expr_alloc(&netlink_location,
						 NFT_META_OIF), octx);

	proto_ctx_init(&ctx, nftnl_trace_get_u32(nlt, NFTNL_TRACE_FAMILY), 0);
	ll_desc = ctx.protocol[PROTO_BASE_LL_HDR].desc;
	if ((ll_desc == &proto_inet || ll_desc  == &proto_netdev) &&
	    nftnl_trace_is_set(nlt, NFTNL_TRACE_NFPROTO)) {
		nfproto = nftnl_trace_get_u32(nlt, NFTNL_TRACE_NFPROTO);

		proto_ctx_update(&ctx, PROTO_BASE_LL_HDR, &netlink_location, NULL);
		proto_ctx_update(&ctx, PROTO_BASE_NETWORK_HDR, &netlink_location,
				 proto_find_upper(ll_desc, nfproto));
	}
	if (ctx.protocol[PROTO_BASE_LL_HDR].desc == NULL &&
	    nftnl_trace_is_set(nlt, NFTNL_TRACE_IIFTYPE)) {
		dev_type = nftnl_trace_get_u16(nlt, NFTNL_TRACE_IIFTYPE);
		proto_ctx_update(&ctx, PROTO_BASE_LL_HDR, &netlink_location,
				 proto_dev_desc(dev_type));
	}

	trace_gen_stmts(&stmts, &ctx, &pctx, nlt, NFTNL_TRACE_LL_HEADER,
			PROTO_BASE_LL_HDR);
	trace_gen_stmts(&stmts, &ctx, &pctx, nlt, NFTNL_TRACE_NETWORK_HEADER,
			PROTO_BASE_NETWORK_HDR);
	trace_gen_stmts(&stmts, &ctx, &pctx, nlt, NFTNL_TRACE_TRANSPORT_HEADER,
			PROTO_BASE_TRANSPORT_HDR);

	list_for_each_entry_safe(stmt, next, &stmts, list) {
		stmt_print(stmt, octx);
		nft_print(octx, " ");
		stmt_free(stmt);
	}
	nft_print(octx, "\n");
}

int netlink_events_trace_cb(const struct nlmsghdr *nlh, int type,
			    struct netlink_mon_handler *monh)
{
	struct nftnl_trace *nlt;

	assert(type == NFT_MSG_TRACE);

	nlt = nftnl_trace_alloc();
	if (!nlt)
		memory_allocation_error();

	if (nftnl_trace_nlmsg_parse(nlh, nlt) < 0)
		netlink_abi_error();

	if (nftnl_trace_is_set(nlt, NFTNL_TRACE_LL_HEADER) ||
	    nftnl_trace_is_set(nlt, NFTNL_TRACE_NETWORK_HEADER))
		trace_print_packet(nlt, &monh->ctx->nft->output);

	switch (nftnl_trace_get_u32(nlt, NFTNL_TRACE_TYPE)) {
	case NFT_TRACETYPE_RULE:
		if (nftnl_trace_is_set(nlt, NFTNL_TRACE_RULE_HANDLE))
			trace_print_rule(nlt, &monh->ctx->nft->output,
					 &monh->ctx->nft->cache);
		break;
	case NFT_TRACETYPE_POLICY:
		trace_print_hdr(nlt, &monh->ctx->nft->output);

		if (nftnl_trace_is_set(nlt, NFTNL_TRACE_POLICY)) {
			trace_print_policy(nlt, &monh->ctx->nft->output);
			nft_mon_print(monh, " ");
		}

		if (nftnl_trace_is_set(nlt, NFTNL_TRACE_MARK))
			trace_print_expr(nlt, NFTNL_TRACE_MARK,
					 meta_expr_alloc(&netlink_location,
							 NFT_META_MARK),
					 &monh->ctx->nft->output);
		nft_mon_print(monh, "\n");
		break;
	case NFT_TRACETYPE_RETURN:
		trace_print_hdr(nlt, &monh->ctx->nft->output);

		if (nftnl_trace_is_set(nlt, NFTNL_TRACE_VERDICT)) {
			trace_print_verdict(nlt, &monh->ctx->nft->output);
			nft_mon_print(monh, " ");
		}

		if (nftnl_trace_is_set(nlt, NFTNL_TRACE_MARK))
			trace_print_expr(nlt, NFTNL_TRACE_MARK,
					 meta_expr_alloc(&netlink_location,
							 NFT_META_MARK),
					 &monh->ctx->nft->output);
		nft_mon_print(monh, "\n");
		break;
	}

	nftnl_trace_free(nlt);
	return MNL_CB_OK;
}
