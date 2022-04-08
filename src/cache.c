/*
 * Copyright (c) 2019 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 (or any
 * later) as published by the Free Software Foundation.
 */

#include <expression.h>
#include <statement.h>
#include <rule.h>
#include <erec.h>
#include <utils.h>
#include <cache.h>
#include <netlink.h>
#include <mnl.h>
#include <libnftnl/chain.h>
#include <linux/netfilter.h>

static unsigned int evaluate_cache_add(struct cmd *cmd, unsigned int flags)
{
	switch (cmd->obj) {
	case CMD_OBJ_TABLE:
		if (!cmd->table)
			break;

		flags |= NFT_CACHE_TABLE |
			 NFT_CACHE_CHAIN |
			 NFT_CACHE_SET |
			 NFT_CACHE_OBJECT |
			 NFT_CACHE_FLOWTABLE;
		break;
	case CMD_OBJ_CHAIN:
	case CMD_OBJ_SET:
	case CMD_OBJ_COUNTER:
	case CMD_OBJ_QUOTA:
	case CMD_OBJ_LIMIT:
	case CMD_OBJ_SECMARK:
	case CMD_OBJ_CT_HELPER:
	case CMD_OBJ_CT_TIMEOUT:
	case CMD_OBJ_CT_EXPECT:
	case CMD_OBJ_SYNPROXY:
	case CMD_OBJ_FLOWTABLE:
		flags |= NFT_CACHE_TABLE;
		break;
	case CMD_OBJ_ELEMENTS:
		flags |= NFT_CACHE_TABLE |
			 NFT_CACHE_CHAIN |
			 NFT_CACHE_SET |
			 NFT_CACHE_OBJECT |
			 NFT_CACHE_SETELEM_MAYBE;
		break;
	case CMD_OBJ_RULE:
		flags |= NFT_CACHE_TABLE |
			 NFT_CACHE_CHAIN |
			 NFT_CACHE_SET |
			 NFT_CACHE_OBJECT |
			 NFT_CACHE_FLOWTABLE;

		if (cmd->handle.index.id ||
		    cmd->handle.position.id)
			flags |= NFT_CACHE_RULE | NFT_CACHE_UPDATE;
		break;
	default:
		break;
	}

	return flags;
}

static unsigned int evaluate_cache_del(struct cmd *cmd, unsigned int flags)
{
	switch (cmd->obj) {
	case CMD_OBJ_ELEMENTS:
		flags |= NFT_CACHE_SETELEM_MAYBE;
		break;
	default:
		break;
	}

	return flags;
}

static unsigned int evaluate_cache_get(struct cmd *cmd, unsigned int flags)
{
	switch (cmd->obj) {
	case CMD_OBJ_ELEMENTS:
		flags |= NFT_CACHE_TABLE |
			 NFT_CACHE_SET |
			 NFT_CACHE_SETELEM;
		break;
	default:
		break;
	}

	return flags;
}

struct nft_cache_filter *nft_cache_filter_init(void)
{
	struct nft_cache_filter *filter;
	int i;

	filter = xzalloc(sizeof(struct nft_cache_filter));
	memset(&filter->list, 0, sizeof(filter->list));
	for (i = 0; i < NFT_CACHE_HSIZE; i++)
		init_list_head(&filter->obj[i].head);

	return filter;
}

void nft_cache_filter_fini(struct nft_cache_filter *filter)
{
	int i;

	for (i = 0; i < NFT_CACHE_HSIZE; i++) {
		struct nft_filter_obj *obj, *next;

		list_for_each_entry_safe(obj, next, &filter->obj[i].head, list)
			xfree(obj);
	}
	xfree(filter);
}

static void cache_filter_add(struct nft_cache_filter *filter,
			     const struct cmd *cmd)
{
	struct nft_filter_obj *obj;
	uint32_t hash;

	obj = xmalloc(sizeof(struct nft_filter_obj));
	obj->family = cmd->handle.family;
	obj->table = cmd->handle.table.name;
	obj->set = cmd->handle.set.name;

	hash = djb_hash(cmd->handle.set.name) % NFT_CACHE_HSIZE;
	list_add_tail(&obj->list, &filter->obj[hash].head);
}

static bool cache_filter_find(const struct nft_cache_filter *filter,
			      const struct handle *handle)
{
	struct nft_filter_obj *obj;
	uint32_t hash;

	hash = djb_hash(handle->set.name) % NFT_CACHE_HSIZE;

	list_for_each_entry(obj, &filter->obj[hash].head, list) {
		if (obj->family == handle->family &&
		    !strcmp(obj->table, handle->table.name) &&
		    !strcmp(obj->set, handle->set.name))
			return true;
	}

	return false;
}

static unsigned int evaluate_cache_flush(struct cmd *cmd, unsigned int flags,
					 struct nft_cache_filter *filter)
{
	switch (cmd->obj) {
	case CMD_OBJ_SET:
	case CMD_OBJ_MAP:
	case CMD_OBJ_METER:
		flags |= NFT_CACHE_SET;
		cache_filter_add(filter, cmd);
		break;
	case CMD_OBJ_RULESET:
		flags |= NFT_CACHE_FLUSHED;
		break;
	default:
		break;
	}

	return flags;
}

static unsigned int evaluate_cache_rename(struct cmd *cmd, unsigned int flags)
{
	switch (cmd->obj) {
	case CMD_OBJ_CHAIN:
		flags |= NFT_CACHE_CHAIN;
		break;
	default:
		break;
	}

	return flags;
}

static unsigned int evaluate_cache_list(struct nft_ctx *nft, struct cmd *cmd,
					unsigned int flags,
					struct nft_cache_filter *filter)
{
	switch (cmd->obj) {
	case CMD_OBJ_TABLE:
		if (filter && cmd->handle.table.name) {
			filter->list.family = cmd->handle.family;
			filter->list.table = cmd->handle.table.name;
		}
		flags |= NFT_CACHE_FULL;
		break;
	case CMD_OBJ_CHAIN:
		if (filter && cmd->handle.chain.name) {
			filter->list.family = cmd->handle.family;
			filter->list.table = cmd->handle.table.name;
			filter->list.chain = cmd->handle.chain.name;
		}
		flags |= NFT_CACHE_FULL;
		break;
	case CMD_OBJ_SET:
	case CMD_OBJ_MAP:
		if (filter && cmd->handle.table.name && cmd->handle.set.name) {
			filter->list.family = cmd->handle.family;
			filter->list.table = cmd->handle.table.name;
			filter->list.set = cmd->handle.set.name;
		}
		if (filter->list.table && filter->list.set)
			flags |= NFT_CACHE_TABLE | NFT_CACHE_SET | NFT_CACHE_SETELEM;
		else if (nft_output_terse(&nft->output))
			flags |= NFT_CACHE_FULL | NFT_CACHE_TERSE;
		else
			flags |= NFT_CACHE_FULL;
		break;
	case CMD_OBJ_CHAINS:
		flags |= NFT_CACHE_TABLE | NFT_CACHE_CHAIN;
		break;
	case CMD_OBJ_SETS:
	case CMD_OBJ_MAPS:
		flags |= NFT_CACHE_TABLE | NFT_CACHE_SET;
		break;
	case CMD_OBJ_FLOWTABLE:
		if (filter &&
		    cmd->handle.table.name &&
		    cmd->handle.flowtable.name) {
			filter->list.family = cmd->handle.family;
			filter->list.table = cmd->handle.table.name;
			filter->list.ft = cmd->handle.flowtable.name;
		}
		/* fall through */
	case CMD_OBJ_FLOWTABLES:
		flags |= NFT_CACHE_TABLE | NFT_CACHE_FLOWTABLE;
		break;
	case CMD_OBJ_RULESET:
		if (nft_output_terse(&nft->output))
			flags |= NFT_CACHE_FULL | NFT_CACHE_TERSE;
		else
			flags |= NFT_CACHE_FULL;
		break;
	default:
		flags |= NFT_CACHE_FULL;
		break;
	}
	flags |= NFT_CACHE_REFRESH;

	return flags;
}

unsigned int nft_cache_evaluate(struct nft_ctx *nft, struct list_head *cmds,
				struct nft_cache_filter *filter)
{
	unsigned int flags = NFT_CACHE_EMPTY;
	struct cmd *cmd;

	list_for_each_entry(cmd, cmds, list) {
		if (filter->list.table && cmd->op != CMD_LIST)
			memset(&filter->list, 0, sizeof(filter->list));

		switch (cmd->op) {
		case CMD_ADD:
		case CMD_INSERT:
		case CMD_CREATE:
			flags = evaluate_cache_add(cmd, flags);
			if (nft_output_echo(&nft->output))
				flags |= NFT_CACHE_FULL;
			break;
		case CMD_REPLACE:
			flags = NFT_CACHE_FULL;
			break;
		case CMD_DELETE:
			flags |= NFT_CACHE_TABLE |
				 NFT_CACHE_CHAIN |
				 NFT_CACHE_SET |
				 NFT_CACHE_FLOWTABLE |
				 NFT_CACHE_OBJECT;

			flags = evaluate_cache_del(cmd, flags);
			break;
		case CMD_GET:
			flags = evaluate_cache_get(cmd, flags);
			break;
		case CMD_RESET:
			flags |= NFT_CACHE_TABLE;
			break;
		case CMD_LIST:
			flags |= evaluate_cache_list(nft, cmd, flags, filter);
			break;
		case CMD_MONITOR:
			flags |= NFT_CACHE_FULL;
			break;
		case CMD_FLUSH:
			flags = evaluate_cache_flush(cmd, flags, filter);
			break;
		case CMD_RENAME:
			flags = evaluate_cache_rename(cmd, flags);
			break;
		case CMD_DESCRIBE:
		case CMD_IMPORT:
		case CMD_EXPORT:
			break;
		default:
			break;
		}
	}

	return flags;
}

void table_cache_add(struct table *table, struct nft_cache *cache)
{
	uint32_t hash;

	hash = djb_hash(table->handle.table.name) % NFT_CACHE_HSIZE;
	cache_add(&table->cache, &cache->table_cache, hash);
}

void table_cache_del(struct table *table)
{
	cache_del(&table->cache);
}

struct table *table_cache_find(const struct cache *cache,
			       const char *name, uint32_t family)
{
	struct table *table;
	uint32_t hash;

	if (!name)
		return NULL;

	hash = djb_hash(name) % NFT_CACHE_HSIZE;
	list_for_each_entry(table, &cache->ht[hash], cache.hlist) {
		if (table->handle.family == family &&
		    !strcmp(table->handle.table.name, name))
			return table;
	}

	return NULL;
}

struct chain_cache_dump_ctx {
	struct netlink_ctx	*nlctx;
	struct table		*table;
};

static int chain_cache_cb(struct nftnl_chain *nlc, void *arg)
{
	struct chain_cache_dump_ctx *ctx = arg;
	const char *chain_name, *table_name;
	uint32_t hash, family;
	struct chain *chain;

	table_name = nftnl_chain_get_str(nlc, NFTNL_CHAIN_TABLE);
	family = nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FAMILY);

	if (family != ctx->table->handle.family ||
	    strcmp(table_name, ctx->table->handle.table.name))
		return 0;

	chain_name = nftnl_chain_get_str(nlc, NFTNL_CHAIN_NAME);
	hash = djb_hash(chain_name) % NFT_CACHE_HSIZE;
	chain = netlink_delinearize_chain(ctx->nlctx, nlc);

	if (chain->flags & CHAIN_F_BINDING) {
		list_add_tail(&chain->cache.list, &ctx->table->chain_bindings);
	} else {
		cache_add(&chain->cache, &ctx->table->chain_cache, hash);
	}

	nftnl_chain_list_del(nlc);
	nftnl_chain_free(nlc);

	return 0;
}

static int chain_cache_init(struct netlink_ctx *ctx, struct table *table,
			    struct nftnl_chain_list *chain_list)
{
	struct chain_cache_dump_ctx dump_ctx = {
		.nlctx	= ctx,
		.table	= table,
	};
	nftnl_chain_list_foreach(chain_list, chain_cache_cb, &dump_ctx);

	return 0;
}

static struct nftnl_chain_list *
chain_cache_dump(struct netlink_ctx *ctx,
		 const struct nft_cache_filter *filter, int *err)
{
	struct nftnl_chain_list *chain_list;
	const char *table = NULL;
	const char *chain = NULL;
	int family = NFPROTO_UNSPEC;

	if (filter && filter->list.table && filter->list.chain) {
		family = filter->list.family;
		table = filter->list.table;
		chain = filter->list.chain;
	}

	chain_list = mnl_nft_chain_dump(ctx, family, table, chain);
	if (chain_list == NULL) {
		if (errno == EINTR) {
			*err = -1;
			return NULL;
		}
		*err = 0;
		return NULL;
	}

	return chain_list;
}

void nft_chain_cache_update(struct netlink_ctx *ctx, struct table *table,
			    const char *chain)
{
	struct nftnl_chain_list *chain_list;

	chain_list = mnl_nft_chain_dump(ctx, table->handle.family,
					table->handle.table.name, chain);
	if (!chain_list)
		return;

	chain_cache_init(ctx, table, chain_list);

	nftnl_chain_list_free(chain_list);
}

void chain_cache_add(struct chain *chain, struct table *table)
{
	uint32_t hash;

	hash = djb_hash(chain->handle.chain.name) % NFT_CACHE_HSIZE;
	cache_add(&chain->cache, &table->chain_cache, hash);
}

void chain_cache_del(struct chain *chain)
{
	cache_del(&chain->cache);
}

struct chain *chain_cache_find(const struct table *table, const char *name)
{
	struct chain *chain;
	uint32_t hash;

	hash = djb_hash(name) % NFT_CACHE_HSIZE;
	list_for_each_entry(chain, &table->chain_cache.ht[hash], cache.hlist) {
		if (!strcmp(chain->handle.chain.name, name))
			return chain;
	}

	return NULL;
}

static int list_rule_cb(struct nftnl_rule *nlr, void *data)
{
	struct netlink_ctx *ctx = data;
	const struct handle *h = ctx->data;
	const char *table, *chain;
	struct rule *rule;
	uint32_t family;

	family = nftnl_rule_get_u32(nlr, NFTNL_RULE_FAMILY);
	table  = nftnl_rule_get_str(nlr, NFTNL_RULE_TABLE);
	chain  = nftnl_rule_get_str(nlr, NFTNL_RULE_CHAIN);

	if (h->family != family ||
	    strcmp(table, h->table.name) != 0 ||
	    (h->chain.name && strcmp(chain, h->chain.name) != 0))
		return 0;

	netlink_dump_rule(nlr, ctx);
	rule = netlink_delinearize_rule(ctx, nlr);
	list_add_tail(&rule->list, &ctx->list);

	return 0;
}

static int rule_cache_dump(struct netlink_ctx *ctx, const struct handle *h,
			   const struct nft_cache_filter *filter)
{
	struct nftnl_rule_list *rule_cache;
	const char *table = NULL;
	const char *chain = NULL;

	if (filter) {
		table = filter->list.table;
		chain = filter->list.chain;
	}

	rule_cache = mnl_nft_rule_dump(ctx, h->family, table, chain);
	if (rule_cache == NULL) {
		if (errno == EINTR)
			return -1;

		return 0;
	}

	ctx->data = h;
	nftnl_rule_list_foreach(rule_cache, list_rule_cb, ctx);
	nftnl_rule_list_free(rule_cache);
	return 0;
}

struct set_cache_dump_ctx {
	struct netlink_ctx	*nlctx;
	struct table		*table;
};

static int set_cache_cb(struct nftnl_set *nls, void *arg)
{
	struct set_cache_dump_ctx *ctx = arg;
	const char *set_table;
	const char *set_name;
	uint32_t set_family;
	struct set *set;
	uint32_t hash;

	set_table = nftnl_set_get_str(nls, NFTNL_SET_TABLE);
	set_family = nftnl_set_get_u32(nls, NFTNL_SET_FAMILY);

	if (set_family != ctx->table->handle.family ||
	    strcmp(set_table, ctx->table->handle.table.name))
		return 0;

	set = netlink_delinearize_set(ctx->nlctx, nls);
	if (!set)
		return -1;

	set_name = nftnl_set_get_str(nls, NFTNL_SET_NAME);
	hash = djb_hash(set_name) % NFT_CACHE_HSIZE;
	cache_add(&set->cache, &ctx->table->set_cache, hash);

	nftnl_set_list_del(nls);
	nftnl_set_free(nls);
	return 0;
}

static int set_cache_init(struct netlink_ctx *ctx, struct table *table,
			  struct nftnl_set_list *set_list)
{
	struct set_cache_dump_ctx dump_ctx = {
		.nlctx	= ctx,
		.table	= table,
	};

	nftnl_set_list_foreach(set_list, set_cache_cb, &dump_ctx);

	return 0;
}

static struct nftnl_set_list *
set_cache_dump(struct netlink_ctx *ctx,
	       const struct nft_cache_filter *filter, int *err)
{
	struct nftnl_set_list *set_list;
	int family = NFPROTO_UNSPEC;
	const char *table = NULL;
	const char *set = NULL;

	if (filter) {
		family = filter->list.family;
		table = filter->list.table;
		set = filter->list.set;
	}

	set_list = mnl_nft_set_dump(ctx, family, table, set);
	if (!set_list) {
                if (errno == EINTR) {
			*err = -1;
			return NULL;
		}
		*err = 0;
		return NULL;
	}

	return set_list;
}

void set_cache_add(struct set *set, struct table *table)
{
	uint32_t hash;

	hash = djb_hash(set->handle.set.name) % NFT_CACHE_HSIZE;
	cache_add(&set->cache, &table->set_cache, hash);
}

void set_cache_del(struct set *set)
{
	cache_del(&set->cache);
}

struct set *set_cache_find(const struct table *table, const char *name)
{
	struct set *set;
	uint32_t hash;

	hash = djb_hash(name) % NFT_CACHE_HSIZE;
	list_for_each_entry(set, &table->set_cache.ht[hash], cache.hlist) {
		if (!strcmp(set->handle.set.name, name))
			return set;
	}

	return NULL;
}

struct obj_cache_dump_ctx {
	struct netlink_ctx	*nlctx;
	struct table		*table;
};

static int obj_cache_cb(struct nftnl_obj *nlo, void *arg)
{
	struct obj_cache_dump_ctx *ctx = arg;
	const char *obj_name;
	struct obj *obj;
	uint32_t hash;

	obj = netlink_delinearize_obj(ctx->nlctx, nlo);
	if (!obj)
		return -1;

	obj_name = nftnl_obj_get_str(nlo, NFTNL_OBJ_NAME);
	hash = djb_hash(obj_name) % NFT_CACHE_HSIZE;
	cache_add(&obj->cache, &ctx->table->obj_cache, hash);

	return 0;
}

static int obj_cache_init(struct netlink_ctx *ctx, struct table *table,
			  struct nftnl_obj_list *obj_list)
{
	struct obj_cache_dump_ctx dump_ctx = {
		.nlctx	= ctx,
		.table	= table,
	};
	nftnl_obj_list_foreach(obj_list, obj_cache_cb, &dump_ctx);

	return 0;
}

static struct nftnl_obj_list *obj_cache_dump(struct netlink_ctx *ctx,
					     const struct table *table)
{
	struct nftnl_obj_list *obj_list;

	obj_list = mnl_nft_obj_dump(ctx, table->handle.family,
				    table->handle.table.name, NULL,
				    0, true, false);
	if (!obj_list) {
                if (errno == EINTR)
			return NULL;

		/* old kernels do not support this, provide an empty list. */
		obj_list = nftnl_obj_list_alloc();
		if (!obj_list)
	                memory_allocation_error();

		return obj_list;
	}

	return obj_list;
}

void obj_cache_add(struct obj *obj, struct table *table)
{
	uint32_t hash;

	hash = djb_hash(obj->handle.obj.name) % NFT_CACHE_HSIZE;
	cache_add(&obj->cache, &table->obj_cache, hash);
}

void obj_cache_del(struct obj *obj)
{
	cache_del(&obj->cache);
}

struct obj *obj_cache_find(const struct table *table, const char *name,
			   uint32_t obj_type)
{
	struct obj *obj;
	uint32_t hash;

	hash = djb_hash(name) % NFT_CACHE_HSIZE;
	list_for_each_entry(obj, &table->obj_cache.ht[hash], cache.hlist) {
		if (!strcmp(obj->handle.obj.name, name) &&
		    obj->type == obj_type)
			return obj;
	}

	return NULL;
}

struct ft_cache_dump_ctx {
	struct netlink_ctx	*nlctx;
	struct table		*table;
};

static int ft_cache_cb(struct nftnl_flowtable *nlf, void *arg)
{
	struct ft_cache_dump_ctx *ctx = arg;
	struct flowtable *ft;
	const char *ft_table;
	const char *ft_name;
	uint32_t ft_family;
	uint32_t hash;

	ft_family = nftnl_flowtable_get_u32(nlf, NFTNL_FLOWTABLE_FAMILY);
	ft_table = nftnl_flowtable_get_str(nlf, NFTNL_FLOWTABLE_TABLE);

	if (ft_family != ctx->table->handle.family ||
	    strcmp(ft_table, ctx->table->handle.table.name))
		return 0;

	ft = netlink_delinearize_flowtable(ctx->nlctx, nlf);
	if (!ft)
		return -1;

	ft_name = nftnl_flowtable_get_str(nlf, NFTNL_FLOWTABLE_NAME);
	hash = djb_hash(ft_name) % NFT_CACHE_HSIZE;
	cache_add(&ft->cache, &ctx->table->ft_cache, hash);

	nftnl_flowtable_list_del(nlf);
	nftnl_flowtable_free(nlf);
	return 0;
}

static int ft_cache_init(struct netlink_ctx *ctx, struct table *table,
			 struct nftnl_flowtable_list *ft_list)
{
	struct ft_cache_dump_ctx dump_ctx = {
		.nlctx	= ctx,
		.table	= table,
	};
	nftnl_flowtable_list_foreach(ft_list, ft_cache_cb, &dump_ctx);

	return 0;
}

static struct nftnl_flowtable_list *
ft_cache_dump(struct netlink_ctx *ctx, const struct nft_cache_filter *filter)
{
	struct nftnl_flowtable_list *ft_list;
	int family = NFPROTO_UNSPEC;
	const char *table = NULL;
	const char *ft = NULL;

	if (filter) {
		family = filter->list.family;
		table = filter->list.table;
		ft = filter->list.ft;
	}

	ft_list = mnl_nft_flowtable_dump(ctx, family, table, ft);
	if (!ft_list) {
                if (errno == EINTR)
			return NULL;

		/* old kernels do not support this, provide an empty list. */
		ft_list = nftnl_flowtable_list_alloc();
		if (!ft_list)
	                memory_allocation_error();

		return ft_list;
	}

	return ft_list;
}

void ft_cache_add(struct flowtable *ft, struct table *table)
{
	uint32_t hash;

	hash = djb_hash(ft->handle.flowtable.name) % NFT_CACHE_HSIZE;
	cache_add(&ft->cache, &table->ft_cache, hash);
}

void ft_cache_del(struct flowtable *ft)
{
	cache_del(&ft->cache);
}

struct flowtable *ft_cache_find(const struct table *table, const char *name)
{
	struct flowtable *ft;
	uint32_t hash;

	hash = djb_hash(name) % NFT_CACHE_HSIZE;
	list_for_each_entry(ft, &table->ft_cache.ht[hash], cache.hlist) {
		if (!strcmp(ft->handle.flowtable.name, name))
			return ft;
	}

	return NULL;
}

static int cache_init_tables(struct netlink_ctx *ctx, struct handle *h,
			     struct nft_cache *cache,
			     const struct nft_cache_filter *filter)
{
	struct table *table, *next;
	int ret;

	ret = netlink_list_tables(ctx, h, filter);
	if (ret < 0)
		return -1;

	list_for_each_entry_safe(table, next, &ctx->list, list) {
		list_del(&table->list);
		table_cache_add(table, cache);
	}

	return 0;
}

static int rule_init_cache(struct netlink_ctx *ctx, struct table *table,
			   const struct nft_cache_filter *filter)
{
	struct rule *rule, *nrule;
	struct chain *chain;
	int ret;

	ret = rule_cache_dump(ctx, &table->handle, filter);

	list_for_each_entry_safe(rule, nrule, &ctx->list, list) {
		chain = chain_cache_find(table, rule->handle.chain.name);
		if (!chain)
			chain = chain_binding_lookup(table,
						     rule->handle.chain.name);
		if (!chain)
			return -1;

		list_move_tail(&rule->list, &chain->rules);
	}

	return ret;
}

static int implicit_chain_cache(struct netlink_ctx *ctx, struct table *table,
				const char *chain_name)
{
	struct nft_cache_filter filter;
	struct chain *chain;
	int ret = 0;

	list_for_each_entry(chain, &table->chain_bindings, cache.list) {
		filter.list.table = table->handle.table.name;
		filter.list.chain = chain->handle.chain.name;
		ret = rule_init_cache(ctx, table, &filter);
	}

	return ret;
}

static int cache_init_objects(struct netlink_ctx *ctx, unsigned int flags,
			      const struct nft_cache_filter *filter)
{
	struct nftnl_flowtable_list *ft_list = NULL;
	struct nftnl_chain_list *chain_list = NULL;
	struct nftnl_set_list *set_list = NULL;
	struct nftnl_obj_list *obj_list;
	struct table *table;
	struct set *set;
	int ret = 0;

	if (flags & NFT_CACHE_CHAIN_BIT) {
		chain_list = chain_cache_dump(ctx, filter, &ret);
		if (!chain_list)
			return -1;
	}
	if (flags & NFT_CACHE_SET_BIT) {
		set_list = set_cache_dump(ctx, filter, &ret);
		if (!set_list) {
			ret = -1;
			goto cache_fails;
		}
	}
	if (flags & NFT_CACHE_FLOWTABLE_BIT) {
		ft_list = ft_cache_dump(ctx, filter);
		if (!ft_list) {
			ret = -1;
			goto cache_fails;
		}
	}

	list_for_each_entry(table, &ctx->nft->cache.table_cache.list, cache.list) {
		if (flags & NFT_CACHE_SET_BIT) {
			ret = set_cache_init(ctx, table, set_list);
			if (ret < 0)
				goto cache_fails;
		}
		if (flags & NFT_CACHE_SETELEM_BIT) {
			list_for_each_entry(set, &table->set_cache.list, cache.list) {
				if (cache_filter_find(filter, &set->handle))
					continue;
				if (!set_is_anonymous(set->flags) &&
				    flags & NFT_CACHE_TERSE)
					continue;

				ret = netlink_list_setelems(ctx, &set->handle,
							    set);
				if (ret < 0)
					goto cache_fails;
			}
		} else if (flags & NFT_CACHE_SETELEM_MAYBE) {
			list_for_each_entry(set, &table->set_cache.list, cache.list) {
				if (cache_filter_find(filter, &set->handle))
					continue;

				if (!set_is_non_concat_range(set))
					continue;

				ret = netlink_list_setelems(ctx, &set->handle,
							    set);
				if (ret < 0)
					goto cache_fails;
			}
		}
		if (flags & NFT_CACHE_CHAIN_BIT) {
			ret = chain_cache_init(ctx, table, chain_list);
			if (ret < 0)
				goto cache_fails;
		}
		if (flags & NFT_CACHE_FLOWTABLE_BIT) {
			ret = ft_cache_init(ctx, table, ft_list);
			if (ret < 0)
				goto cache_fails;
		}
		if (flags & NFT_CACHE_OBJECT_BIT) {
			obj_list = obj_cache_dump(ctx, table);
			if (!obj_list) {
				ret = -1;
				goto cache_fails;
			}
			ret = obj_cache_init(ctx, table, obj_list);

			nftnl_obj_list_free(obj_list);

			if (ret < 0)
				goto cache_fails;
		}

		if (flags & NFT_CACHE_RULE_BIT) {
			ret = rule_init_cache(ctx, table, filter);
			if (ret < 0)
				goto cache_fails;

			if (filter && filter->list.table && filter->list.chain) {
				ret = implicit_chain_cache(ctx, table, filter->list.chain);
				if (ret < 0)
					goto cache_fails;
			}
		}
	}

cache_fails:
	if (set_list)
		nftnl_set_list_free(set_list);
	if (ft_list)
		nftnl_flowtable_list_free(ft_list);

	if (flags & NFT_CACHE_CHAIN_BIT)
		nftnl_chain_list_free(chain_list);

	return ret;
}

static int nft_cache_init(struct netlink_ctx *ctx, unsigned int flags,
			  const struct nft_cache_filter *filter)
{
	struct handle handle = {
		.family = NFPROTO_UNSPEC,
	};
	int ret;

	if (flags == NFT_CACHE_EMPTY)
		return 0;

	/* assume NFT_CACHE_TABLE is always set. */
	ret = cache_init_tables(ctx, &handle, &ctx->nft->cache, filter);
	if (ret < 0)
		return ret;
	ret = cache_init_objects(ctx, flags, filter);
	if (ret < 0)
		return ret;

	return 0;
}

static bool nft_cache_is_complete(struct nft_cache *cache, unsigned int flags)
{
	return (cache->flags & flags) == flags;
}

static bool nft_cache_needs_refresh(struct nft_cache *cache)
{
	return cache->flags & NFT_CACHE_REFRESH;
}

static bool nft_cache_is_updated(struct nft_cache *cache, uint16_t genid)
{
	return genid && genid == cache->genid;
}

bool nft_cache_needs_update(struct nft_cache *cache)
{
	return cache->flags & NFT_CACHE_UPDATE;
}

int nft_cache_update(struct nft_ctx *nft, unsigned int flags,
		     struct list_head *msgs,
		     const struct nft_cache_filter *filter)
{
	struct netlink_ctx ctx = {
		.list		= LIST_HEAD_INIT(ctx.list),
		.nft		= nft,
		.msgs		= msgs,
	};
	struct nft_cache *cache = &nft->cache;
	uint32_t genid, genid_stop, oldflags;
	int ret;
replay:
	ctx.seqnum = cache->seqnum++;
	genid = mnl_genid_get(&ctx);
	if (!nft_cache_needs_refresh(cache) &&
	    nft_cache_is_complete(cache, flags) &&
	    nft_cache_is_updated(cache, genid))
		return 0;

	if (cache->genid)
		nft_cache_release(cache);

	if (flags & NFT_CACHE_FLUSHED) {
		oldflags = flags;
		flags = NFT_CACHE_EMPTY;
		if (oldflags & NFT_CACHE_UPDATE)
			flags |= NFT_CACHE_UPDATE;
		goto skip;
	}

	ret = nft_cache_init(&ctx, flags, filter);
	if (ret < 0) {
		if (errno == EINTR) {
			nft_cache_release(cache);
			goto replay;
		}

		nft_cache_release(cache);
		return -1;
	}

	genid_stop = mnl_genid_get(&ctx);
	if (genid != genid_stop) {
		nft_cache_release(cache);
		goto replay;
	}
skip:
	cache->genid = genid;
	cache->flags = flags;
	return 0;
}

static void nft_cache_flush(struct cache *table_cache)
{
	struct table *table, *next;

	list_for_each_entry_safe(table, next, &table_cache->list, cache.list) {
		table_cache_del(table);
		table_free(table);
	}
}

void nft_cache_release(struct nft_cache *cache)
{
	nft_cache_flush(&cache->table_cache);
	cache->genid = 0;
	cache->flags = NFT_CACHE_EMPTY;
}

void cache_init(struct cache *cache)
{
	int i;

	cache->ht = xmalloc(sizeof(struct list_head) * NFT_CACHE_HSIZE);
	for (i = 0; i < NFT_CACHE_HSIZE; i++)
		init_list_head(&cache->ht[i]);

	init_list_head(&cache->list);
}

void cache_free(struct cache *cache)
{
	xfree(cache->ht);
}

void cache_add(struct cache_item *item, struct cache *cache, uint32_t hash)
{
	list_add_tail(&item->hlist, &cache->ht[hash]);
	list_add_tail(&item->list, &cache->list);
}

void cache_del(struct cache_item *item)
{
	list_del(&item->hlist);
	list_del(&item->list);
}
