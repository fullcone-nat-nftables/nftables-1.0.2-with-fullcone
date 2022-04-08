/*
 * Copyright (c) 2021 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 (or any
 * later) as published by the Free Software Foundation.
 */

/* Funded through the NGI0 PET Fund established by NLnet (https://nlnet.nl)
 * with support from the European Commission's Next Generation Internet
 * programme.
 */

#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <nftables.h>
#include <parser.h>
#include <expression.h>
#include <statement.h>
#include <utils.h>
#include <erec.h>

#define MAX_STMTS	32

struct optimize_ctx {
	struct stmt *stmt[MAX_STMTS];
	uint32_t num_stmts;

	struct stmt ***stmt_matrix;
	struct rule **rule;
	uint32_t num_rules;
};

static bool __expr_cmp(const struct expr *expr_a, const struct expr *expr_b)
{
	if (expr_a->etype != expr_b->etype)
		return false;

	switch (expr_a->etype) {
	case EXPR_PAYLOAD:
		/* disable until concatenation with integer works. */
		if (expr_a->payload.is_raw || expr_b->payload.is_raw)
			return false;
		if (expr_a->payload.base != expr_b->payload.base)
			return false;
		if (expr_a->payload.offset != expr_b->payload.offset)
			return false;
		if (expr_a->payload.desc != expr_b->payload.desc)
			return false;
		if (expr_a->payload.tmpl != expr_b->payload.tmpl)
			return false;
		break;
	case EXPR_EXTHDR:
		if (expr_a->exthdr.desc != expr_b->exthdr.desc)
			return false;
		if (expr_a->exthdr.tmpl != expr_b->exthdr.tmpl)
			return false;
		break;
	case EXPR_META:
		if (expr_a->meta.key != expr_b->meta.key)
			return false;
		if (expr_a->meta.base != expr_b->meta.base)
			return false;
		break;
	case EXPR_CT:
		if (expr_a->ct.key != expr_b->ct.key)
			return false;
		if (expr_a->ct.base != expr_b->ct.base)
			return false;
		if (expr_a->ct.direction != expr_b->ct.direction)
			return false;
		if (expr_a->ct.nfproto != expr_b->ct.nfproto)
			return false;
		break;
	case EXPR_RT:
		if (expr_a->rt.key != expr_b->rt.key)
			return false;
		break;
	case EXPR_SOCKET:
		if (expr_a->socket.key != expr_b->socket.key)
			return false;
		if (expr_a->socket.level != expr_b->socket.level)
			return false;
		break;
	default:
		return false;
	}

	return true;
}

static bool __stmt_type_eq(const struct stmt *stmt_a, const struct stmt *stmt_b)
{
	struct expr *expr_a, *expr_b;

	if (stmt_a->ops->type != stmt_b->ops->type)
		return false;

	switch (stmt_a->ops->type) {
	case STMT_EXPRESSION:
		expr_a = stmt_a->expr;
		expr_b = stmt_b->expr;

		return __expr_cmp(expr_a->left, expr_b->left);
	case STMT_COUNTER:
	case STMT_NOTRACK:
		break;
	case STMT_VERDICT:
		expr_a = stmt_a->expr;
		expr_b = stmt_b->expr;

		if (expr_a->etype != expr_b->etype)
			return false;

		if (expr_a->etype == EXPR_MAP &&
		    expr_b->etype == EXPR_MAP)
			return __expr_cmp(expr_a->map, expr_b->map);
		break;
	case STMT_LIMIT:
		if (stmt_a->limit.rate != stmt_b->limit.rate ||
		    stmt_a->limit.unit != stmt_b->limit.unit ||
		    stmt_a->limit.burst != stmt_b->limit.burst ||
		    stmt_a->limit.type != stmt_b->limit.type ||
		    stmt_a->limit.flags != stmt_b->limit.flags)
			return false;
		break;
	case STMT_LOG:
		if (stmt_a->log.snaplen != stmt_b->log.snaplen ||
		    stmt_a->log.group != stmt_b->log.group ||
		    stmt_a->log.qthreshold != stmt_b->log.qthreshold ||
		    stmt_a->log.level != stmt_b->log.level ||
		    stmt_a->log.logflags != stmt_b->log.logflags ||
		    stmt_a->log.flags != stmt_b->log.flags ||
		    stmt_a->log.prefix->etype != EXPR_VALUE ||
		    stmt_b->log.prefix->etype != EXPR_VALUE ||
		    mpz_cmp(stmt_a->log.prefix->value, stmt_b->log.prefix->value))
			return false;
		break;
	case STMT_REJECT:
		if (stmt_a->reject.expr || stmt_b->reject.expr)
			return false;

		if (stmt_a->reject.family != stmt_b->reject.family ||
		    stmt_a->reject.type != stmt_b->reject.type ||
		    stmt_a->reject.icmp_code != stmt_b->reject.icmp_code)
			return false;
		break;
	default:
		/* ... Merging anything else is yet unsupported. */
		return false;
	}

	return true;
}

static bool expr_verdict_eq(const struct expr *expr_a, const struct expr *expr_b)
{
	if (expr_a->verdict != expr_b->verdict)
		return false;
	if (expr_a->chain && expr_b->chain) {
		if (expr_a->chain->etype != expr_b->chain->etype)
			return false;
		if (expr_a->chain->etype == EXPR_VALUE &&
		    strcmp(expr_a->chain->identifier, expr_b->chain->identifier))
			return false;
	} else if (expr_a->chain || expr_b->chain) {
		return false;
	}

	return true;
}

static bool stmt_verdict_eq(const struct stmt *stmt_a, const struct stmt *stmt_b)
{
	struct expr *expr_a, *expr_b;

	assert (stmt_a->ops->type == STMT_VERDICT);

	expr_a = stmt_a->expr;
	expr_b = stmt_b->expr;
	if (expr_a->etype == EXPR_VERDICT &&
	    expr_b->etype == EXPR_VERDICT)
		return expr_verdict_eq(expr_a, expr_b);

	if (expr_a->etype == EXPR_MAP &&
	    expr_b->etype == EXPR_MAP)
		return __expr_cmp(expr_a->map, expr_b->map);

	return false;
}

static bool stmt_type_eq(const struct stmt *stmt_a, const struct stmt *stmt_b)
{
	if (!stmt_a && !stmt_b)
		return true;
	else if (!stmt_a)
		return false;
	else if (!stmt_b)
		return false;

	return __stmt_type_eq(stmt_a, stmt_b);
}

static bool stmt_type_find(struct optimize_ctx *ctx, const struct stmt *stmt)
{
	uint32_t i;

	for (i = 0; i < ctx->num_stmts; i++) {
		if (__stmt_type_eq(stmt, ctx->stmt[i]))
			return true;
	}

	return false;
}

static int rule_collect_stmts(struct optimize_ctx *ctx, struct rule *rule)
{
	struct stmt *stmt, *clone;

	list_for_each_entry(stmt, &rule->stmts, list) {
		if (stmt_type_find(ctx, stmt))
			continue;

		if (stmt->ops->type == STMT_VERDICT &&
		    stmt->expr->etype == EXPR_MAP)
			continue;

		/* No refcounter available in statement objects, clone it to
		 * to store in the array of selectors.
		 */
		clone = stmt_alloc(&internal_location, stmt->ops);
		switch (stmt->ops->type) {
		case STMT_EXPRESSION:
		case STMT_VERDICT:
			clone->expr = expr_get(stmt->expr);
			break;
		case STMT_COUNTER:
		case STMT_NOTRACK:
			break;
		case STMT_LIMIT:
			memcpy(&clone->limit, &stmt->limit, sizeof(clone->limit));
			break;
		case STMT_LOG:
			memcpy(&clone->log, &stmt->log, sizeof(clone->log));
			clone->log.prefix = expr_get(stmt->log.prefix);
			break;
		default:
			break;
		}

		ctx->stmt[ctx->num_stmts++] = clone;
		if (ctx->num_stmts >= MAX_STMTS)
			return -1;
	}

	return 0;
}

static int cmd_stmt_find_in_stmt_matrix(struct optimize_ctx *ctx, struct stmt *stmt)
{
	uint32_t i;

	for (i = 0; i < ctx->num_stmts; i++) {
		if (__stmt_type_eq(stmt, ctx->stmt[i]))
			return i;
	}
	/* should not ever happen. */
	return 0;
}

static void rule_build_stmt_matrix_stmts(struct optimize_ctx *ctx,
					 struct rule *rule, uint32_t *i)
{
	struct stmt *stmt;
	int k;

	list_for_each_entry(stmt, &rule->stmts, list) {
		k = cmd_stmt_find_in_stmt_matrix(ctx, stmt);
		ctx->stmt_matrix[*i][k] = stmt;
	}
	ctx->rule[(*i)++] = rule;
}

static int stmt_verdict_find(const struct optimize_ctx *ctx)
{
	uint32_t i;

	for (i = 0; i < ctx->num_stmts; i++) {
		if (ctx->stmt[i]->ops->type != STMT_VERDICT)
			continue;

		return i;
	}

	return -1;
}

struct merge {
	/* interval of rules to be merged */
	uint32_t	rule_from;
	uint32_t	num_rules;
	/* statements to be merged (index relative to statement matrix) */
	uint32_t	stmt[MAX_STMTS];
	uint32_t	num_stmts;
};

static void merge_expr_stmts(const struct optimize_ctx *ctx,
			     uint32_t from, uint32_t to,
			     const struct merge *merge,
			     struct stmt *stmt_a)
{
	struct expr *expr_a, *expr_b, *set, *elem;
	struct stmt *stmt_b;
	uint32_t i;

	set = set_expr_alloc(&internal_location, NULL);
	set->set_flags |= NFT_SET_ANONYMOUS;

	expr_a = stmt_a->expr->right;
	elem = set_elem_expr_alloc(&internal_location, expr_get(expr_a));
	compound_expr_add(set, elem);

	for (i = from + 1; i <= to; i++) {
		stmt_b = ctx->stmt_matrix[i][merge->stmt[0]];
		expr_b = stmt_b->expr->right;
		elem = set_elem_expr_alloc(&internal_location, expr_get(expr_b));
		compound_expr_add(set, elem);
	}

	expr_free(stmt_a->expr->right);
	stmt_a->expr->right = set;
}

static void merge_vmap(const struct optimize_ctx *ctx,
		       struct stmt *stmt_a, const struct stmt *stmt_b)
{
	struct expr *mappings, *mapping, *expr;

	mappings = stmt_b->expr->mappings;
	list_for_each_entry(expr, &mappings->expressions, list) {
		mapping = expr_clone(expr);
		compound_expr_add(stmt_a->expr->mappings, mapping);
	}
}

static void merge_verdict_stmts(const struct optimize_ctx *ctx,
				uint32_t from, uint32_t to,
				const struct merge *merge,
				struct stmt *stmt_a)
{
	struct stmt *stmt_b;
	uint32_t i;

	for (i = from + 1; i <= to; i++) {
		stmt_b = ctx->stmt_matrix[i][merge->stmt[0]];
		switch (stmt_b->ops->type) {
		case STMT_VERDICT:
			switch (stmt_b->expr->etype) {
			case EXPR_MAP:
				merge_vmap(ctx, stmt_a, stmt_b);
				break;
			default:
				assert(1);
			}
			break;
		default:
			assert(1);
			break;
		}
	}
}

static void merge_stmts(const struct optimize_ctx *ctx,
			uint32_t from, uint32_t to, const struct merge *merge)
{
	struct stmt *stmt_a = ctx->stmt_matrix[from][merge->stmt[0]];

	switch (stmt_a->ops->type) {
	case STMT_EXPRESSION:
		merge_expr_stmts(ctx, from, to, merge, stmt_a);
		break;
	case STMT_VERDICT:
		merge_verdict_stmts(ctx, from, to, merge, stmt_a);
		break;
	default:
		assert(1);
	}
}

static void merge_concat_stmts(const struct optimize_ctx *ctx,
			       uint32_t from, uint32_t to,
			       const struct merge *merge)
{
	struct expr *concat, *elem, *set;
	struct stmt *stmt, *stmt_a;
	uint32_t i, k;

	stmt = ctx->stmt_matrix[from][merge->stmt[0]];
	/* build concatenation of selectors, eg. ifname . ip daddr . tcp dport */
	concat = concat_expr_alloc(&internal_location);

	for (k = 0; k < merge->num_stmts; k++) {
		stmt_a = ctx->stmt_matrix[from][merge->stmt[k]];
		compound_expr_add(concat, expr_get(stmt_a->expr->left));
	}
	expr_free(stmt->expr->left);
	stmt->expr->left = concat;

	/* build set data contenation, eg. { eth0 . 1.1.1.1 . 22 } */
	set = set_expr_alloc(&internal_location, NULL);
	set->set_flags |= NFT_SET_ANONYMOUS;

	for (i = from; i <= to; i++) {
		concat = concat_expr_alloc(&internal_location);
		for (k = 0; k < merge->num_stmts; k++) {
			stmt_a = ctx->stmt_matrix[i][merge->stmt[k]];
			compound_expr_add(concat, expr_get(stmt_a->expr->right));
		}
		elem = set_elem_expr_alloc(&internal_location, concat);
		compound_expr_add(set, elem);
	}
	expr_free(stmt->expr->right);
	stmt->expr->right = set;

	for (k = 1; k < merge->num_stmts; k++) {
		stmt_a = ctx->stmt_matrix[from][merge->stmt[k]];
		list_del(&stmt_a->list);
		stmt_free(stmt_a);
	}
}

static void build_verdict_map(struct expr *expr, struct stmt *verdict, struct expr *set)
{
	struct expr *item, *elem, *mapping;

	if (expr->etype == EXPR_LIST) {
		list_for_each_entry(item, &expr->expressions, list) {
			elem = set_elem_expr_alloc(&internal_location, expr_get(item));
			mapping = mapping_expr_alloc(&internal_location, elem,
						     expr_get(verdict->expr));
			compound_expr_add(set, mapping);
		}
	} else {
		elem = set_elem_expr_alloc(&internal_location, expr_get(expr));
		mapping = mapping_expr_alloc(&internal_location, elem,
					     expr_get(verdict->expr));
		compound_expr_add(set, mapping);
	}
}

static void remove_counter(const struct optimize_ctx *ctx, uint32_t from)
{
	struct stmt *stmt;
	uint32_t i;

	/* remove counter statement */
	for (i = 0; i < ctx->num_stmts; i++) {
		stmt = ctx->stmt_matrix[from][i];
		if (!stmt)
			continue;

		if (stmt->ops->type == STMT_COUNTER) {
			list_del(&stmt->list);
			stmt_free(stmt);
		}
	}
}

static void merge_stmts_vmap(const struct optimize_ctx *ctx,
			     uint32_t from, uint32_t to,
			     const struct merge *merge)
{
	struct stmt *stmt_a = ctx->stmt_matrix[from][merge->stmt[0]];
	struct stmt *stmt_b, *verdict_a, *verdict_b, *stmt;
	struct expr *expr_a, *expr_b, *expr, *left, *set;
	uint32_t i;
	int k;

	k = stmt_verdict_find(ctx);
	assert(k >= 0);

	verdict_a = ctx->stmt_matrix[from][k];
	set = set_expr_alloc(&internal_location, NULL);
	set->set_flags |= NFT_SET_ANONYMOUS;

	expr_a = stmt_a->expr->right;
	build_verdict_map(expr_a, verdict_a, set);
	for (i = from + 1; i <= to; i++) {
		stmt_b = ctx->stmt_matrix[i][merge->stmt[0]];
		expr_b = stmt_b->expr->right;
		verdict_b = ctx->stmt_matrix[i][k];

		build_verdict_map(expr_b, verdict_b, set);
	}

	left = expr_get(stmt_a->expr->left);
	expr = map_expr_alloc(&internal_location, left, set);
	stmt = verdict_stmt_alloc(&internal_location, expr);

	remove_counter(ctx, from);
	list_add(&stmt->list, &stmt_a->list);
	list_del(&stmt_a->list);
	stmt_free(stmt_a);
	list_del(&verdict_a->list);
	stmt_free(verdict_a);
}

static void merge_concat_stmts_vmap(const struct optimize_ctx *ctx,
				    uint32_t from, uint32_t to,
				    const struct merge *merge)
{
	struct stmt *orig_stmt = ctx->stmt_matrix[from][merge->stmt[0]];
	struct expr *concat_a, *concat_b, *expr, *set;
	struct stmt *stmt, *stmt_a, *stmt_b, *verdict;
	uint32_t i, j;
	int k;

	k = stmt_verdict_find(ctx);
	assert(k >= 0);

	/* build concatenation of selectors, eg. ifname . ip daddr . tcp dport */
	concat_a = concat_expr_alloc(&internal_location);
	for (i = 0; i < merge->num_stmts; i++) {
		stmt_a = ctx->stmt_matrix[from][merge->stmt[i]];
		compound_expr_add(concat_a, expr_get(stmt_a->expr->left));
	}

	/* build set data contenation, eg. { eth0 . 1.1.1.1 . 22 : accept } */
	set = set_expr_alloc(&internal_location, NULL);
	set->set_flags |= NFT_SET_ANONYMOUS;

	for (i = from; i <= to; i++) {
		concat_b = concat_expr_alloc(&internal_location);
		for (j = 0; j < merge->num_stmts; j++) {
			stmt_b = ctx->stmt_matrix[i][merge->stmt[j]];
			expr = stmt_b->expr->right;
			compound_expr_add(concat_b, expr_get(expr));
		}
		verdict = ctx->stmt_matrix[i][k];
		build_verdict_map(concat_b, verdict, set);
		expr_free(concat_b);
	}

	expr = map_expr_alloc(&internal_location, concat_a, set);
	stmt = verdict_stmt_alloc(&internal_location, expr);

	remove_counter(ctx, from);
	list_add(&stmt->list, &orig_stmt->list);
	list_del(&orig_stmt->list);
	stmt_free(orig_stmt);

	for (i = 1; i < merge->num_stmts; i++) {
		stmt_a = ctx->stmt_matrix[from][merge->stmt[i]];
		list_del(&stmt_a->list);
		stmt_free(stmt_a);
	}

	verdict = ctx->stmt_matrix[from][k];
	list_del(&verdict->list);
	stmt_free(verdict);
}

static bool stmt_verdict_cmp(const struct optimize_ctx *ctx,
			     uint32_t from, uint32_t to)
{
	struct stmt *stmt_a, *stmt_b;
	uint32_t i;
	int k;

	k = stmt_verdict_find(ctx);
	if (k < 0)
		return true;

	for (i = from; i + 1 <= to; i++) {
		stmt_a = ctx->stmt_matrix[i][k];
		stmt_b = ctx->stmt_matrix[i + 1][k];
		if (!stmt_a && !stmt_b)
			return true;
		if (stmt_verdict_eq(stmt_a, stmt_b))
			return true;
	}

	return false;
}

static void rule_optimize_print(struct output_ctx *octx,
				const struct rule *rule)
{
	const struct location *loc = &rule->location;
	const struct input_descriptor *indesc = loc->indesc;
	const char *line = "";
	char buf[1024];

	switch (indesc->type) {
	case INDESC_BUFFER:
	case INDESC_CLI:
		line = indesc->data;
		*strchrnul(line, '\n') = '\0';
		break;
	case INDESC_STDIN:
		line = indesc->data;
		line += loc->line_offset;
		*strchrnul(line, '\n') = '\0';
		break;
	case INDESC_FILE:
		line = line_location(indesc, loc, buf, sizeof(buf));
		break;
	case INDESC_INTERNAL:
	case INDESC_NETLINK:
		break;
	default:
		BUG("invalid input descriptor type %u\n", indesc->type);
	}

	print_location(octx->error_fp, indesc, loc);
	fprintf(octx->error_fp, "%s\n", line);
}

static void merge_rules(const struct optimize_ctx *ctx,
			uint32_t from, uint32_t to,
			const struct merge *merge,
			struct output_ctx *octx)
{
	bool same_verdict;
	uint32_t i;

	same_verdict = stmt_verdict_cmp(ctx, from, to);

	if (merge->num_stmts > 1) {
		if (same_verdict)
			merge_concat_stmts(ctx, from, to, merge);
		else
			merge_concat_stmts_vmap(ctx, from, to, merge);
	} else {
		if (same_verdict)
			merge_stmts(ctx, from, to, merge);
		else
			merge_stmts_vmap(ctx, from, to, merge);
	}

	fprintf(octx->error_fp, "Merging:\n");
	rule_optimize_print(octx, ctx->rule[from]);

	for (i = from + 1; i <= to; i++) {
		rule_optimize_print(octx, ctx->rule[i]);
		list_del(&ctx->rule[i]->list);
		rule_free(ctx->rule[i]);
	}

	fprintf(octx->error_fp, "into:\n\t");
	rule_print(ctx->rule[from], octx);
	fprintf(octx->error_fp, "\n");
}

static bool rules_eq(const struct optimize_ctx *ctx, int i, int j)
{
	uint32_t k;

	for (k = 0; k < ctx->num_stmts; k++) {
		if (!stmt_type_eq(ctx->stmt_matrix[i][k], ctx->stmt_matrix[j][k]))
			return false;
	}

	return true;
}

static int chain_optimize(struct nft_ctx *nft, struct list_head *rules)
{
	struct optimize_ctx *ctx;
	uint32_t num_merges = 0;
	struct merge *merge;
	uint32_t i, j, m, k;
	struct rule *rule;
	int ret;

	ctx = xzalloc(sizeof(*ctx));

	/* Step 1: collect statements in rules */
	list_for_each_entry(rule, rules, list) {
		ret = rule_collect_stmts(ctx, rule);
		if (ret < 0)
			goto err;

		ctx->num_rules++;
	}

	ctx->rule = xzalloc(sizeof(ctx->rule) * ctx->num_rules);
	ctx->stmt_matrix = xzalloc(sizeof(struct stmt *) * ctx->num_rules);
	for (i = 0; i < ctx->num_rules; i++)
		ctx->stmt_matrix[i] = xzalloc(sizeof(struct stmt *) * MAX_STMTS);

	merge = xzalloc(sizeof(*merge) * ctx->num_rules);

	/* Step 2: Build matrix of statements */
	i = 0;
	list_for_each_entry(rule, rules, list)
		rule_build_stmt_matrix_stmts(ctx, rule, &i);

	/* Step 3: Look for common selectors for possible rule mergers */
	for (i = 0; i < ctx->num_rules; i++) {
		for (j = i + 1; j < ctx->num_rules; j++) {
			if (!rules_eq(ctx, i, j)) {
				if (merge[num_merges].num_rules > 0)
					num_merges++;

				i = j - 1;
				break;
			}
			if (merge[num_merges].num_rules > 0) {
				merge[num_merges].num_rules++;
			} else {
				merge[num_merges].rule_from = i;
				merge[num_merges].num_rules = 2;
			}
		}
		if (j == ctx->num_rules && merge[num_merges].num_rules > 0) {
			num_merges++;
			break;
		}
	}

	/* Step 4: Infer how to merge the candidate rules */
	for (k = 0; k < num_merges; k++) {
		i = merge[k].rule_from;

		for (m = 0; m < ctx->num_stmts; m++) {
			if (!ctx->stmt_matrix[i][m])
				continue;
			switch (ctx->stmt_matrix[i][m]->ops->type) {
			case STMT_EXPRESSION:
				merge[k].stmt[merge[k].num_stmts++] = m;
				break;
			default:
				break;
			}
		}

		j = merge[k].num_rules - 1;
		merge_rules(ctx, i, i + j, &merge[k], &nft->output);
	}
	ret = 0;
	for (i = 0; i < ctx->num_rules; i++)
		xfree(ctx->stmt_matrix[i]);

	xfree(ctx->stmt_matrix);
	xfree(merge);
err:
	for (i = 0; i < ctx->num_stmts; i++)
		stmt_free(ctx->stmt[i]);

	xfree(ctx->rule);
	xfree(ctx);

	return ret;
}

static int cmd_optimize(struct nft_ctx *nft, struct cmd *cmd)
{
	struct table *table;
	struct chain *chain;
	int ret = 0;

	switch (cmd->obj) {
	case CMD_OBJ_TABLE:
		table = cmd->table;
		if (!table)
			break;

		list_for_each_entry(chain, &table->chains, list) {
			if (chain->flags & CHAIN_F_HW_OFFLOAD)
				continue;

			chain_optimize(nft, &chain->rules);
		}
		break;
	default:
		break;
	}

	return ret;
}

int nft_optimize(struct nft_ctx *nft, struct list_head *cmds)
{
	struct cmd *cmd;
	int ret;

	list_for_each_entry(cmd, cmds, list) {
		switch (cmd->op) {
		case CMD_ADD:
			ret = cmd_optimize(nft, cmd);
			break;
		default:
			break;
		}
	}

	return ret;
}
