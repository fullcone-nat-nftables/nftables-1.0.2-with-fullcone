/*
 * Copyright (c) 2008-2012 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <libnftnl/udata.h>

#include <rule.h>
#include <expression.h>
#include <gmputil.h>
#include <utils.h>
#include <rbtree.h>

/**
 * struct seg_tree - segment tree
 *
 * @root:	the rbtree's root
 * @type:	the datatype of the dimension
 * @dwidth:	width of the dimension
 * @byteorder:	byteorder of elements
 * @debug_mask:	display debugging information
 */
struct seg_tree {
	struct rb_root			root;
	const struct datatype		*keytype;
	unsigned int			keylen;
	const struct datatype		*datatype;
	unsigned int			datalen;
	enum byteorder			byteorder;
	unsigned int			debug_mask;
};

enum elementary_interval_flags {
	EI_F_INTERVAL_END	= 0x1,
	EI_F_INTERVAL_OPEN	= 0x2,
};

/**
 * struct elementary_interval - elementary interval [left, right]
 *
 * @rb_node:	seg_tree rb node
 * @list:	list node for linearized tree
 * @left:	left endpoint
 * @right:	right endpoint
 * @size:	interval size (right - left)
 * @flags:	flags
 * @expr:	associated expression
 */
struct elementary_interval {
	union {
		struct rb_node		rb_node;
		struct list_head	list;
	};

	mpz_t				left;
	mpz_t				right;
	mpz_t				size;

	enum elementary_interval_flags	flags;
	struct expr			*expr;
};

static void seg_tree_init(struct seg_tree *tree, const struct set *set,
			  struct expr *init, unsigned int debug_mask)
{
	struct expr *first;

	first = list_entry(init->expressions.next, struct expr, list);
	tree->root	= RB_ROOT;
	tree->keytype	= set->key->dtype;
	tree->keylen	= set->key->len;
	tree->datatype	= NULL;
	tree->datalen	= 0;
	if (set->data) {
		tree->datatype	= set->data->dtype;
		tree->datalen	= set->data->len;
	}
	tree->byteorder	= first->byteorder;
	tree->debug_mask = debug_mask;
}

static struct elementary_interval *ei_alloc(const mpz_t left, const mpz_t right,
					    struct expr *expr,
					    enum elementary_interval_flags flags)
{
	struct elementary_interval *ei;

	ei = xzalloc(sizeof(*ei));
	mpz_init_set(ei->left, left);
	mpz_init_set(ei->right, right);
	mpz_init(ei->size);
	mpz_sub(ei->size, right, left);
	if (expr != NULL)
		ei->expr = expr_get(expr);
	ei->flags = flags;
	return ei;
}

static void ei_destroy(struct elementary_interval *ei)
{
	mpz_clear(ei->left);
	mpz_clear(ei->right);
	mpz_clear(ei->size);
	if (ei->expr != NULL)
		expr_free(ei->expr);
	xfree(ei);
}

/**
 * ei_lookup - find elementary interval containing point p
 *
 * @tree:	segment tree
 * @p:		the point
 */
static struct elementary_interval *ei_lookup(struct seg_tree *tree, const mpz_t p)
{
	struct rb_node *n = tree->root.rb_node;
	struct elementary_interval *ei;

	while (n != NULL) {
		ei = rb_entry(n, struct elementary_interval, rb_node);

		if (mpz_cmp(p, ei->left) >= 0 &&
		    mpz_cmp(p, ei->right) <= 0)
			return ei;
		else if (mpz_cmp(p, ei->left) <= 0)
			n = n->rb_left;
		else if (mpz_cmp(p, ei->right) > 0)
			n = n->rb_right;
	}
	return NULL;
}

static void ei_remove(struct seg_tree *tree, struct elementary_interval *ei)
{
	rb_erase(&ei->rb_node, &tree->root);
}

static void __ei_insert(struct seg_tree *tree, struct elementary_interval *new)
{
	struct rb_node **p = &tree->root.rb_node;
	struct rb_node *parent = NULL;
	struct elementary_interval *ei;

	while (*p != NULL) {
		parent = *p;
		ei = rb_entry(parent, struct elementary_interval, rb_node);

		if (mpz_cmp(new->left, ei->left) >= 0 &&
		    mpz_cmp(new->left, ei->right) <= 0)
			break;
		else if (mpz_cmp(new->left, ei->left) <= 0)
			p = &(*p)->rb_left;
		else if (mpz_cmp(new->left, ei->left) > 0)
			p = &(*p)->rb_right;
	}

	rb_link_node(&new->rb_node, parent, p);
	rb_insert_color(&new->rb_node, &tree->root);
}

static bool segtree_debug(unsigned int debug_mask)
{
	if (debug_mask & NFT_DEBUG_SEGTREE)
		return true;

	return false;
}

/**
 * ei_insert - insert an elementary interval into the tree
 *
 * @tree:	the seg_tree
 * @new:	the elementary interval
 *
 * New entries take precedence over existing ones. Insertions are assumed to
 * be ordered by descending interval size, meaning the new interval never
 * extends over more than two existing intervals.
 */
static int ei_insert(struct list_head *msgs, struct seg_tree *tree,
		     struct elementary_interval *new, bool merge)
{
	struct elementary_interval *lei, *rei, *ei;
	struct expr *new_expr, *expr;
	mpz_t p;

	mpz_init2(p, tree->keylen);

	/*
	 * Lookup the intervals containing the left and right endpoints.
	 */
	lei = ei_lookup(tree, new->left);
	rei = ei_lookup(tree, new->right);

	if (segtree_debug(tree->debug_mask))
		pr_gmp_debug("insert: [%Zx %Zx]\n", new->left, new->right);

	if (lei != NULL && rei != NULL && lei == rei) {
		if (!merge) {
			ei = lei;
			goto err;
		}
		/* single element contained in an existing interval */
		if (mpz_cmp(new->left, new->right) == 0) {
			ei_destroy(new);
			goto out;
		}

		/*
		 * The new interval is entirely contained in the same interval,
		 * split it into two parts:
		 *
		 * [lei_left, new_left) and (new_right, rei_right]
		 */
		if (segtree_debug(tree->debug_mask))
			pr_gmp_debug("split [%Zx %Zx]\n", lei->left, lei->right);

		ei_remove(tree, lei);

		mpz_sub_ui(p, new->left, 1);
		if (mpz_cmp(lei->left, p) <= 0)
			__ei_insert(tree, ei_alloc(lei->left, p, lei->expr, 0));

		mpz_add_ui(p, new->right, 1);
		if (mpz_cmp(p, rei->right) < 0)
			__ei_insert(tree, ei_alloc(p, rei->right, lei->expr, 0));
		ei_destroy(lei);
	} else {
		if (lei != NULL) {
			if (!merge) {
				ei = lei;
				goto err;
			}
			/*
			 * Left endpoint is within lei, adjust it so we have:
			 *
			 * [lei_left, new_left)[new_left, new_right]
			 */
			if (segtree_debug(tree->debug_mask)) {
				pr_gmp_debug("adjust left [%Zx %Zx]\n",
					     lei->left, lei->right);
			}

			mpz_sub_ui(lei->right, new->left, 1);
			mpz_sub(lei->size, lei->right, lei->left);
			if (mpz_sgn(lei->size) < 0) {
				ei_remove(tree, lei);
				ei_destroy(lei);
			}
		}
		if (rei != NULL) {
			if (!merge) {
				ei = rei;
				goto err;
			}
			/*
			 * Right endpoint is within rei, adjust it so we have:
			 *
			 * [new_left, new_right](new_right, rei_right]
			 */
			if (segtree_debug(tree->debug_mask)) {
				pr_gmp_debug("adjust right [%Zx %Zx]\n",
					     rei->left, rei->right);
			}

			mpz_add_ui(rei->left, new->right, 1);
			mpz_sub(rei->size, rei->right, rei->left);
			if (mpz_sgn(rei->size) < 0) {
				ei_remove(tree, rei);
				ei_destroy(rei);
			}
		}
	}

	__ei_insert(tree, new);
out:
	mpz_clear(p);

	return 0;
err:
	mpz_clear(p);
	errno = EEXIST;
	if (new->expr->etype == EXPR_MAPPING) {
		new_expr = new->expr->left;
		expr = ei->expr->left;
	} else {
		new_expr = new->expr;
		expr = ei->expr;
	}

	return expr_binary_error(msgs, new_expr, expr,
				 "conflicting intervals specified");
}

/*
 * Sort intervals according to their priority, which is defined inversely to
 * their size.
 *
 * The beginning of the interval is used as secondary sorting criterion. This
 * makes sure that overlapping ranges with equal priority are next to each
 * other, allowing to easily detect unsolvable conflicts during insertion.
 *
 * Note: unsolvable conflicts can only occur when using ranges or two identical
 * prefix specifications.
 */
static int interval_cmp(const void *p1, const void *p2)
{
	const struct elementary_interval *e1 = *(void * const *)p1;
	const struct elementary_interval *e2 = *(void * const *)p2;
	mpz_t d;
	int ret;

	mpz_init(d);

	mpz_sub(d, e2->size, e1->size);
	if (mpz_cmp_ui(d, 0))
		ret = mpz_sgn(d);
	else
		ret = mpz_cmp(e1->left, e2->left);

	mpz_clear(d);
	return ret;
}

static unsigned int expr_to_intervals(const struct expr *set,
				      unsigned int keylen,
				      struct elementary_interval **intervals)
{
	struct elementary_interval *ei;
	struct expr *i, *next;
	unsigned int n;
	mpz_t low, high;

	mpz_init2(low, keylen);
	mpz_init2(high, keylen);

	/*
	 * Convert elements to intervals.
	 */
	n = 0;
	list_for_each_entry_safe(i, next, &set->expressions, list) {
		range_expr_value_low(low, i);
		range_expr_value_high(high, i);
		ei = ei_alloc(low, high, i, 0);
		intervals[n++] = ei;
	}
	mpz_clear(high);
	mpz_clear(low);

	return n;
}

static bool intervals_match(const struct elementary_interval *e1,
			    const struct elementary_interval *e2)
{
	return mpz_cmp(e1->left, e2->left) == 0 &&
	       mpz_cmp(e1->right, e2->right) == 0;
}

/* This function checks for overlaps in two ways:
 *
 * 1) A new interval end intersects an existing interval.
 * 2) New intervals that are larger than existing ones, that don't intersect
 *    at all, but that wrap the existing ones.
 */
static bool interval_overlap(const struct elementary_interval *e1,
			     const struct elementary_interval *e2)
{
	if (intervals_match(e1, e2))
		return false;

	return (mpz_cmp(e1->left, e2->left) >= 0 &&
	        mpz_cmp(e1->left, e2->right) <= 0) ||
	       (mpz_cmp(e1->right, e2->left) >= 0 &&
	        mpz_cmp(e1->right, e2->right) <= 0) ||
	       (mpz_cmp(e1->left, e2->left) <= 0 &&
		mpz_cmp(e1->right, e2->right) >= 0);
}

static int set_overlap(struct list_head *msgs, const struct set *set,
		       struct expr *init, unsigned int keylen, bool add)
{
	struct elementary_interval *new_intervals[init->size + 1];
	struct elementary_interval *intervals[set->init->size + 1];
	unsigned int n, m, i, j;
	int ret = 0;

	n = expr_to_intervals(init, keylen, new_intervals);
	m = expr_to_intervals(set->init, keylen, intervals);

	for (i = 0; i < n; i++) {
		bool found = false;

		for (j = 0; j < m; j++) {
			if (add && interval_overlap(new_intervals[i],
						    intervals[j])) {
				expr_error(msgs, new_intervals[i]->expr,
					   "interval overlaps with an existing one");
				errno = EEXIST;
				ret = -1;
				goto out;
			} else if (!add && intervals_match(new_intervals[i],
							   intervals[j])) {
				found = true;
				break;
			}
		}
		if (!add && !found) {
			expr_error(msgs, new_intervals[i]->expr,
				   "interval not found in set");
			errno = ENOENT;
			ret = -1;
			break;
		}
	}
out:
	for (i = 0; i < n; i++)
		ei_destroy(new_intervals[i]);
	for (i = 0; i < m; i++)
		ei_destroy(intervals[i]);

	return ret;
}

static int set_to_segtree(struct list_head *msgs, struct set *set,
			  struct expr *init, struct seg_tree *tree,
			  bool add, bool merge)
{
	struct elementary_interval **intervals;
	struct expr *i, *next;
	unsigned int n, m;
	int err = 0;

	/* We are updating an existing set with new elements, check if the new
	 * interval overlaps with any of the existing ones.
	 */
	if (set->init && set->init != init) {
		err = set_overlap(msgs, set, init, tree->keylen, add);
		if (err < 0)
			return err;
	}

	intervals = xmalloc_array(init->size, sizeof(intervals[0]));
	n = expr_to_intervals(init, tree->keylen, intervals);

	list_for_each_entry_safe(i, next, &init->expressions, list) {
		list_del(&i->list);
		expr_free(i);
	}

	/*
	 * Sort intervals by priority.
	 */
	qsort(intervals, n, sizeof(intervals[0]), interval_cmp);

	/*
	 * Insert elements into tree
	 */
	for (n = 0; n < init->size; n++) {
		err = ei_insert(msgs, tree, intervals[n], merge);
		if (err < 0) {
			struct elementary_interval *ei;
			struct rb_node *node, *next;

			for (m = n; m < init->size; m++)
				ei_destroy(intervals[m]);

			rb_for_each_entry_safe(ei, node, next, &tree->root, rb_node) {
				ei_remove(tree, ei);
				ei_destroy(ei);
			}
			break;
		}
	}

	xfree(intervals);
	return err;
}

static bool segtree_needs_first_segment(const struct set *set,
					const struct expr *init, bool add)
{
	if (add && !set->root) {
		/* Add the first segment in four situations:
		 *
		 * 1) This is an anonymous set.
		 * 2) This set exists and it is empty.
		 * 3) New empty set and, separately, new elements are added.
		 * 4) This set is created with a number of initial elements.
		 */
		if ((set_is_anonymous(set->flags)) ||
		    (set->init && set->init->size == 0) ||
		    (set->init == NULL && init) ||
		    (set->init == init)) {
			return true;
		}
	}
	/* This is an update for a set that already contains elements, so don't
	 * add the first non-matching elements otherwise we hit EEXIST.
	 */
	return false;
}

static void segtree_linearize(struct list_head *list, const struct set *set,
			      const struct expr *init, struct seg_tree *tree,
			      bool add, bool merge)
{
	bool needs_first_segment = segtree_needs_first_segment(set, init, add);
	struct elementary_interval *ei, *nei, *prev = NULL;
	struct rb_node *node, *next;
	mpz_t p, q;

	mpz_init2(p, tree->keylen);
	mpz_init2(q, tree->keylen);

	/*
	 * Convert the tree of open intervals to half-closed map expressions.
	 */
	rb_for_each_entry_safe(ei, node, next, &tree->root, rb_node) {
		if (segtree_debug(tree->debug_mask))
			pr_gmp_debug("iter: [%Zx %Zx]\n", ei->left, ei->right);

		if (prev == NULL) {
			/*
			 * If the first segment doesn't begin at zero, insert a
			 * non-matching segment to cover [0, first_left).
			 */
			if (needs_first_segment && mpz_cmp_ui(ei->left, 0)) {
				mpz_set_ui(p, 0);
				mpz_sub_ui(q, ei->left, 1);
				nei = ei_alloc(p, q, NULL, EI_F_INTERVAL_END);
				list_add_tail(&nei->list, list);
			}
		} else {
			/*
			 * If the previous segment doesn't end directly left to
			 * this one, insert a non-matching segment to cover
			 * (prev_right, ei_left).
			 */
			mpz_add_ui(p, prev->right, 1);
			if (mpz_cmp(p, ei->left) < 0 ||
			    (!set_is_anonymous(set->flags) && !merge)) {
				mpz_sub_ui(q, ei->left, 1);
				nei = ei_alloc(p, q, NULL, EI_F_INTERVAL_END);
				list_add_tail(&nei->list, list);
			} else if (add && merge &&
			           ei->expr->etype != EXPR_MAPPING) {
				/* Merge contiguous segments only in case of
				 * new additions.
				 */
				mpz_set(prev->right, ei->right);
				ei_remove(tree, ei);
				ei_destroy(ei);
				continue;
			}
		}

		ei_remove(tree, ei);
		list_add_tail(&ei->list, list);

		prev = ei;
	}

	/*
	 * If the last segment doesn't end at the right side of the dimension,
	 * insert a non-matching segment to cover (last_right, end].
	 */
	if (mpz_scan0(prev->right, 0) != tree->keylen) {
		mpz_add_ui(p, prev->right, 1);
		mpz_bitmask(q, tree->keylen);
		nei = ei_alloc(p, q, NULL, EI_F_INTERVAL_END);
		list_add_tail(&nei->list, list);
	} else {
		prev->flags |= EI_F_INTERVAL_OPEN;
	}

	mpz_clear(p);
	mpz_clear(q);
}

static void interval_expr_copy(struct expr *dst, struct expr *src)
{
	if (src->comment)
		dst->comment = xstrdup(src->comment);
	if (src->timeout)
		dst->timeout = src->timeout;
	if (src->expiration)
		dst->expiration = src->expiration;

	list_splice_init(&src->stmt_list, &dst->stmt_list);
}

static void set_insert_interval(struct expr *set, struct seg_tree *tree,
				const struct elementary_interval *ei)
{
	struct expr *expr;

	expr = constant_expr_alloc(&internal_location, tree->keytype,
				   tree->byteorder, tree->keylen, NULL);
	mpz_set(expr->value, ei->left);
	expr = set_elem_expr_alloc(&internal_location, expr);

	if (ei->expr != NULL) {
		if (ei->expr->etype == EXPR_MAPPING) {
			interval_expr_copy(expr, ei->expr->left);
			expr = mapping_expr_alloc(&ei->expr->location, expr,
						  expr_get(ei->expr->right));
		} else {
			interval_expr_copy(expr, ei->expr);
		}
	}

	if (ei->flags & EI_F_INTERVAL_END)
		expr->flags |= EXPR_F_INTERVAL_END;
	if (ei->flags & EI_F_INTERVAL_OPEN)
		expr->elem_flags |= NFTNL_SET_ELEM_F_INTERVAL_OPEN;

	compound_expr_add(set, expr);
}

int set_to_intervals(struct list_head *errs, struct set *set,
		     struct expr *init, bool add, unsigned int debug_mask,
		     bool merge, struct output_ctx *octx)
{
	struct expr *catchall = NULL, *i, *in, *key;
	struct elementary_interval *ei, *next;
	struct seg_tree tree;
	LIST_HEAD(list);

	list_for_each_entry_safe(i, in, &init->expressions, list) {
		if (i->etype == EXPR_MAPPING)
			key = i->left->key;
		else if (i->etype == EXPR_SET_ELEM)
			key = i->key;
		else
			continue;

		if (key->etype == EXPR_SET_ELEM_CATCHALL) {
			init->size--;
			catchall = i;
			list_del(&i->list);
			break;
		}
	}

	seg_tree_init(&tree, set, init, debug_mask);
	if (set_to_segtree(errs, set, init, &tree, add, merge) < 0)
		return -1;
	segtree_linearize(&list, set, init, &tree, add, merge);

	init->size = 0;
	list_for_each_entry_safe(ei, next, &list, list) {
		if (segtree_debug(tree.debug_mask)) {
			pr_gmp_debug("list: [%.*Zx %.*Zx]\n",
				     2 * tree.keylen / BITS_PER_BYTE, ei->left,
				     2 * tree.keylen / BITS_PER_BYTE, ei->right);
		}
		set_insert_interval(init, &tree, ei);
		ei_destroy(ei);
	}

	if (segtree_debug(tree.debug_mask)) {
		expr_print(init, octx);
		pr_gmp_debug("\n");
	}

	if (catchall) {
		list_add_tail(&catchall->list, &init->expressions);
		init->size++;
	}

	return 0;
}

static void set_elem_add(const struct set *set, struct expr *init, mpz_t value,
			 uint32_t flags, enum byteorder byteorder)
{
	struct expr *expr;

	expr = constant_expr_alloc(&internal_location, set->key->dtype,
				   byteorder, set->key->len, NULL);
	mpz_set(expr->value, value);
	expr = set_elem_expr_alloc(&internal_location, expr);
	expr->flags = flags;

	compound_expr_add(init, expr);
}

struct expr *get_set_intervals(const struct set *set, const struct expr *init)
{
	struct expr *new_init;
	mpz_t low, high;
	struct expr *i;

	mpz_init2(low, set->key->len);
	mpz_init2(high, set->key->len);

	new_init = list_expr_alloc(&internal_location);

	list_for_each_entry(i, &init->expressions, list) {
		switch (i->key->etype) {
		case EXPR_VALUE:
			set_elem_add(set, new_init, i->key->value,
				     i->flags, i->byteorder);
			break;
		case EXPR_CONCAT:
			compound_expr_add(new_init, expr_clone(i));
			i->flags |= EXPR_F_INTERVAL_END;
			compound_expr_add(new_init, expr_clone(i));
			break;
		case EXPR_SET_ELEM_CATCHALL:
			compound_expr_add(new_init, expr_clone(i));
			break;
		default:
			range_expr_value_low(low, i);
			set_elem_add(set, new_init, low, 0, i->byteorder);
			range_expr_value_high(high, i);
			mpz_add_ui(high, high, 1);
			set_elem_add(set, new_init, high,
				     EXPR_F_INTERVAL_END, i->byteorder);
			break;
		}
	}

	mpz_clear(low);
	mpz_clear(high);

	return new_init;
}

static struct expr *get_set_interval_find(const struct set *cache_set,
					  struct expr *left,
					  struct expr *right)
{
	const struct set *set = cache_set;
	struct expr *range = NULL;
	struct expr *i;
	mpz_t val;

	mpz_init2(val, set->key->len);

	list_for_each_entry(i, &set->init->expressions, list) {
		switch (i->key->etype) {
		case EXPR_PREFIX:
		case EXPR_RANGE:
			range_expr_value_low(val, i);
			if (left && mpz_cmp(left->key->value, val))
				break;

			range_expr_value_high(val, i);
			if (right && mpz_cmp(right->key->value, val))
				break;

			range = expr_clone(i->key);
			goto out;
		default:
			break;
		}
	}
out:
	mpz_clear(val);

	return range;
}

int get_set_decompose(struct set *cache_set, struct set *set)
{
	struct expr *i, *next, *range;
	struct expr *left = NULL;
	struct expr *new_init;

	new_init = set_expr_alloc(&internal_location, set);

	list_for_each_entry_safe(i, next, &set->init->expressions, list) {
		if (i->flags & EXPR_F_INTERVAL_END && left) {
			list_del(&left->list);
			list_del(&i->list);
			mpz_sub_ui(i->key->value, i->key->value, 1);
			range = get_set_interval_find(cache_set, left, i);
			if (!range) {
				expr_free(left);
				expr_free(i);
				expr_free(new_init);
				errno = ENOENT;
				return -1;
			}
			expr_free(left);
			expr_free(i);

			compound_expr_add(new_init, range);
			left = NULL;
		} else {
			if (left) {
				range = get_set_interval_find(cache_set,
							      left, NULL);
				if (range)
					compound_expr_add(new_init, range);
				else
					compound_expr_add(new_init,
							  expr_clone(left));
			}
			left = i;
		}
	}
	if (left) {
		range = get_set_interval_find(cache_set, left, NULL);
		if (range)
			compound_expr_add(new_init, range);
		else
			compound_expr_add(new_init, expr_clone(left));
	}

	expr_free(set->init);
	set->init = new_init;

	return 0;
}

static bool range_is_prefix(const mpz_t range)
{
	mpz_t tmp;
	bool ret;

	mpz_init_set(tmp, range);
	mpz_add_ui(tmp, tmp, 1);
	mpz_and(tmp, range, tmp);
	ret = !mpz_cmp_ui(tmp, 0);
	mpz_clear(tmp);
	return ret;
}

static struct expr *expr_value(struct expr *expr)
{
	switch (expr->etype) {
	case EXPR_MAPPING:
		return expr->left->key;
	case EXPR_SET_ELEM:
		return expr->key;
	default:
		BUG("invalid expression type %s\n", expr_name(expr));
	}
}

static int expr_value_cmp(const void *p1, const void *p2)
{
	struct expr *e1 = *(void * const *)p1;
	struct expr *e2 = *(void * const *)p2;
	int ret;

	if (expr_value(e1)->etype == EXPR_CONCAT)
		return -1;

	ret = mpz_cmp(expr_value(e1)->value, expr_value(e2)->value);
	if (ret == 0) {
		if (e1->flags & EXPR_F_INTERVAL_END)
			return -1;
		else if (e2->flags & EXPR_F_INTERVAL_END)
			return 1;
	}

	return ret;
}

/* Given start and end elements of a range, check if it can be represented as
 * a single netmask, and if so, how long, by returning zero or a positive value.
 */
static int range_mask_len(const mpz_t start, const mpz_t end, unsigned int len)
{
	mpz_t tmp_start, tmp_end;
	int ret;

	mpz_init_set(tmp_start, start);
	mpz_init_set(tmp_end, end);

	while (mpz_cmp(tmp_start, tmp_end) <= 0 &&
		!mpz_tstbit(tmp_start, 0) && mpz_tstbit(tmp_end, 0) &&
		len--) {
		mpz_fdiv_q_2exp(tmp_start, tmp_start, 1);
		mpz_fdiv_q_2exp(tmp_end, tmp_end, 1);
	}

	ret = !mpz_cmp(tmp_start, tmp_end) ? (int)len : -1;

	mpz_clear(tmp_start);
	mpz_clear(tmp_end);

	return ret;
}

/* Given a set with two elements (start and end), transform them into a
 * concatenation of ranges. That is, from a list of start expressions and a list
 * of end expressions, form a list of start - end expressions.
 */
void concat_range_aggregate(struct expr *set)
{
	struct expr *i, *start = NULL, *end, *r1, *r2, *next, *r1_next, *tmp;
	struct list_head *r2_next;
	int prefix_len, free_r1;
	mpz_t range, p;

	list_for_each_entry_safe(i, next, &set->expressions, list) {
		if (!start) {
			start = i;
			continue;
		}
		end = i;

		/* Walk over r1 (start expression) and r2 (end) in parallel,
		 * form ranges between corresponding r1 and r2 expressions,
		 * store them by replacing r2 expressions, and free r1
		 * expressions.
		 */
		r2 = list_first_entry(&expr_value(end)->expressions,
				      struct expr, list);
		list_for_each_entry_safe(r1, r1_next,
					 &expr_value(start)->expressions,
					 list) {
			mpz_init(range);
			mpz_init(p);

			r2_next = r2->list.next;
			free_r1 = 0;

			if (!mpz_cmp(r1->value, r2->value)) {
				free_r1 = 1;
				goto next;
			}

			mpz_sub(range, r2->value, r1->value);
			mpz_sub_ui(range, range, 1);
			mpz_and(p, r1->value, range);

			/* Check if we are forced, or if it's anyway preferable,
			 * to express the range as two points instead of a
			 * netmask.
			 */
			prefix_len = range_mask_len(r1->value, r2->value,
						    r1->len);
			if (prefix_len < 0 ||
			    !(r1->dtype->flags & DTYPE_F_PREFIX)) {
				tmp = range_expr_alloc(&r1->location, r1,
						       r2);

				list_replace(&r2->list, &tmp->list);
				r2_next = tmp->list.next;
			} else {
				tmp = prefix_expr_alloc(&r1->location, r1,
							prefix_len);
				tmp->len = r2->len;

				list_replace(&r2->list, &tmp->list);
				r2_next = tmp->list.next;
				expr_free(r2);
			}

next:
			mpz_clear(p);
			mpz_clear(range);

			r2 = list_entry(r2_next, typeof(*r2), list);
			compound_expr_remove(start, r1);

			if (free_r1)
				expr_free(r1);
		}

		compound_expr_remove(set, start);
		expr_free(start);
		start = NULL;
	}
}

void interval_map_decompose(struct expr *set)
{
	struct expr *i, *next, *low = NULL, *end, *catchall = NULL, *key;
	struct expr **elements, **ranges;
	unsigned int n, m, size;
	mpz_t range, p;
	bool interval;

	if (set->size == 0)
		return;

	elements = xmalloc_array(set->size, sizeof(struct expr *));
	ranges = xmalloc_array(set->size * 2, sizeof(struct expr *));

	mpz_init(range);
	mpz_init(p);

	/* Sort elements */
	n = 0;
	list_for_each_entry_safe(i, next, &set->expressions, list) {
		key = NULL;
		if (i->etype == EXPR_SET_ELEM)
			key = i->key;
		else if (i->etype == EXPR_MAPPING)
			key = i->left->key;

		if (key && key->etype == EXPR_SET_ELEM_CATCHALL) {
			list_del(&i->list);
			catchall = i;
			continue;
		}
		compound_expr_remove(set, i);
		elements[n++] = i;
	}
	qsort(elements, n, sizeof(elements[0]), expr_value_cmp);
	size = n;

	/* Transform points (single values) into half-closed intervals */
	n = 0;
	interval = false;
	for (m = 0; m < size; m++) {
		i = elements[m];

		if (i->flags & EXPR_F_INTERVAL_END)
			interval = false;
		else if (interval) {
			end = expr_clone(i);
			end->flags |= EXPR_F_INTERVAL_END;
			ranges[n++] = end;
		} else
			interval = true;

		ranges[n++] = i;
	}
	size = n;

	for (n = 0; n < size; n++) {
		i = ranges[n];

		if (low == NULL) {
			if (i->flags & EXPR_F_INTERVAL_END) {
				/*
				 * End of interval mark
				 */
				expr_free(i);
				continue;
			} else {
				/*
				 * Start a new interval
				 */
				low = i;
				continue;
			}
		}

		mpz_sub(range, expr_value(i)->value, expr_value(low)->value);
		mpz_sub_ui(range, range, 1);

		mpz_and(p, expr_value(low)->value, range);

		if (!mpz_cmp_ui(range, 0))
			compound_expr_add(set, expr_get(low));
		else if ((!range_is_prefix(range) ||
			  !(i->dtype->flags & DTYPE_F_PREFIX)) ||
			 mpz_cmp_ui(p, 0)) {
			struct expr *tmp;

			tmp = constant_expr_alloc(&low->location, low->dtype,
						  low->byteorder, expr_value(low)->len,
						  NULL);

			mpz_add(range, range, expr_value(low)->value);
			mpz_set(tmp->value, range);

			tmp = range_expr_alloc(&low->location,
					       expr_clone(expr_value(low)),
					       tmp);
			tmp = set_elem_expr_alloc(&low->location, tmp);

			if (low->etype == EXPR_MAPPING) {
				interval_expr_copy(tmp, low->left);

				tmp = mapping_expr_alloc(&tmp->location, tmp,
							 expr_clone(low->right));
			} else {
				interval_expr_copy(tmp, low);
			}

			compound_expr_add(set, tmp);
		} else {
			struct expr *prefix;
			unsigned int prefix_len;

			prefix_len = expr_value(i)->len - mpz_scan0(range, 0);
			prefix = prefix_expr_alloc(&low->location,
						   expr_clone(expr_value(low)),
						   prefix_len);
			prefix->len = expr_value(i)->len;

			prefix = set_elem_expr_alloc(&low->location, prefix);

			if (low->etype == EXPR_MAPPING) {
				interval_expr_copy(prefix, low->left);

				prefix = mapping_expr_alloc(&low->location, prefix,
							    expr_clone(low->right));
			} else {
				interval_expr_copy(prefix, low);
			}

			compound_expr_add(set, prefix);
		}

		if (i->flags & EXPR_F_INTERVAL_END) {
			expr_free(low);
			low = NULL;
		}
		expr_free(i);
	}

	if (!low) /* no unclosed interval at end */
		goto out;

	i = constant_expr_alloc(&low->location, low->dtype,
				low->byteorder, expr_value(low)->len, NULL);
	mpz_bitmask(i->value, i->len);

	if (!mpz_cmp(i->value, expr_value(low)->value)) {
		expr_free(i);
		i = low;
	} else {
		i = range_expr_alloc(&low->location,
				     expr_clone(expr_value(low)), i);
		i = set_elem_expr_alloc(&low->location, i);
		if (low->etype == EXPR_MAPPING) {
			i = mapping_expr_alloc(&i->location, i,
					       expr_clone(low->right));
			interval_expr_copy(i->left, low->left);
		} else {
			interval_expr_copy(i, low);
		}
		expr_free(low);
	}

	compound_expr_add(set, i);
out:
	if (catchall)
		compound_expr_add(set, catchall);

	mpz_clear(range);
	mpz_clear(p);

	xfree(ranges);
	xfree(elements);
}
