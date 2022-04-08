#ifndef NFTABLES_PARSER_H
#define NFTABLES_PARSER_H

#include <list.h>
#include <rule.h> // FIXME
#include <nftables.h>

#define TABSIZE				8

#define YYLTYPE				struct location
#define YYLTYPE_IS_TRIVIAL		0
#define YYENABLE_NLS			0

#define SCOPE_NEST_MAX			4

struct parser_state {
	struct input_descriptor		*indesc;
	struct list_head		indesc_list;

	struct list_head		*msgs;
	unsigned int			nerrs;

	struct scope			*scopes[SCOPE_NEST_MAX];
	unsigned int			scope;

	unsigned int			flex_state_pop;
	unsigned int			startcond_type;
	struct list_head		*cmds;
};

enum startcond_type {
	PARSER_SC_BEGIN,
	PARSER_SC_ARP,
	PARSER_SC_CT,
	PARSER_SC_COUNTER,
	PARSER_SC_ETH,
	PARSER_SC_IP,
	PARSER_SC_IP6,
	PARSER_SC_LIMIT,
	PARSER_SC_QUOTA,
	PARSER_SC_SCTP,
	PARSER_SC_SECMARK,
	PARSER_SC_TCP,
	PARSER_SC_VLAN,
	PARSER_SC_CMD_LIST,
	PARSER_SC_EXPR_FIB,
	PARSER_SC_EXPR_HASH,
	PARSER_SC_EXPR_IPSEC,
	PARSER_SC_EXPR_NUMGEN,
	PARSER_SC_EXPR_QUEUE,
	PARSER_SC_EXPR_RT,
	PARSER_SC_EXPR_SCTP_CHUNK,
	PARSER_SC_EXPR_SOCKET,

	PARSER_SC_STMT_LOG,
};

struct mnl_socket;

extern void parser_init(struct nft_ctx *nft, struct parser_state *state,
			struct list_head *msgs, struct list_head *cmds,
			struct scope *top_scope);
extern int nft_parse(struct nft_ctx *ctx, void *, struct parser_state *state);

extern void *scanner_init(struct parser_state *state);
extern void scanner_destroy(struct nft_ctx *nft);

extern int scanner_read_file(struct nft_ctx *nft, const char *filename,
			     const struct location *loc);
extern int scanner_include_file(struct nft_ctx *ctx, void *scanner,
				const char *filename,
				const struct location *loc);
extern void scanner_push_buffer(void *scanner,
				const struct input_descriptor *indesc,
				const char *buffer);

extern void scanner_pop_start_cond(void *scanner, enum startcond_type sc);

#endif /* NFTABLES_PARSER_H */
