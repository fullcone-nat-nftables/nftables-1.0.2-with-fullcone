#ifndef _NFT_CMD_H_
#define _NFT_CMD_H_

void nft_cmd_error(struct netlink_ctx *ctx, struct cmd *cmd,
		   struct mnl_err *err);

#endif
