#ifndef __CMD_SCP_H__
#define __CMD_SCP_H__

#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"

typedef struct proxy_scp_st proxy_scp_st;
proxy_scp_st *proxy_scp_pd_create();
void proxy_scp_pd_destroy(void *private_data);

int cmd_scp_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);
int cmd_scp_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

#endif