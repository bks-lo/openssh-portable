#ifndef __CMD_SCP_H__
#define __CMD_SCP_H__

#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"

int cmd_scp_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);
int cmd_scp_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

#endif