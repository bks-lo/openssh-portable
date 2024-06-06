#ifndef _CMD_SFTP_H__
#define _CMD_SFTP_H__

#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include <stdint.h>

typedef struct proxy_sftp_st proxy_sftp_st;
proxy_sftp_st *proyx_sftp_pd_create();
void *proxy_sftp_pd_destroy(void *private_data);

int cmd_sftp_wfd_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len);

int cmd_sftp_rfd_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len);
#endif