#ifndef __CMD_SSH_H__
#define __CMD_SSH_H__

#include <stdbool.h>
#include "sshbuf.h"

typedef struct proxy_ssh_st proxy_ssh_st;
proxy_ssh_st *proxy_ssh_pd_create();
void proxy_ssh_pd_destroy(void *private_data);

int proxy_ssh_vc_resize(Channel *c, unsigned int cols, unsigned int lines);

int cmd_ssh_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

int cmd_ssh_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

#endif