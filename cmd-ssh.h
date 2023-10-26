#ifndef __CMD_SSH_H__
#define __CMD_SSH_H__

int cmd_ssh_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

int cmd_ssh_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

#endif