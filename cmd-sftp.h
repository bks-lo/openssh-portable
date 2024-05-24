#ifndef _CMD_SFTP_H__
#define _CMD_SFTP_H__

#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include <stdint.h>

int cmd_sftp_wfd_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len);

int cmd_sftp_rfd_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len);
#endif