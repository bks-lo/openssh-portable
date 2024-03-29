#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include "cmd-define.h"
#include "cmd-audit.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-sftp.h"
#include "cmd-ssh.h"

int cmd_audit_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    int ret = 0;
    proxy_info_st *pinfo = &(c->proxy_info);
    switch (pinfo->pt) {
    case PT_SFTP:
        ret = cmd_sftp_wfd_handle(ssh, c, buf, len);
        break;
    case PT_SSH:
        ret = cmd_ssh_wfd_handle(ssh, c, buf, len);
        break;
    default:
        break;
    }

    return ret;
}

int cmd_audit_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    proxy_info_st *pinfo = &(c->proxy_info);
    switch (pinfo->pt) {
    case PT_SFTP:
        cmd_sftp_rfd_handle(ssh, c, buf, len);
        break;
    case PT_SSH:
        cmd_ssh_rfd_handle(ssh, c, buf, len);
        break;
    default:
        break;
    }

    return 0;
}


int cmd_audit_efd_read_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    return cmd_audit_rfd_handle(ssh, c, buf, len);
}

int cmd_audit_efd_write_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    return 0;
}
