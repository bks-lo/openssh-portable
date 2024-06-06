#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include "cmd-define.h"
#include "cmd-audit.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-sftp.h"
#include "cmd-ssh.h"
#include "cmd-scp.h"

void proxy_channel_handler_set(Channel *c)
{
    switch (c->proxy_type) {
    case PT_SSH:
    case PT_RLOGIN:
    case PT_TELNET:
        c->proxy_data = proxy_ssh_pd_create();
        c->proxy_dfunc = proxy_ssh_pd_destroy;
        break;
    case PT_SFTP:
        c->proxy_data = proxy_sftp_pd_create();
        c->proxy_dfunc = proxy_sftp_pd_destroy;
        break;
    case PT_SCP:
        c->proxy_data = proxy_scp_pd_create();
        c->proxy_dfunc = proxy_scp_pd_destroy;
    default:
        break;
    }

    return ;
}

int cmd_audit_wfd_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len)
{
    int ret = 0;
    switch (c->proxy_type) {
    case PT_SFTP:
        ret = cmd_sftp_wfd_handle(ssh, c, buf, len);
        break;
    case PT_SSH:
    case PT_RLOGIN:
    case PT_TELNET:
        ret = cmd_ssh_wfd_handle(ssh, c, buf, len);
        break;
    case PT_SCP:
        ret = cmd_scp_wfd_handle(ssh, c, buf, len);
        break;
    default:
        break;
    }

    return ret;
}

int cmd_audit_rfd_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len)
{
    switch (c->proxy_type) {
    case PT_SFTP:
        cmd_sftp_rfd_handle(ssh, c, buf, len);
        break;
    case PT_SSH:
    case PT_RLOGIN:
    case PT_TELNET:
        cmd_ssh_rfd_handle(ssh, c, buf, len);
        break;
    case PT_SCP:
        cmd_scp_rfd_handle(ssh, c, buf, len);
        break;
    default:
        break;
    }

    return 0;
}


int cmd_audit_efd_read_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len)
{
    return cmd_audit_rfd_handle(ssh, c, buf, len);
}

int cmd_audit_efd_write_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len)
{
    return 0;
}
