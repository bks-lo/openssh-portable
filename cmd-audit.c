#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include "cmd-audit.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-sftp.h"
#include "cmd-ssh.h"

int cmd_audit_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    proxy_info_st *pinfo = &(c->proxy_info);
    switch (pinfo->pt) {
    case PT_SFTP:
        cmd_sftp_wfd_handle(ssh, c, buf, len);
        break;
    case PT_SSH:
        cmd_ssh_wfd_handle(ssh, c, buf, len);
        break;
    default:
        break;
    }

    return 0;
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

int proxy_info_get(char *sid, proxy_info_st *pinfo)
{
    snprintf(pinfo->sid, sizeof(pinfo->sid), "%s", sid);

    //todo: get proxy info from db by sid
    debug_p("sid = %s", sid);
#ifndef PROXY_185
    if (strcasecmp(sid, "ssh") == 0) {
        pinfo->pt = PT_SSH;
        pinfo->port = strtoul("6022", NULL, 10);
        snprintf(pinfo->protocol_type, sizeof(pinfo->protocol_type), "%s", "ssh");
        snprintf(pinfo->hostname, sizeof(pinfo->hostname), "%s", "192.168.45.185");
        snprintf(pinfo->username, sizeof(pinfo->username), "%s", "root");
        snprintf(pinfo->password, sizeof(pinfo->password), "%s", "Abmin@1234@Mmtsl");
    } else if (strcasecmp(sid, "sftp") == 0) {
        pinfo->pt = PT_SFTP;
        pinfo->port = strtoul("6022", NULL, 10);
        snprintf(pinfo->protocol_type, sizeof(pinfo->protocol_type), "%s", "sftp");
        snprintf(pinfo->hostname, sizeof(pinfo->hostname), "%s", "192.168.45.185");
        snprintf(pinfo->username, sizeof(pinfo->username), "%s", "root");
        snprintf(pinfo->password, sizeof(pinfo->password), "%s", "Abmin@1234@Mmtsl");
    } else if (strcasecmp(sid, "scp") == 0) {
        pinfo->pt = PT_SCP;
        pinfo->port = strtoul("6022", NULL, 10);
        snprintf(pinfo->protocol_type, sizeof(pinfo->protocol_type), "%s", "scp");
        snprintf(pinfo->hostname, sizeof(pinfo->hostname), "%s", "192.168.45.185");
        snprintf(pinfo->username, sizeof(pinfo->username), "%s", "root");
        snprintf(pinfo->password, sizeof(pinfo->password), "%s", "Abmin@1234@Mmtsl");
    }
#else
    if (strcasecmp(sid, "ssh") == 0) {
        pinfo->pt = PT_SSH;
        pinfo->port = strtoul("22", NULL, 10);
        snprintf(pinfo->protocol_type, sizeof(pinfo->protocol_type), "%s", "ssh");
        snprintf(pinfo->hostname, sizeof(pinfo->hostname), "%s", "124.222.69.155");
        snprintf(pinfo->username, sizeof(pinfo->username), "%s", "root");
        snprintf(pinfo->password, sizeof(pinfo->password), "%s", "Dajiahao1230@s");
    } else if (strcasecmp(sid, "sftp") == 0) {
        pinfo->pt = PT_SFTP;
        pinfo->port = strtoul("22", NULL, 10);
        snprintf(pinfo->protocol_type, sizeof(pinfo->protocol_type), "%s", "sftp");
        snprintf(pinfo->hostname, sizeof(pinfo->hostname), "%s", "124.222.69.155");
        snprintf(pinfo->username, sizeof(pinfo->username), "%s", "root");
        snprintf(pinfo->password, sizeof(pinfo->password), "%s", "Dajiahao1230@s");
    } else if (strcasecmp(sid, "scp") == 0) {
        pinfo->pt = PT_SCP;
        pinfo->port = strtoul("22", NULL, 10);
        snprintf(pinfo->protocol_type, sizeof(pinfo->protocol_type), "%s", "scp");
        snprintf(pinfo->hostname, sizeof(pinfo->hostname), "%s", "124.222.69.155");
        snprintf(pinfo->username, sizeof(pinfo->username), "%s", "root");
        snprintf(pinfo->password, sizeof(pinfo->password), "%s", "Dajiahao1230@s");
    }
#endif
    else if (strcasecmp(sid, "ftp") == 0) {
        pinfo->pt = PT_FTP;
        pinfo->port = strtoul("21", NULL, 10);
        snprintf(pinfo->protocol_type, sizeof(pinfo->protocol_type), "%s", "ftp");
        snprintf(pinfo->hostname, sizeof(pinfo->hostname), "%s", "192.168.45.24");
        snprintf(pinfo->username, sizeof(pinfo->username), "%s", "root");
        snprintf(pinfo->password, sizeof(pinfo->password), "%s", "root");
    } else if (strcasecmp(sid, "rlogin") == 0) {
        pinfo->pt = PT_RLOGIN;
        pinfo->port = strtoul("513", NULL, 10);
        snprintf(pinfo->protocol_type, sizeof(pinfo->protocol_type), "%s", "rlogin");
        snprintf(pinfo->hostname, sizeof(pinfo->hostname), "%s", "192.168.45.185");
        snprintf(pinfo->username, sizeof(pinfo->username), "%s", "test");
        snprintf(pinfo->password, sizeof(pinfo->password), "%s", "test1");
    } else if (strcasecmp(sid, "telnet") == 0) {
        pinfo->pt = PT_TELNET;
        pinfo->port = strtoul("23", NULL, 10);
        snprintf(pinfo->protocol_type, sizeof(pinfo->protocol_type), "%s", "telnet");
        snprintf(pinfo->hostname, sizeof(pinfo->hostname), "%s", "192.168.45.185");
        snprintf(pinfo->username, sizeof(pinfo->username), "%s", "test");
        snprintf(pinfo->password, sizeof(pinfo->password), "%s", "test");
    }


    return 0;
}

#define SSH_PROXY_CMD	    "/home/xiaoke/dbproxy/openssh-portable/ssh %s@%s -p %d -o PreferredAuthentications=password -d %s"
#define RLOGIN_PROXY_CMD    "/usr/bin/rlogin -l %s -p %d %s"
#define TELNET_PROXY_CMD    "/usr/bin/telnet -l %s %s %d"

int proxy_cmd_get(char *cmd, int clen, proxy_info_st *pinfo, const char *command)
{
    const char *suffix = (command == NULL) ? "" : command;

    switch (pinfo->pt) {
    case PT_SSH:
        snprintf(cmd, clen, SSH_PROXY_CMD" %s", pinfo->username, pinfo->hostname, pinfo->port, pinfo->password, suffix);
        break;
    case PT_SFTP:
        snprintf(cmd, clen, SSH_PROXY_CMD" -s sftp", pinfo->username, pinfo->hostname, pinfo->port, pinfo->password);
        break;
    case PT_SCP:
        snprintf(cmd, clen, SSH_PROXY_CMD" %s", pinfo->username, pinfo->hostname, pinfo->port, pinfo->password, suffix);
        break;
    case PT_FTP:
        //snprintf(cmd, clen, "/home/xiaoke/netkit-ftp/ftp/ftp -H 192.168.45.24 -u root -s %s", pinfo->password);
        break;
    case PT_RLOGIN:
        snprintf(cmd, clen, RLOGIN_PROXY_CMD, pinfo->username, pinfo->port, pinfo->hostname);
        break;
    case PT_TELNET:
        snprintf(cmd, clen, TELNET_PROXY_CMD, pinfo->username, pinfo->hostname, pinfo->port);
        break;
    default:
        debug_p("not support proxy type %s", pinfo->protocol_type);
        return -1;
    }

    debug_p("cmd => %s", cmd);
    return 0;
}