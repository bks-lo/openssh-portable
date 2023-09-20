#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include "cmd-audit.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-define.h"

int strcasecmp_r(const char *str1, int len1, const char *str2, int len2)
{
    int ret = 0;
    int aA = 'a' - 'A';
    int Aa = 'A' - 'a';

    debug3("str1[%d]=%s, str2[%d]=%s", len1, str1, len2, str2);

    for (; (len1--) > 0 && (len2--) > 0; ) {
        ret = str1[len1] - str2[len2];

        if (ret == aA) {
            if (str1[len1] < 'a' || str1[len1] > 'z') {
                return ret;
            }
        } else if (ret == Aa) {
            if (str1[len1] < 'A' || str1[len1] > 'Z') {
                return ret;
            }
        } else if (ret != 0) {
            return ret;
        }
    }

    if (len1 == -1 || len2 == -1) {
        return 0;
    }

    return -1;
}

static int login_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    static int need_password = 0;
    proxy_info_st *pinfo = &(c->proxy_info);

    /* rlogin telnet 只能在交互时传输密码 */
    if (need_password == 0 && (pinfo->pt == PT_RLOGIN || pinfo->pt == PT_TELNET)) {
        if (strcasecmp_r(buf, len, CONST_STR_N("password: ")) == 0) {
            need_password = 1;
            write(c->wfd, pinfo->password, strlen(pinfo->password));
            write(c->wfd, "\r", 1);
            return 0;
        }
    }

    /* 剔除字符串前面的\r\n */
    if (buf[0] == '\r' && buf[1] == '\n') {
        buf += 2;
        len -= 2;
    }

    if (strncasecmp(buf, CONST_STR_N("Last")) == 0) {
        c->proxy_state = PROXY_STATE_LOGIN_OK;
        debug3("login success");
    } else if (strncasecmp(buf, CONST_STR_N("Permission")) == 0) {
        c->proxy_state = PROXY_STATE_LOGIN_FAILED;
        debug3("login Permission");
    } else if (strncasecmp(buf, CONST_STR_N("Login incorrect")) == 0) {
        c->proxy_state = PROXY_STATE_LOGIN_FAILED;
        write(c->wfd, pinfo->username, strlen(pinfo->username));
        write(c->wfd, "\r", 1);
        debug3("Login incorrect");
    }

    return 0;
}

static int login_ok_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    snprintf(c->prompt, sizeof(c->prompt), "%s", buf);
    c->proxy_state = PROXY_STATE_CMD;
    return 0;
}

static int cmd_reset(cmd_t *pcmd)
{
    pcmd->char_state = ESnormal;
    pcmd->cmd_state  = CSnone;
    pcmd->key_state  = KSnone;
    sshbuf_reset(pcmd->cmd_buf);
    sshbuf_reset(pcmd->rsp_buf);
    return 0;
}

/* is this char_state an ANSI control string? */
static int ansi_control_string(unsigned int char_state)
{
	if (char_state == ESosc || char_state == ESapc || char_state == ESpm || char_state == ESdcs)
		return 1;
	return 0;
}

static void cmd_char_handle(cmd_t *pcmd, int ch)
{
    if (ansi_control_string(pcmd->char_state) && ch >= 8 && ch <= 13) {
        return;
    }

    switch (ch) {
    case 0:
        return;
    case 7:             /* bell键 */
        if (ansi_control_string(pcmd->char_state)) {
            pcmd->char_state = ESnormal;
        }
    case 8:             /* 普通的退格键 */
        return;
    case 9:
        return;
    case 10:
    case 13:
        debug3("cmd: %s", sshbuf_ptr(pcmd->cmd_buf));
        pcmd->cmd_state = CSrespd;
        return;
    case 11:
    case 12:
        // fallthrough;
        return;
    case 14:
        return;
    case 15:
        return;
    case 24:
    case 26:
        pcmd->char_state = ESnormal;
        return;
    case 27:
        pcmd->char_state = ESesc;
        return;
    case ';':
        return;
    case '|':
        return;
    case '&':
        return;
    case 127:
        return;
    case 128+27:
        pcmd->char_state = ESsquare;
        return;
    }

    switch (pcmd->char_state) {
    case ESesc:
        pcmd->char_state = ESnormal;

        switch (ch) {
        case '[':
            pcmd->char_state = ESsquare;
            return;
        case ']':
            pcmd->char_state = ESnonstd;
            return;
        case '_':
            pcmd->char_state = ESapc;
            return;
        case '^':
            pcmd->char_state = ESpm;
            return;
        case '%':
            pcmd->char_state = ESpercent;
            return;
        case '(':
            pcmd->char_state = ESsetG0;
            return;
        case ')':
            pcmd->char_state = ESsetG1;
            return;
        case '#':
            pcmd->char_state = EShash;
            return;
        case 'P':
            pcmd->char_state = ESdcs;
            return;
        case 'E':
        case 'M':
        case 'D':
        case 'H':
        case 'Z':
        case '7':
        case '8':
        case 'c':
        case '>':
        case '=':
            return;
        }

        return;
    case ESnonstd:
        if (ch == 'P') {
            pcmd->char_state = ESpalette;
        } else if (ch == 'R') {
            pcmd->char_state = ESnormal;
        } else if (ch >= '0' && ch <= '9') {
            pcmd->char_state = ESosc;
        } else {
            pcmd->char_state = ESnormal;
        }
        return;
    case ESpalette:
        pcmd->char_state = ESnormal;
        return;
    case ESsquare:
        pcmd->char_state = ESgetpars;
        if (ch == '[') {
            pcmd->char_state = ESfunckey;
            return;
        }

        switch (ch) {
        case '?':
			return;
        case '>':
            return;
        case '=':
            return;
        case '<':
            return;
        }
        // fallthrough;
    case ESgetpars:

        pcmd->char_state = ESnormal;
        switch (ch) {
        case 'h':
            /* code */
            return;
        case 'l':
            return;
        case 'c':
            return;
        case 'm':
            return;
        case 'n':
            return;
        }

        switch (ch) {
        case 'G':
        case '`':
            /* code */
            return;
        case 'A':
            pcmd->key_state = KSup;
            pcmd->cmd_state = CSfindrespd;
            debug3("up");
            return;
        case 'B':
        case 'e':
            debug3("down");
            return;
        case 'C':
        case 'a':
            debug3("right");
            return;
        case 'D':
            debug3("left");
            return;
        case 'E':
            return;
        case 'F':
            return;
        case 'd':
            return;
        case 'H':
        case 'f':
            return;
        case 'J':
            return;
        case 'K':
            return;
        case 'L':
            return;
        case 'M':
            return;
        case 'P':
            return;
        case 'c':
            return;
        case 'g':
            return;
        case 'm':
            return;
        case 'q':
            return;
        case 'r':
            return;
        case 's':
            return;
        case 'u':
            return;
        case 'X':
            return;
        case '@':
            return;
        case ']':
            return;
        }

        return;
    case EScsiignore:
        if (ch >= 20 && ch <= 0x3f)
			return;
		pcmd->char_state = ESnormal;
		return;
    case ESpercent:
        pcmd->char_state = ESnormal;
        switch (ch) {
        case '@':
            /* code */
            return;
        case 'G':
        case '8':
            return;
        }

        return;
    case ESfunckey:
        pcmd->char_state = ESnormal;
        return;
    case EShash:
        pcmd->char_state = ESnormal;
        if (ch == '8') {
        }
        return;
    case ESsetG0:
        pcmd->char_state = ESnormal;
        return;
    case ESsetG1:
        pcmd->char_state = ESnormal;
        return;
    case ESapc:
    case ESosc:
    case ESpm:
    case ESdcs:
        return;
    default:
        pcmd->char_state = ESnormal;
        sshbuf_put_u8(pcmd->cmd_buf, (uint8_t)ch);
    }
}

static int wfd_cmd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    int ch = 0;
    cmd_t *pcmd = &(c->cmd);

    int i = 0;
    for (; i < len; ++i) {
        ch = (int)buf[i];
        cmd_char_handle(pcmd, ch);
    }

    return 0;
}

static int rfd_respd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    int ch = 0;
    cmd_t *pcmd = &(c->cmd);



#if 0

    if (pcmd->cmd_state != CSrespd) {
        return 0;
    }

    int i = 0;
    for (; i < len; ++i) {
        ch = (int)buf[i];


    }
#endif

    switch (pcmd->cmd_state) {
    case CSrespd:
        if (strcmp(c->prompt, buf) == 0) {

        }
        sshbuf_put_string(pcmd->cmd_buf, buf, len);
        break;
    case CSfindrespd:
        sshbuf_put_string(pcmd->cmd_buf, buf, len);
        break;
    default:
        break;
    }


    return 0;
}

static int sftp_respd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    
    return 0;
}

int cmd_audit_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    if (c->proxy_state != PROXY_STATE_CMD) {
        return 0;
    }

    proxy_info_st *pinfo = &(c->proxy_info);
    switch (pinfo->pt) {
    case PT_SFTP:
        break;
    default:
        wfd_cmd_handle(ssh, c, buf, len);
        break;
    }

    return 0;
}


int cmd_audit_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN:
        login_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_LOGIN_OK:
        login_ok_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_CMD:
        rfd_respd_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_LOGIN_FAILED:
        debug3("login failed");
        fatal("login failed");  /* exit */
        break;
    default:
        break;
    }
    return 0;
}

int proxy_info_get(char *sid, proxy_info_st *pinfo)
{
	snprintf(pinfo->sid, sizeof(pinfo->sid), "%s", sid);

    //todo: get proxy info from db by sid
    debug3("sid = %s", sid);
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
    } else if (strcasecmp(sid, "ftp") == 0) {
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
        debug3("not support proxy type %s", pinfo->protocol_type);
        return -1;
    }

    debug3("cmd => %s", cmd);
    return 0;
}