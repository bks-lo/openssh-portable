#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include "cmd-audit.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-define.h"

static int login_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    if (strncasecmp(buf, CONST_STR_N("Last")) == 0) {
        c->proxy_state = PROXY_STATE_LOGIN_OK;
        debug3("login success");
    } else if (strncasecmp(buf, CONST_STR_N("Permission")) == 0) {
        c->proxy_state = PROXY_STATE_LOGIN_FAILED;
        debug3("login failed");
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

int cmd_audit_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    if (c->proxy_state != PROXY_STATE_CMD) {
        return 0;
    }

    wfd_cmd_handle(ssh, c, buf, len);

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
    default:
        break;
    }
    return 0;
}