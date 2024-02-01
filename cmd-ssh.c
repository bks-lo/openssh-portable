#include <string.h>
#include <linux/types.h>
#include <stdbool.h>
#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-ssh.h"
#include "cmd-common.h"
#include "cmd-vc.h"
#include "xmalloc.h"

static int reset_cmd_status(Channel *c)
{
    sshbuf_reset(c->cmd);
    reset_terminal(c->vc);
}

static int reset_rspd_status(Channel *c)
{
    sshbuf_reset(c->rspd);
    reset_terminal(c->vc);
}

static int proxy_cmd_end(Channel *c)
{
    vc_data_to_sshbuf(c->vc, c->cmd);
    debug_p("cmd[%d]>>%s", sshbuf_len(c->cmd), sshbuf_ptr(c->cmd));
}

static int set_prompt(Channel *c, struct vc_data *vc)
{
    sshbuf_reset(c->prompt);
    uints_to_sshbuf(vc->vc_uni_lines[vc->state.y], vc->state.x, c->prompt);
    debug_p("prompt [%u]>>%s", sshbuf_len(c->prompt), sshbuf_ptr(c->prompt));
    return 0;
}

static int login_ok_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    struct vc_data *vc = c->vc;
    do_con_write(vc, buf, len);
    set_prompt(c, vc);
    return 0;
}

static int wfd_cmd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    return do_con_write(c->vc, buf, len);
}

static int rfd_cmd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    return do_con_write(c->vc, buf, len);
}

int cmd_ssh_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN_OK:
        /* 为了让rfd退出 PROXY_STATE_LOGIN_OK 状态，避免一直记录prompt */
        c->proxy_state = PROXY_STATE_CMD_START;
        // fallthrough
    case PROXY_STATE_CMD_START:
        reset_cmd_status(c);

        /* 第一个字符为控制字符，则在回显数据中获取命令 */
        if (vc_is_control(c->vc, 1, buf[0])) {
            c->proxy_state = PROXY_STATE_CMD_ECHO;
            break;
        }

        /* 第一个字符为普通字符，则在当前获取命令 */
        c->proxy_state = PROXY_STATE_CMD;
        // fallthrough
    case PROXY_STATE_CMD:
        wfd_cmd_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_CMD_ECHO:
        if (len == 1 && buf[0] == 0x0d) {
            proxy_cmd_end(c);
            c->proxy_state = PROXY_STATE_RSPD;
            reset_rspd_status(c);
        }
        break;
    default:
        fatal_f("state = %d, invalid", c->proxy_state);
        break;
    }


    return 0;
}

int cmd_ssh_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN:
        login_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_LOGIN_OK:
        login_ok_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_CMD_ECHO:
        rfd_cmd_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_CMD:
        if (!vc_is_cr(c->vc)) {
            break;
        }

        proxy_cmd_end(c);
        c->proxy_state = PROXY_STATE_RSPD;
        reset_rspd_status(c);
        // fallthrough
    case PROXY_STATE_RSPD:
        break;
    default:
        fatal_f("state = %d, invalid", c->proxy_state);
        break;
    }

    return 0;
}


#ifdef UNITTEST_CMD_SSH
#include "./tests/cmd-ssh-test.c"
#endif