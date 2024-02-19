#include <string.h>
#include <linux/types.h>
#include <stdbool.h>
#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include "packet.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-ssh.h"
#include "cmd-common.h"
#include "cmd-vc.h"
#include "xmalloc.h"

#define WHITESPACE " \t\r\n"

static void reset_vc_status(struct vc_data *vc)
{
    reset_terminal(vc);
    vc_uniscr_memset(vc);
}

/* 一个新命令开始审计，清理请求和响应缓存 */
static void reset_cmd_status(Channel *c)
{
    sshbuf_reset(c->cmd);
    sshbuf_reset(c->rspd);
    reset_vc_status(c->vc);
}

static void proxy_cmd_end(Channel *c)
{
    vc_data_to_sshbuf(c->vc, c->cmd);
    print_uni_line(c->vc);
    debug_p("cmd[%d]>>%s", sshbuf_len(c->cmd), sshbuf_ptr(c->cmd));
    reset_vc_status(c->vc);
}

static void proxy_rspd_end(Channel *c)
{
    vc_data_to_sshbuf(c->vc, c->rspd);
    print_uni_line(c->vc);
    debug_p("rspd[%lu]>>%s", sshbuf_len(c->rspd), sshbuf_ptr(c->rspd));
    reset_vc_status(c->vc);
}

static int set_prompt(Channel *c, struct vc_data *vc)
{
    sshbuf_reset(c->prompt);
    uints_to_sshbuf(vc->vc_uni_lines[vc->state.y], vc->state.x, c->prompt);
    debug_p("prompt [%u]>>%s", sshbuf_len(c->prompt), sshbuf_ptr(c->prompt));
    return 0;
}

static int login_prompt_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    struct vc_data *vc = c->vc;
    do_rspd_con_write(vc, buf, len);
    set_prompt(c, vc);
    return 0;
}

static int wfd_cmd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    return do_rqst_con_write(c->vc, buf, len);
}

static int rfd_cmd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    return do_rspd_con_write(c->vc, buf, len);
}

static int rfd_rspd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    return do_rspd_con_write(c->vc, buf, len);
}

#define SSH_PROXY_DIRECT    0

static int need_input(Channel *c)
{
    //TODO: 将输入标记通过配置文件加载到 Channel 中，然后循环匹配
    const char *arr[] = {
        ": ",
        "? [y/n] ",
    };

    int i = 0;
    const u_char *ptr = sshbuf_ptr(c->rspd);
    for (; i < sizeof(arr)/sizeof(arr[0]); ++i) {
        if (strncasecmp_r((const char *)ptr, arr[i], strlen(arr[i])) == 0) {
            return 1;
        }
    }

    return 0;
}


int cmd_ssh_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
#if SSH_PROXY_DIRECT
    return 0;
#endif

    debug_p("cmd start state=%d", c->proxy_state);
    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN_PROMPT:
        /* 为了让rfd退出 PROXY_STATE_LOGIN_PROMPT 状态，避免一直记录prompt */
        c->proxy_state = PROXY_STATE_CMD_START;
        // fallthrough
    proxy_state_cmd_start:
    case PROXY_STATE_CMD_START:
        reset_cmd_status(c);

        /* 只按了一个回车键，则记录prompt */
        if (len == 1 && buf[0] == 0x0d) {
            c->proxy_state = PROXY_STATE_LOGIN_PROMPT;
            break;
        }

        /* 只有一个字符 代表是用户手动输入的字符，会回显请求数据，可以在回显中审计     ||
           第一个字节为控制字符 的多字节字符串 代表 粘贴的命令不会直接发送给服务端，会回显请求数据，可以在回显中审计 */
        if (len == 1 || vc_is_control(c->vc, 1, buf[0])) {
            c->proxy_state = PROXY_STATE_CMD_ECHO_START;
            break;
        }

        /* 第一个字节为普通字符  的多字节字符串 代表 用户粘贴的命令没有回显，会直接发送给服务端，所以需要立即审计 */
        c->proxy_state = PROXY_STATE_CMD;
        // fallthrough
    case PROXY_STATE_CMD:
        wfd_cmd_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_CMD_ECHO:
        if (len == 1 && buf[0] == 0x0d) {
            proxy_cmd_end(c);
            c->proxy_state = PROXY_STATE_RSPD;
        }
        break;
    case PROXY_STATE_RSPD:
        proxy_rspd_end(c);
        if (!need_input(c)) {
            c->proxy_state = PROXY_STATE_CMD_START;
            goto proxy_state_cmd_start;
        }

        c->proxy_state = PROXY_STATE_RSPD_INPUT;
    case PROXY_STATE_RSPD_INPUT:
        if (buf[len - 1] == 0x0d) {
            c->proxy_state = PROXY_STATE_RSPD;
        }
        break;
    default:
        fatal_f("state = %d, invalid", c->proxy_state);
        break;
    }

    debug_p("cmd end  state=%d", c->proxy_state);
    return 0;
}

int cmd_ssh_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
#if SSH_PROXY_DIRECT
    return 0;
#endif
    debug_p("rspd start state=%d", c->proxy_state);
    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN:
        login_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_LOGIN_PROMPT:
        login_prompt_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_CMD_ECHO_START:
        /* 客户端发送了 ctrl + [a ... z] 的特殊请求，很多请求是无效的，服务端会发来07，不需要记录 */
        if (len == 1 && vc_is_control(c->vc, 1, buf[0])) {
            c->proxy_state = PROXY_STATE_CMD_START;
            break;
        }
        c->proxy_state = PROXY_STATE_CMD_ECHO;
        // fallthrough
    case PROXY_STATE_CMD_ECHO:
        rfd_cmd_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_CMD:
        if (!vc_is_cr(c->vc)) {
            break;
        }

        proxy_cmd_end(c);
        c->proxy_state = PROXY_STATE_RSPD;
        // fallthrough
    case PROXY_STATE_RSPD:
    case PROXY_STATE_RSPD_INPUT:
        rfd_rspd_handle(ssh, c, buf, len);
        break;
    /*
    case PROXY_STATE_RSPD_INPUT:
        rfd_rspd_handle(ssh, c, buf, len);
        break;
    */
    case PROXY_STATE_CMD_START:
        /* Not to do anything */
        break;
    default:
        fatal_f("state = %d, invalid", c->proxy_state);
        break;
    }

    debug_p("rspd end  state=%d", c->proxy_state);
    return 0;
}


#ifdef UNITTEST_CMD_SSH
#include "./tests/cmd-ssh-test.c"
#endif