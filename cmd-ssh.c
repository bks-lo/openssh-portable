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
#include "cmd-match.h"

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
        ": ",           /* 登录提示符 */
        "? [y/n] ",     /* 确认是否执行命令 */
        "[y/n]? ",
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

static int cmd_is_vi(const char *cmd, int len)
{
    if (cmd[1] == 'i') {
        if (cmd[2] == ' ' && len > 3) {
            return 1;
        } else if (cmd[2] == 'm' && cmd[3] == ' ' && len > 4) {
            return 1;
        }
    }

    return 0;
}

static int cmd_is_rz(const char *cmd, int len)
{
    if (cmd[1] == 'z' && len > 2) {
        return 1;
    }

    return 0;
}

static int cmd_is_sz(const char *cmd, int len)
{
    if (cmd[1] == 'z' && len > 2) {
        return 1;
    }

    return 0;
}

/**
 * \brief cmd
 *
 * \param [in|out] cmd
 * \return int
 */
static int is_non_audit_response(struct sshbuf *cmd)
{
    const char *ptr = sshbuf_ptr(cmd);
    int len = sshbuf_len(cmd);

    int ret = 0;
    switch (ptr[0]) {
    case 'v':
        ret = cmd_is_vi(ptr, len);
        break;
    case 'r':
        ret = cmd_is_rz(ptr, len);
        break;
    case 's':
        ret = cmd_is_sz(ptr, len);
        break;
    }

    return ret;
}

static int cmd_match(Channel *c, struct sshbuf *cmd)
{
    cmd_st *pcmd_ret = cmdctrl_match(c->pcmdctrl, sshbuf_ptr(cmd));

    if (pcmd_ret == NULL || !CCTYPE_ISSET(pcmd_ret, CCTYPE_BLACK)) {
        return 0;
    }

    debug_p("Warnning: black cmd match %s", pcmd_ret->cmd);

    // send to client
    char cmd_deny[1024] = {0};
    snprintf(cmd_deny, sizeof(cmd_deny), "\r\nPermission denied by rule [%s]", pcmd_ret->cmd);
    sshbuf_put(c->input, cmd_deny, strlen(cmd_deny));

    // send to server [ctrl + c]
    char clearline[1] = {0x03};
    write(c->wfd, clearline, 1);

    return 1;
}

int cmd_ssh_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
#if SSH_PROXY_DIRECT
    return 0;
#endif
    struct sshbuf *newline = NULL;
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

        /* 只有一个字符 代表是用户手动输入的字符，会回显请求数据，可以在回显中审计
           || 第一个字节为控制字符 的多字节字符串 代表 粘贴的命令不会直接发送给服务端，会回显请求数据，可以在回显中审计
           || 粘贴的命令中没有 提交字符('\r')  */
        if (len == 1 || vc_is_control(c->vc, 1, buf[0]) || strchr(buf, '\r') == NULL) {
            c->proxy_state = PROXY_STATE_CMD_ECHO_START;
            break;
        }

        /* 第一个字节为普通字符  的多字节字符串  并且 有提交字符， 代表 用户粘贴的命令没有回显，会直接发送给服务端，所以需要立即审计 */
        c->proxy_state = PROXY_STATE_CMD;
        // fallthrough
    case PROXY_STATE_CMD:
        wfd_cmd_handle(ssh, c, buf, len);
        // 命令匹配
        if (newline == NULL) {
            newline = sshbuf_new();
        } else {
            sshbuf_reset(newline);
        }
        vc_data_to_sshbuf(c->vc, newline);
        if (cmd_match(c, newline)) {
            c->proxy_state = PROXY_STATE_LOGIN_PROMPT;
            return -1;
        }

        break;
    case PROXY_STATE_CMD_ECHO:
        if (len == 1 && buf[0] == 0x0d) {
            proxy_cmd_end(c);
            if (cmd_match(c, c->cmd)) {
                c->proxy_state = PROXY_STATE_LOGIN_PROMPT;
                return -1;
            }
            if (is_non_audit_response(c->cmd)) {
                c->proxy_state = PROXY_STATE_RSPD_NOA;
            } else {
                c->proxy_state = PROXY_STATE_RSPD;
            }
        }
        break;
    case PROXY_STATE_RSPD:
        proxy_rspd_end(c);
        /* 根据响应最后的单词标记 来判断 是否为交互式的命令输入，还是普通的命令输入 */
        if (!need_input(c)) {
            c->proxy_state = PROXY_STATE_CMD_START;
            goto proxy_state_cmd_start;
        }

        c->proxy_state = PROXY_STATE_RSPD_INPUT;
    case PROXY_STATE_RSPD_INPUT:
        /* 当交互式的命令输入提交后，继续审计响应数据 */
        if (buf[len - 1] == 0x0d) {
            c->proxy_state = PROXY_STATE_RSPD;
        }
        break;
    case PROXY_STATE_CMD_ECHO_START:
        /* 需要在回包中审计命令，但是请求包过长分包了，不做任何处理 */
        break;
    case PROXY_STATE_RSPD_NOA:
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
    struct sshbuf *newline = NULL;
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
        /* 记录 */
        if (!vc_is_cr(c->vc)) {
            break;
        }

        proxy_cmd_end(c);
        if (is_non_audit_response(c->cmd)) {
            c->proxy_state = PROXY_STATE_RSPD_NOA;
            break;
        } else {
            c->proxy_state = PROXY_STATE_RSPD;
        }
        // fallthrough
    case PROXY_STATE_RSPD:
    case PROXY_STATE_RSPD_INPUT:    /* 交互式命令输入的回显数据正常审计 */
        rfd_rspd_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_RSPD_NOA:
        rfd_rspd_handle(ssh, c, buf, len);
        if (newline == NULL) {
            newline = sshbuf_new();
        }
        vc_data_to_sshbuf(c->vc, newline);
        //debug_p("newline[%d]>>%s", sshbuf_len(newline), sshbuf_ptr(newline));
        reset_vc_status(c->vc);
        if (strncasecmp(sshbuf_ptr(c->prompt), sshbuf_ptr(newline), sshbuf_len(c->prompt)) == 0) {
            c->proxy_state = PROXY_STATE_CMD_START;
        }
        sshbuf_reset(newline);
        break;
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