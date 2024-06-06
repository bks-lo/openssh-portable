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

typedef struct proxy_ssh_st
{
    /* 虚拟终端信息 */
    struct vc_data *vc;
    struct sshbuf *prompt;  /* 记录远程服务器的prompt */
    struct sshbuf *cmd;
    struct sshbuf *rspd;

    cmdctrl_st *pcmdctrl;   /* 用来加载命令控制结构 */
} proxy_ssh_st;

proxy_ssh_st *proxy_ssh_pd_create()
{
    proxy_ssh_st *ssh_pd = xmalloc(sizeof(proxy_ssh_st));
    ssh_pd->vc = vc_data_creat();
    if (vc_do_resize(ssh_pd->vc, 120, 100))
        fatal_f("resize vc falied");
    vc_data_init(ssh_pd->vc);

    ssh_pd->prompt = sshbuf_new();
    ssh_pd->cmd = sshbuf_new();
    ssh_pd->rspd = sshbuf_new();
    ssh_pd->pcmdctrl = cmdctrl_create();

#ifdef PROXY_DEBUG
    // TODO： parser cmd match rule
    cmd_string_parser1(ssh_pd->pcmdctrl, CCTYPE_BLACK, "\\bls\\b", strlen("\\bls\\b"));
#endif

    return ssh_pd;
}

void proxy_ssh_pd_destroy(void *private_data)
{
    proxy_ssh_st *ssh_pd = (proxy_ssh_st *)private_data;
    vc_data_destroy(ssh_pd->vc);
    ssh_pd->vc = NULL;

    sshbuf_free(ssh_pd->prompt);
    sshbuf_free(ssh_pd->cmd);
    sshbuf_free(ssh_pd->rspd);
    cmdctrl_destroy(ssh_pd->pcmdctrl);

    return ;
}

int proxy_ssh_vc_resize(Channel *c, unsigned int cols, unsigned int lines)
{
    proxy_ssh_st *ssh_pd = (proxy_ssh_st *)c->proxy_data;
    return vc_do_resize(ssh_pd->vc, cols, lines);
}


static void reset_vc_status(struct vc_data *vc)
{
    reset_terminal(vc);
    vc_uniscr_memset(vc);
}

/* 一个新命令开始审计，清理请求和响应缓存 */
static void reset_cmd_status(proxy_ssh_st *ssh_pd)
{
    sshbuf_reset(ssh_pd->cmd);
    sshbuf_reset(ssh_pd->rspd);
    reset_vc_status(ssh_pd->vc);
}

static void proxy_cmd_end(proxy_ssh_st *ssh_pd)
{
    vc_data_to_sshbuf(ssh_pd->vc, ssh_pd->cmd);
    print_uni_line(ssh_pd->vc);
    debug_p("cmd[%d]>>%s", sshbuf_len(ssh_pd->cmd), sshbuf_ptr(ssh_pd->cmd));
    reset_vc_status(ssh_pd->vc);
}

static void proxy_rspd_end(proxy_ssh_st *ssh_pd)
{
    vc_data_to_sshbuf(ssh_pd->vc, ssh_pd->rspd);
    print_uni_line(ssh_pd->vc);
    debug_p("rspd[%lu]>>%s", sshbuf_len(ssh_pd->rspd), sshbuf_ptr(ssh_pd->rspd));
    reset_vc_status(ssh_pd->vc);
}

static int login_prompt_handle(proxy_ssh_st *ssh_pd, const char *buf, int len)
{
    struct vc_data *vc = ssh_pd->vc;
    do_rspd_con_write(vc, buf, len);
    sshbuf_reset(ssh_pd->prompt);
    uints_to_sshbuf(vc->vc_uni_lines[vc->state.y], vc->state.x, ssh_pd->prompt);
    debug_p("prompt [%u]>>%s", sshbuf_len(ssh_pd->prompt), sshbuf_ptr(ssh_pd->prompt));
    return 0;
}

static int wfd_cmd_handle(proxy_ssh_st *ssh_pd, const char *buf, int len)
{
    return do_rqst_con_write(ssh_pd->vc, buf, len);
}

static int rfd_cmd_handle(proxy_ssh_st *ssh_pd, const char *buf, int len)
{
    return do_rspd_con_write(ssh_pd->vc, buf, len);
}

static int rfd_rspd_handle(proxy_ssh_st *ssh_pd, const char *buf, int len)
{
    return do_rspd_con_write(ssh_pd->vc, buf, len);
}

#define SSH_PROXY_DIRECT    0

static int need_input(proxy_ssh_st *ssh_pd)
{
    //TODO: 将输入标记通过配置文件加载到 Channel 中，然后循环匹配
    const char *arr[] = {
        ": ",           /* 登录提示符 */
        "? [y/n] ",     /* 确认是否执行命令 */
        "[y/n]? ",
    };

    int i = 0;
    const u_char *ptr = sshbuf_ptr(ssh_pd->rspd);
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
    proxy_ssh_st *ssh_pd = (proxy_ssh_st *)(c->proxy_data);
    cmd_st *pcmd_ret = cmdctrl_match(ssh_pd->pcmdctrl, sshbuf_ptr(cmd));

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
    proxy_ssh_st *ssh_pd = (proxy_ssh_st *)(c->proxy_data);

    debug_p("cmd start state=%d", c->proxy_state);
    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN_PROMPT:
        /* 为了让rfd退出 PROXY_STATE_LOGIN_PROMPT 状态，避免一直记录prompt */
        c->proxy_state = PROXY_STATE_CMD_START;
        // fallthrough
    proxy_state_cmd_start:
    case PROXY_STATE_CMD_START:
        reset_cmd_status(ssh_pd);

        /* 只按了一个回车键，则记录prompt */
        if (len == 1 && buf[0] == 0x0d) {
            c->proxy_state = PROXY_STATE_LOGIN_PROMPT;
            break;
        }

        /* 只有一个字符 代表是用户手动输入的字符，会回显请求数据，可以在回显中审计
           || 第一个字节为控制字符 的多字节字符串 代表 粘贴的命令不会直接发送给服务端，会回显请求数据，可以在回显中审计
           || 粘贴的命令中没有 提交字符('\r')  */
        if (len == 1 || vc_is_control(ssh_pd->vc, 1, buf[0]) || strchr(buf, '\r') == NULL) {
            c->proxy_state = PROXY_STATE_CMD_ECHO_START;
            break;
        }

        /* 第一个字节为普通字符  的多字节字符串  并且 有提交字符， 代表 用户粘贴的命令没有回显，会直接发送给服务端，所以需要立即审计 */
        c->proxy_state = PROXY_STATE_CMD;
        // fallthrough
    case PROXY_STATE_CMD:
        wfd_cmd_handle(ssh_pd, buf, len);
        // 命令匹配
        if (newline == NULL) {
            newline = sshbuf_new();
        } else {
            sshbuf_reset(newline);
        }
        vc_data_to_sshbuf(ssh_pd->vc, newline);
        if (cmd_match(c, newline)) {
            c->proxy_state = PROXY_STATE_LOGIN_PROMPT;
            return -1;
        }

        break;
    case PROXY_STATE_CMD_ECHO:
        if (len == 1 && buf[0] == 0x0d) {
            proxy_cmd_end(ssh_pd);
            if (cmd_match(c, ssh_pd->cmd)) {
                c->proxy_state = PROXY_STATE_LOGIN_PROMPT;
                return -1;
            }
            if (is_non_audit_response(ssh_pd->cmd)) {
                c->proxy_state = PROXY_STATE_RSPD_NOA;
            } else {
                c->proxy_state = PROXY_STATE_RSPD;
            }
        }
        break;
    case PROXY_STATE_RSPD:
        proxy_rspd_end(ssh_pd);
        /* 根据响应最后的单词标记 来判断 是否为交互式的命令输入，还是普通的命令输入 */
        if (!need_input(ssh_pd)) {
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
    proxy_ssh_st *ssh_pd = (proxy_ssh_st *)(c->proxy_data);

    debug_p("rspd start state=%d", c->proxy_state);
    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN:
        login_handle(c, buf, len);
        break;
    case PROXY_STATE_LOGIN_PROMPT:
        login_prompt_handle(ssh_pd, buf, len);
        break;
    case PROXY_STATE_CMD_ECHO_START:
        /* 客户端发送了 ctrl + [a ... z] 的特殊请求，很多请求是无效的，服务端会发来07，不需要记录 */
        if (len == 1 && vc_is_control(ssh_pd->vc, 1, buf[0])) {
            c->proxy_state = PROXY_STATE_CMD_START;
            break;
        }
        c->proxy_state = PROXY_STATE_CMD_ECHO;
        // fallthrough
    case PROXY_STATE_CMD_ECHO:
        rfd_cmd_handle(ssh_pd, buf, len);
        break;
    case PROXY_STATE_CMD:
        /* 记录 */
        if (!vc_is_cr(ssh_pd->vc)) {
            break;
        }

        proxy_cmd_end(ssh_pd);
        if (is_non_audit_response(ssh_pd->cmd)) {
            c->proxy_state = PROXY_STATE_RSPD_NOA;
            break;
        } else {
            c->proxy_state = PROXY_STATE_RSPD;
        }
        // fallthrough
    case PROXY_STATE_RSPD:
    case PROXY_STATE_RSPD_INPUT:    /* 交互式命令输入的回显数据正常审计 */
        rfd_rspd_handle(ssh_pd, buf, len);
        break;
    case PROXY_STATE_RSPD_NOA:
        rfd_rspd_handle(ssh_pd, buf, len);
        if (newline == NULL) {
            newline = sshbuf_new();
        }
        vc_data_to_sshbuf(ssh_pd->vc, newline);
        //debug_p("newline[%d]>>%s", sshbuf_len(newline), sshbuf_ptr(newline));
        reset_vc_status(ssh_pd->vc);
        if (strncasecmp(sshbuf_ptr(ssh_pd->prompt), sshbuf_ptr(newline), sshbuf_len(ssh_pd->prompt)) == 0) {
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