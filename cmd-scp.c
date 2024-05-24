#include "cmd-scp.h"
#include "sftp.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-common.h"
#include <string.h>
#include <stdlib.h>
#include <limits.h>

/**
A. 输入
    1. 默认命令集 [ + （文件 or 目录）] + 动作
    2. 数据包

A2B 处理:
    1. 操作的文件名称审计
    2. 命令集是否匹配，动作是什么
    3.


B. 输出
    1. 告警日志
    2. 事件日志
 */

typedef enum {
    SCP_STATE_INIT = 0,
    SCP_STATE_CMD,
    SCP_STATE_CMD_RSPD,
    SCP_STATE_FILE_BEGIN,
    SCP_STATE_FILE_DOWN,
    SCP_STATE_FILE_UP,
    SCP_STATE_DATA,
    SCP_STATE_DATA_END,
    SCP_STATE_FILE_END,
    SCP_STATE_END,
} scp_state_em;

typedef enum scp_type_em {
    SCP_TYPE_CD = 0,
    SCP_TYPE_PWD,
    SCP_TYPE_RM,
    SCP_TYPE_MKDIR,
    SCP_TYPE_LS,
    SCP_TYPE_MV,
    SCP_TYPE_DOWN,
    SCP_TYPE_UP
} scp_type_em;

typedef struct proxy_scp_st {
    scp_state_em state;
    int type;
    int scp_dir;
    char file_path[1024];
    int file_total_len;
    int cur_len;
    int scp_state;
} proxy_scp_st;

static proxy_scp_st s_scp_data;

struct scp_cmds_st {
    int enable;
    scp_type_em ctype;
    const char *cmd;
} scp_cmds[] = {
    {0, SCP_TYPE_CD,       "cd \""},
    {0, SCP_TYPE_PWD,      "pwd ;" },
    {0, SCP_TYPE_RM,       "rm -f -r \"" },
    {0, SCP_TYPE_MKDIR,    "mkdir \"" },
    {0, SCP_TYPE_LS,       "ls -la \"" },
    {0, SCP_TYPE_MV,       "mv -f \"" }
};

#define WINSCP_FILE_BEGIN_FLAG  "WinSCP: this is begin-of-file."
#define WINSCP_FILE_END_FLAG    "WinSCP: this is end-of-file:"

/**
 * \brief 是否为scp分割符
 *
 * \param [in|out] buf
 * \param [in|out] len
 */
static int is_split_flag(const char *buf, int len)
{
    if (len == 1 && buf[0] == 0) {
        return 1;
    }

    if (len == 2 && buf[0] == 0 && buf[1] == 0) {
        return 1;
    }

    return 0;
}

static int is_scp_file_begin(const char *buf, int len)
{
    if (strncmp(buf, WINSCP_FILE_BEGIN_FLAG, sizeof(WINSCP_FILE_BEGIN_FLAG) - 1) == 0) {
        return 1;
    }

    return 0;
}

static int scp_login_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    if (len == 1 && buf[0] == 0) {
        c->proxy_state = PROXY_STATE_CMD;
        debug_p("login success");
    }
    return 0;
}

static int scp_cmd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{

    return 0;
}

static int is_high_risk_cmd(const char *buf, int len)
{
    int i = 0;
    int size = sizeof(scp_cmds)/sizeof(scp_cmds[0]);
    for (; i < size; ++i) {
        if (scp_cmds[i].enable == 0) {
            continue;
        }

        if (strncmp(scp_cmds[i].cmd, buf, strlen(scp_cmds[i].cmd)) == 0) {
            return 1;
        }
    }

    return 0;
}

/**
 * \brief 文件信息解析
 *        格式： 文件权限 0x20 文件大小 0x20 文件名 0x0a [文件内容]
 *
 * \param [in|out] c
 * \param [in|out] buf
 * \param [in|out] len
 * \return int
 *    ret < 0 : failed
 *    ret == 0: all file content in this packet
 *    ret > 0: file content been sliced
 */
static int scp_file_info_parser(Channel *c, const char *buf, int len)
{
    int i = 0;
    char *endptr = buf + len;
    char *flagptr = NULL;

    /* skip file permison string */
    for (; (i < len) && (buf[i] != 0x20); ++i);
    if (i >= len) {
        logit_p("file permison string invalid");
        return -1;
    }

    /* parser file size */
    i += 1;
    int filesize = strtol(&buf[i], &flagptr, 10);
    if (flagptr == NULL || *flagptr != 0x20
        || filesize < 0 || filesize == LONG_MAX) {
        logit_p("filesize[%d] invalid  or  end flag not 0x20", filesize);
        return -1;
    }

    /* parser file name */
    flagptr += 1;
    for (i = 0; (flagptr + i < endptr) && (flagptr[i] != 0x0a); ++i);
    if (flagptr + i >= endptr) {
        logit_p("file name invalid");
        return -1;
    }

    char filename[128] = {0};
    if ((i + 1) <= sizeof(filename)) {
        snprintf(filename, i + 1, "%s", flagptr);
    } else {
        snprintf(filename, sizeof(filename), "%s", flagptr);
    }
    debug_p("filesize %d, filename %s", filesize, filename);

    /* parser file content */
    flagptr = flagptr + i + 1;
    int ctlen = endptr - flagptr;
    if (ctlen <= 0) {
        ctlen = 0;
    }

    int left = filesize - ctlen;
    debug_p("left size = %d", left);
    if (left > 0) {
        debug_p("file content in next packet");
        return 1;
    } else {
        debug_p("file content in this packet");
        return 0;
    }
}

#define SCP_PROXY_DIRECT    0
int cmd_scp_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
#if SCP_PROXY_DIRECT
    return 0;
#endif

    int ret = 0;
    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN:
        c->proxy_state = SCP_STATE_INIT;
    case SCP_STATE_INIT:
        if (is_high_risk_cmd(buf, len)) {
            debug_p("is high risk cmd %s", buf);
            c->proxy_state = SCP_STATE_CMD_RSPD;
            return 0;
        }
        break;
    case SCP_STATE_FILE_BEGIN:
        if (is_split_flag(buf, len)) {
            c->proxy_state = SCP_STATE_FILE_DOWN;
            s_scp_data.scp_dir = 1;
        }
        break;
    case SCP_STATE_FILE_UP:
        if (buf[0] != 'C') {
            break;
        }

        ret = scp_file_info_parser(c, buf, len);
        if (ret < 0) {
            c->proxy_state = SCP_STATE_INIT;
        } else if (ret == 0) {
            c->proxy_state = SCP_STATE_DATA_END;
        } else {
            c->proxy_state = SCP_STATE_DATA;
        }
        break;
    case SCP_STATE_DATA:
        break;
    default:
        break;
    }

    return 0;
}

int cmd_scp_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
#if SCP_PROXY_DIRECT
    return 0;
#endif

    int ret = 0;
    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN:
        c->proxy_state = SCP_STATE_INIT;
    case SCP_STATE_INIT:
        if (is_scp_file_begin(buf, len)) {
            c->proxy_state = SCP_STATE_FILE_BEGIN;
        }
        break;
    case SCP_STATE_FILE_BEGIN:
        if (is_split_flag(buf, len)) {
            c->proxy_state = SCP_STATE_FILE_UP;
            s_scp_data.scp_dir = 0;
        }
        break;
    case SCP_STATE_FILE_DOWN:
        if (buf[0] != 'C') {
            break;
        }

        ret = scp_file_info_parser(c, buf, len);
        if (ret < 0) {
            c->proxy_state = SCP_STATE_INIT;
        } else if (ret == 0) {
            c->proxy_state = SCP_STATE_DATA_END;
        } else {
            c->proxy_state = SCP_STATE_DATA;
        }
        break;
    case SCP_STATE_DATA:
    case SCP_STATE_DATA_END:
        if (is_split_flag(buf, len)) {
            c->proxy_state = SCP_STATE_INIT;
        }
        break;
    case SCP_STATE_CMD_RSPD:

        break;
    default:
        break;
    }

    return 0;
}


#ifdef UNITTEST_CMD_SCP
#include "./tests/cmd-scp-test.c"
#endif