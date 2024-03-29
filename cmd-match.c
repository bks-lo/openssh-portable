#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "cmd-match.h"
#include "log.h"
#include "xmalloc.h"

/**
 * \brief 创建一个cmdctrl结构
 *
 * \return	cmdctrl_st*   NULL：创建失败  其他：创建成功
 */
cmdctrl_st *cmdctrl_create(void)
{
    cmdctrl_st *cmdctrl = (cmdctrl_st *)xcalloc(1, sizeof(cmdctrl_st));
    cmdctrl->enable = 1;
    return cmdctrl;
}

/**
 * \brief 创建一个cmdctrl结构
 *
 * \return	cmdctrl_st*   NULL：创建失败  其他：创建成功
 */
static int cmdctrl_relloc(cmdctrl_st *cmdctrl, int add)
{
    assert(cmdctrl != NULL && add > 0);

    /* 申请新的内存 */
    int num = cmdctrl->cmd_max + add;
    cmd_st *new = (cmd_st *)xcalloc(num, sizeof(cmd_st));

    /* 将老的内容拷贝到新的内存上 */
    memcpy(new, cmdctrl->cmd, cmdctrl->cmd_max * sizeof(cmd_st));
    free(cmdctrl->cmd);
    cmdctrl->cmd = new;
    cmdctrl->cmd_max = num;
    return 0;
}

/**
 * \brief 销毁cmdctrl结构
 *
 * \param [in]	cmdctrl 需要销毁的cmdctrl指针，清理后会被置NULL
 */
void cmdctrl_destroy(cmdctrl_st *cmdctrl)
{
    if(cmdctrl->cmd == NULL)
        return;

    int i = 0;
    cmd_st *arr = cmdctrl->cmd;
    for (; i < cmdctrl->cmd_cur; ++i) {
        free(arr[i].cmd);
        free(arr[i].pcre);
    }

    free(cmdctrl->cmd);
    cmdctrl->cmd = NULL;
    cmdctrl->cmd_max = 0;
    cmdctrl->cmd_cur = 0;
}

/**
 * \brief 解析命令字符串，并填充cmdctrl结构
 *
 * \param [in|out]	cmdctrl 命令控制结构
 * \param [in]	type 命令类型
 * \param [in]	cmdstring 前端输入的一行命令串，需要是动态开辟的，地址由cmdctrl结构管理
 * \return	int     0：解析成功；-1：解析失败；1：输入字符串和已有的字符串重复
 */
int cmd_string_parser2(cmdctrl_st *cmdctrl, cmdctrl_type_em type, char *cmdstring)
{
    assert(cmdctrl != NULL && cmdstring != NULL);

    /* 遍历 判重 */
    int i;
    cmd_st *arr = cmdctrl->cmd;
    for (i = 0; i < cmdctrl->cmd_cur; ++i) {
        if (strcmp(arr[i].cmd, cmdstring) == 0) {
            CCTYPE_SET(&(arr[i]), type);
            return 1;
        }
    }

    /* 编译命令 */
    const char *errstr = NULL;
    int erroffset = 0;
    pcre *pattern = pcre_compile(cmdstring, 0, &errstr, &erroffset, NULL);
    if (pattern == NULL) {
        debug_p("PCRE compilation %s pattern failed at offset %d: %s",
            cmdstring, erroffset, errstr);
        return -1;
    }

    /* 增加新的命令 */
    if (cmdctrl->cmd_cur == cmdctrl->cmd_max) { /* 当ip段数组已经满时，需要重新开辟空间 */
        cmdctrl_relloc(cmdctrl, 5);             /* 多开辟一些空间，避免频繁malloc */
        arr = cmdctrl->cmd;
    }

    /* 赋值 */
    cmd_st *new = &(arr[cmdctrl->cmd_cur]);
    CCTYPE_SET(new, type);
    new->cmd = cmdstring;
    new->pcre = pattern;
    cmdctrl->cmd_cur += 1;
    return 0;
}

/**
 * \brief 解析命令字符串，并填充cmdctrl结构
 *
 * \param [in|out]	cmdctrl 命令控制结构
 * \param [in]	type 命令类型
 * \param [in]	cmdstring 前端输入的一行命令串
 * \param [in]  len 字符串长度
 * \return	int     0：解析成功；-1：解析失败；
 */
int cmd_string_parser1(cmdctrl_st *cmdctrl, cmdctrl_type_em type, const char *cmdstring, int len)
{
    assert(cmdctrl != NULL && cmdstring != NULL && len > 0);

    char *tmp = (char *)xcalloc(len + 1, sizeof(char));
    memcpy(tmp, cmdstring, len);

    int ret = cmd_string_parser2(cmdctrl, type, tmp);
    if (ret == 1 || ret < 0) {
        free(tmp);
        tmp = NULL;
    }

    ret = ret  < 0 ? -1 : 0;
    return ret;
}


/**
 * \brief 匹配一个cmd命令
 *
 * \param [in]	cmdctrl 命令控制结构
 * \param [in]	cmd     单个命令字符串
 * \return	cmd_st*  NULL：匹配失败    否则返回命中的命令结构
 */
cmd_st *cmdctrl_match(cmdctrl_st *cmdctrl, char *cmd)
{
#define PCRE_VECSIZE    30  /* pcre_exec接口输出的数组大小 */

    assert(cmdctrl != NULL && cmd != NULL);

    int i = 0;
    cmd_st *pcmd = NULL;
    //int ovecter[PCRE_VECSIZE] = {0};
    for (; i < cmdctrl->cmd_cur; ++i) {
        pcmd = &(cmdctrl->cmd[i]);
        //int ret = pcre_exec(pcmd->pcre, NULL, cmd, strlen(cmd), 0, 0, ovecter, PCRE_VECSIZE);
        int ret = pcre_exec(pcmd->pcre, NULL, cmd, strlen(cmd), 0, 0, NULL, 0);

        if (ret >= 0) {
            return pcmd;
        }
    }

    return NULL;
}


/**
 * \brief 获取最高位1的下标
 *
 * \param [in]	type 命令的类型
 * \return	int
 * \retval  获取失败：sizeof(uint8_t)； 获取成功返回对应的下标
 * \retval  从高位往低位遍历，遇到的第一个1的下标.
 */
uint8_t get_fist_1idx(uint8_t type)
{
#define BIT_PER_BYTE 8
    uint8_t max = sizeof(uint8_t) * BIT_PER_BYTE;
    uint8_t i = max;

    /* 从最高位向下遍历获取高位的1 */
    while (i > 0) {
        if (type & ((uint8_t)1 << (i - 1))) {
            return i - 1;
        }
        --i;
    }

    return max;
}