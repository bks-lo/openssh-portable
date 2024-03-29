#ifndef __CMD_MATCH_H__
#define __CMD_MATCH_H__

#include <stdint.h>
#include <pcre.h>

/** 设置命令类型 */
#define CCTYPE_SET(cmd, flag)       do { ((cmd)->type) |= (((uint8_t)1) << flag);} while (0)
#define CCTYPE_ISSET(cmd, flag)     ((((uint8_t)((cmd)->type)) >> (flag)) & (uint8_t)1)
#define CCTYPE_UNSET(cmd, flag)     do { ((cmd)->type) &= ~(((uint8_t)1) << (flag));} while (0)
#define CCTYPE_CLEAR(cmd)           do { ((cmd)->type) = 0; } while (0)

/** 获取优先级最高的命令类型 */
#define CCTYPE_GET(cmd)     get_fist_1idx(cmd->type)

/** 命令类型，按优先级排序，数字越大，匹配的优先级越高 */
typedef enum
{
    CCTYPE_BLACK = 0,           /**< 黑名单 */
    CCTYPE_WHITE,               /**< 白名单 */
    CCTYPE_GRANT,               /**< 审批 */
    CCTYPE_BLOCK,               /**< 阻断 */

    CCTYPE_MAX,                 /**< 最值，一直保持在最后 */
} cmdctrl_type_em;

typedef struct cmd_st
{
    uint8_t type;          /**< 命令类型 */
    char *cmd;             /**< 命令字符串 */
    pcre *pcre;            /**< 正则编译后的结果 */
} cmd_st;

typedef struct cmdctrl_st
{
    uint8_t enable;             /**< 是否开启命令控制 */
    uint8_t is_white;           /**< 是否为白名单模式, 1:白名单，0：黑名单 */
    int cmd_max;                /**< 命令数组最大个数 */
    int cmd_cur;                /**< 当前命令数组使用的个数 */
    cmd_st *cmd;                /**< 命令内容，优先加载和匹配级别高的命令*/
} cmdctrl_st;

/**
 * \brief 创建一个cmdctrl结构
 *
 * \return	cmdctrl_st*   NULL：创建失败  其他：创建成功
 */
cmdctrl_st *cmdctrl_create(void);

/**
 * \brief 销毁cmdctrl结构
 *
 * \param [in]	cmdctrl 需要销毁的cmdctrl指针，清理后会被置NULL
 */
void cmdctrl_destroy(cmdctrl_st *cmdctrl);

/**
 * \brief 解析命令字符串，并填充cmdctrl结构
 *
 * \param [in|out]	cmdctrl 命令控制结构
 * \param [in]	type 命令类型
 * \param [in]	cmdstring 前端输入的一行命令串，需要是动态开辟的，地址由cmdctrl结构管理
 * \return	int     0：解析成功；-1：解析失败；1：输入字符串和已有的字符串重复
 */
int cmd_string_parser2(cmdctrl_st *cmdctrl, cmdctrl_type_em type, char *cmdstring);

/**
 * \brief 解析命令字符串，并填充cmdctrl结构
 *
 * \param [in|out]	cmdctrl 命令控制结构
 * \param [in]	type 命令类型
 * \param [in]	cmdstring 前端输入的一行命令串
 * \param [in]  len 字符串长度
 * \return	int     0：解析成功；-1：解析失败；
 */
int cmd_string_parser1(cmdctrl_st *cmdctrl, cmdctrl_type_em type, const char *cmdstring, int len);


/**
 * \brief 匹配一个cmd命令
 *
 * \param [in]	cmdctrl 命令控制结构
 * \param [in]	cmd     单个命令字符串
 * \return	cmd_st*  NULL：匹配失败    否则返回命中的命令结构
 */
cmd_st *cmdctrl_match(cmdctrl_st *cmdctrl, char *cmd);

/**
 * \brief 获取最高位1的下标
 *
 * \param [in]	type 命令的类型
 * \return	int
 * \retval  获取失败：sizeof(uint8_t)； 获取成功返回对应的下标
 * \retval  从高位往低位遍历，遇到的第一个1的下标.
 */
uint8_t get_fist_1idx(uint8_t type);

#endif