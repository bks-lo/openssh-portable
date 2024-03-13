#ifndef _CMD_DEFINE_H
#define _CMD_DEFINE_H

#include <stdbool.h>
#include <stddef.h>
#include <hiredis/hiredis.h>
#include "sshbuf.h"
#include "pathnames.h"

#define     SSH_NOPWD_PROXY_CMD     _PATH_SSH_PROGRAM " -F " SSHDIR "/ssh_config %s@%s -p %d"
#define     SSH_PROXY_CMD           SSH_NOPWD_PROXY_CMD" -d %s"
#define     RLOGIN_PROXY_CMD        "/usr/bin/rlogin -l %s -p %d %s"
#define     TELNET_PROXY_CMD        "/usr/bin/telnet -l %s %s %d"

typedef enum proxy_state_t
{
    PROXY_STATE_NONE = 0,
    PROXY_STATE_LOGIN,          /* 登录阶段 */
    PROXY_STATE_LOGIN_PROMPT,   /* 记录命令行提示符 */
    PROXY_STATE_CMD_START,      /* 开始输入命令 */
	PROXY_STATE_CMD,            /* 输入命令阶段 */
    PROXY_STATE_CMD_ECHO_START, /* 开始在回显中提取命令*/
    PROXY_STATE_CMD_ECHO,       /* 在回显中提取命令阶段 */
    PROXY_STATE_RSPD,           /* 记录响应数据 */
    PROXY_STATE_RSPD_INPUT,     /* 交互式输入阶段 */
    PROXY_STATE_END
} proxy_state_t;

typedef enum login_state_t
{
    LOGIN_STATE_NONE = 0,
    LOGIN_STATE_SUCCESS,
    LOGIN_STATE_FAIL,
    LOGIN_STATE_MAX
} login_state_t;

typedef enum protolcol_type_t
{
    PT_SSH,
    PT_SFTP,
    PT_SCP,
    PT_TELNET,
    PT_RLOGIN,
    PT_FTP
} protolcol_type_t;

typedef enum read_state_t
{
    READ_STATE_NONE = 0,
    READ_STATE_SUCCESS,
    READ_STATE_FAIL,
    READ_STATE_MAX
} read_state_t;

typedef enum write_state_t
{
    WRITE_STATE_NONE = 0,
    WRITE_STATE_SUCCESS,
    WRITE_STATE_FAIL,
    WRITE_STATE_MAX
} write_state_t;

typedef enum terminal_type_t
{
    TERMINAL_TYPE_AAA = 0
} terminal_type_t;

typedef enum cmd_state_t
{
    CSnone,
    CSstart,
    CSfindrespd,        /* 需要在响应中查找命令 */
    CSrespd
} cmd_state_t;

typedef enum key_state_t
{
    KSnone,
    KSup,
    KSdown,
} key_state_t;


typedef enum code_type_em
{
    UTF_8=0,
    GBK,
    BIG5,
    EUC_JP,
    EUC_KR,
    GB2312,
    GB18030,
    ISO_88592,
    KOI8_R,
    SHIFT_JIS,
    WINDOW874
} code_type_em;


typedef struct proxy_info_st
{
    char sid[128];                  //
    char uid[128];                  //

    void *redis_conn;               // redis连接句柄，取配置用
    void *mysql_conn;               // MySQL连接句柄，发送日志用

    char protocol_type[32];         //真实协议名称
    protolcol_type_t pt;            //真实协议类型

    code_type_em encode;            //编码格式: utf-8 = 0 , gbk = 1

    char hostname[256];             //服务器ip 地址
    char username[256];             //服务器username
    char password[256];             //服务器username
    char remote_ip[256];            //客户端ip
    int port;                       //服务器port

    char cli_pname[64];             //客户端程序名
    char client_ip[256];            //客户端ip
} proxy_info_st;


typedef struct sftp_cache_st
{
    uint8_t enable;         // 是否启用这个cache结构
    char *buf;              // 缓存空间，已经为下一个分包，开辟好了空间，下个分包到达后直接填充
    void *cmd_cb;           // 缓存数据包的处理函数，为空 代表 不关心接下来的缓存内容，所以不用缓存数据，只用记录偏移就可以。
    int tlen;               // buf的空间大小
    int offset;             // 当前已缓存的偏移
    int needlen;            // 需要下一个分包的长度 = tlen - offset
} sftp_cache_st;

int proxy_cmd_get(char *cmd, int clen, proxy_info_st *pinfo, const char *command);

#endif