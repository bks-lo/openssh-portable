#ifndef _CMD_DEFINE_H
#define _CMD_DEFINE_H

#include "sshbuf.h"

typedef enum proxy_state_t
{
    PROXY_STATE_NONE = 0,
    PROXY_STATE_LOGIN,
    PROXY_STATE_LOGIN_OK,
	PROXY_STATE_LOGIN_FAILED,
	PROXY_STATE_CMD,
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
    PT_NONE,
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

typedef enum char_state_t
{
    ESnormal,
    ESesc,
    ESsquare,
    ESgetpars,
    ESfunckey,
	EShash,
    ESsetG0,
    ESsetG1,
    ESpercent,
    EScsiignore,
    ESnonstd,
	ESpalette,
    ESosc,
    ESapc,
    ESpm,
    ESdcs,
    ESsemi,     /* 分号 */
} char_state_t;

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

typedef struct cmd_t
{
    terminal_type_t     ter_type;           /**< */
    login_state_t       login_state;        /**< */
    read_state_t        read_state;         /**< */
    write_state_t       write_state;        /**< */

    char_state_t        char_state;         /**< */
    cmd_state_t         cmd_state;          /**< */
    key_state_t         key_state;          /**< */
    struct sshbuf      *cmd_part;           /**< 被 ; ||  && 分割的多个命令其中的一部分，用来做命令匹配 */
    struct sshbuf      *cmd_buf;            /**< 请求命令 buf */
    struct sshbuf      *rsp_buf;            /**< 响应buf */
    struct sshbuf      *orig_bug;           /**< 原始数据 */
} cmd_t;


typedef struct proxy_info_st
{
    char sid[128];
    char uid[128];

    char protocol_type[32];			//真实协议类型
    protolcol_type_t pt;            //真实协议类型

    char hostname[256];				//服务器ip 地址
    char username[256];				//服务器username
    char password[256];				//服务器username
    int port;   				    //服务器port

    char cli_pname[64];             //客户端程序名
    char client_ip[256];			//客户端ip
} proxy_info_st;

int proxy_info_get(char *sid, proxy_info_st *pinfo);

int proxy_cmd_get(char *cmd, int clen, proxy_info_st *pinfo, const char *command);

#endif