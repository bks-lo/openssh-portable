#ifndef _CMD_DEFINE_H
#define _CMD_DEFINE_H

#include "sshbuf.h"

#define     SSH_ETC_DIR     "/etc/ssh"
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

    char protocol_type[32];			//真实协议名称
    protolcol_type_t pt;            //真实协议类型

    char hostname[256];				//服务器ip 地址
    char username[256];				//服务器username
    char password[256];				//服务器username
    int port;   				    //服务器port

    char cli_pname[64];             //客户端程序名
    char client_ip[256];			//客户端ip
} proxy_info_st;

typedef enum code_type_em
{
    UTF_8=1,
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


typedef struct sftp_cache_st
{
    uint8_t enable;         // 是否启用这个cache结构
    char *buf;              // 缓存空间，已经为下一个分包，开辟好了空间，下个分包到达后直接填充
    void *cmd_cb;           // 缓存数据包的处理函数，为空 代表 不关心接下来的缓存内容，所以不用缓存数据，只用记录偏移就可以。
    int tlen;               // buf的空间大小
    int offset;             // 当前已缓存的偏移
    int needlen;            // 需要下一个分包的长度 = tlen - offset
} sftp_cache_st;


int proxy_info_get(char *sid, proxy_info_st *pinfo);

int proxy_cmd_get(char *cmd, int clen, proxy_info_st *pinfo, const char *command);

#endif