#include "includes.h"

#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <ctype.h>
#include "cJSON.h"
#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-common.h"
#include "cmd-define.h"
#include "db_utils.h"
#include "proxy.h"
#include "xmalloc.h"
#include "pathnames.h"


typedef struct protocol_info_st
{
    const char *protocol;
    protolcol_type_t pt;
    const char *desc;
} protocol_info_st;

protocol_info_st g_protocol_info[] = {
    {"ssh",     PT_SSH,     "ssh v2 protocol"},
    {"sftp",    PT_SFTP,    "sftp protocol"},
    {"scp",     PT_SCP,     "scp protocol"},
    {"telnet",  PT_TELNET,  "telnet protocol"},
    {"rlogin",  PT_RLOGIN,  "rlogin protocol"},
    {"ftp",     PT_FTP,     "ftp protocol"}
};

int strcasecmp_r(const char *str1, int len1, const char *str2, int len2)
{
    int ret = 0;
    int aA = 'a' - 'A';
    int Aa = 'A' - 'a';

    debug_p("str1[%d]=%s, str2[%d]=%s", len1, str1, len2, str2);

    for (; (len1--) > 0 && (len2--) > 0; ) {
        ret = str1[len1] - str2[len2];

        if (ret == aA) {
            if (str1[len1] < 'a' || str1[len1] > 'z') {
                return ret;
            }
        } else if (ret == Aa) {
            if (str1[len1] < 'A' || str1[len1] > 'Z') {
                return ret;
            }
        } else if (ret != 0) {
            return ret;
        }
    }

    if (len1 == -1 || len2 == -1) {
        return 0;
    }

    return -1;
}

#define WHITESPACE " \t\r\n"
char *strip_whitespace_trail(char *line)
{
    int len = 0;
    /* Strip trailing whitespace. Allow \f (form feed) at EOL only */
    if ((len = strlen(line)) == 0)
        return 0;
    for (len--; len >= 0; len--) {
        if (strchr(WHITESPACE "\f", line[len]) == NULL)
            break;
        line[len] = '\0';
    }

    return line;
}

const char *strip_whitespace_head(const char *line)
{
    return line + strspn(line, WHITESPACE);
}

int get_file_line_num(const char *file)
{
    FILE *fp = fopen(file, "r");
    if (fp == NULL) {
        debug_p("open %s failed", file);
        return -1;
    }

    int linenum = 0;
    char str[512] = {0};
    while (fgets(str, sizeof(str), fp) != NULL) {
        ++linenum;
    }

    return linenum;
}

int get_simple_file_content(const char *file, char ***line_arr, int *line_num)
{
    char *cp;
    char str[512] = {0};
    FILE *fp = fopen(file, "r");
    if (fp == NULL) {
        debug_p("open %s failed", file);
        return -1;
    }

    int tlnum = get_file_line_num(file);
    if (tlnum <= 0) {
        debug_p("%s line size == 0", file);
        return -1;
    }

    char **carr = (char **)malloc(sizeof(char *) * tlnum);
    if (carr == NULL) {
        debug_p("%s malloc linenum[%d] arr failed", file, tlnum);
        return -1;
    }
    memset(carr, 0, sizeof(char *) * tlnum);

    int linenum = 0;
    while (fgets(str, sizeof(str), fp) != NULL && linenum < tlnum) {
        cp = str;
        //cp = strip_whitespace_head(cp);     /* 保留头部的原始格式 */
        strip_whitespace_trail(cp);
        if (cp[0] == '#' || cp[0] == '\0') {
            continue;
        }

        carr[linenum] = strdup(cp);
        ++linenum;
    }

    if (linenum == 0) {
        free(carr);
        debug_p("%s line size == 0", file);
        return -1;
    }

    if (line_arr == NULL) {
        free(carr);
    } else {
        *line_arr = carr;
    }

    if (line_num != NULL) {
        *line_num = linenum;
    }

    return 0;
}

int get_login_rstr_by_proto(const char *protocol_type, int is_fail, char ***lrstr_arr, int *lrsize)
{
    char lrfile[512] = {0};

    /* example: /etc/ssh/login_result_ssh.ok    /etc/ssh/login_result_rlogin.fail */
    snprintf(lrfile, sizeof(lrfile), "%s/login_result_%s.%s",
             SSHDIR, protocol_type, (is_fail ? "fail" : "ok"));

    return get_simple_file_content(lrfile, lrstr_arr, lrsize);
}

/**
 * \brief 找到最后字符串最后一个合法的单词  (必须以字母开头)
 *
 * \param [in|out] buf
 * \param [in|out] len
 * \param [in|out] min_len      单词的最小长度，当单词长度>=min_len时，才被认为合法
 * \return const char*
 */
static const char *find_last_word(const char *buf, int len, int min_len)
{
    int i = len -1;
    int last_i = len;
    int wlen = 0;
    const char *ret = NULL;
    min_len = min_len > 0 ? min_len : 1;    /* 最小长度为 1 */

    for(; i >= 0; --i) {
        if (i == 0 && buf[i] != ' ') {
            wlen = last_i - i;
            ret = buf + i;
        } else if (buf[i] == ' ') {
            wlen = last_i - i -1;
            ret = buf + i + 1;
        } else {
            continue;
        }

        last_i = i;
        if (wlen < min_len) {
            continue;
        }

        if (isalpha(*ret)) {
            return ret;
        }
    }

    return NULL;
}

int login_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
#if 0
    static int need_password = 0;
    proxy_info_st *pinfo = &(c->proxy_info);

    /* rlogin telnet 只能在交互时传输密码 */
    if (need_password == 0 && (pinfo->pt == PT_RLOGIN || pinfo->pt == PT_TELNET)) {
        if (strcasecmp_r(buf, len, CONST_STR_N("password: ")) == 0) {
            need_password = 1;
            write(c->wfd, pinfo->password, strlen(pinfo->password));
            write(c->wfd, "\r", 1);
            return 0;
        }
    }

    /* 剔除字符串前面的\r\n */
    if (buf[0] == '\r' && buf[1] == '\n') {
        buf += 2;
        len -= 2;
    }

    if (strncasecmp(buf, CONST_STR_N("Last")) == 0) {
        c->proxy_state = PROXY_STATE_LOGIN_OK;
        debug_p("login success");
    } else if (strncasecmp(buf, CONST_STR_N("Permission")) == 0) {
        c->proxy_state = PROXY_STATE_LOGIN_FAILED;
        debug_p("login Permission");
    } else if (strncasecmp(buf, CONST_STR_N("Login incorrect")) == 0) {
        c->proxy_state = PROXY_STATE_LOGIN_FAILED;
        write(c->wfd, pinfo->username, strlen(pinfo->username));
        write(c->wfd, "\r", 1);
        debug_p("Login incorrect");
    } else if (is_sftp_version_type(buf, len)) {
        c->proxy_state = PROXY_STATE_CMD;
        debug_p("login success");
    }

    return 0;
#endif

#if 0
    int i = 0;
    int ret = 0;
    int lrok_num = 0;
    int lrfail_num = 0;
    const char *result = NULL;
    char **lrok_arr = NULL;
    char **lrfail_arr = NULL;

    proxy_info_st *pinfo = &(c->proxy_info);
    ret = get_login_rstr_by_proto(pinfo->protocol_type, 1, &lrfail_arr, &lrfail_num);
    if (ret) {
        debug_p("get_login_rstr_by_proto failed");
        return -1;
    }

    ret = get_login_rstr_by_proto(pinfo->protocol_type, 0, &lrok_arr, &lrok_num);
    if (ret) {
        debug_p("get_login_rstr_by_proto failed");
        return -1;
    }

    int loop = 0;
    int is_new_line = 1;            /* When there are multiple lines, match the first word of each line. */
    for (; loop < len; ++loop) {
        if (buf[loop] == 0x0d || buf[loop] == 0x0a) {
            is_new_line = 1;
            continue;
        }

        if (!is_new_line)
            continue;

        is_new_line = 0;
        for (i = 0; i < lrfail_num; ++i) {
            if (strncasecmp(buf + loop, lrfail_arr[i], strlen(lrfail_arr[i])) == 0) {
                c->proxy_state = PROXY_STATE_LOGIN_FAILED;
                debug_p("login failed");
                break;
            }
        }

        for (i = 0; i < lrok_num; ++i) {
            if (strncasecmp(buf + loop, lrok_arr[i], strlen(lrok_arr[i])) == 0) {
                c->proxy_state = PROXY_STATE_LOGIN_OK;
                debug_p("login success 1");
                break;
            }
        }
    }

    return 0;
#endif

#if 0
    proxy_info_st *pinfo = ssh->pinfo;
    /* 输入密码 */
    char *tmp = xstrdup(buf);
    char *w = NULL;
    while ((w = strrchr(tmp, ' ')) != NULL) {
        if (w[1] >= 'A' && w[1] <= 'Z' || w[1] >= 'a' && w[1] <= 'z') {
            if (strncasecmp(w + 1, "password", sizeof("password") - 1) == 0) {
                write(c->wfd, pinfo->password, strlen(pinfo->password));
                write(c->wfd, "\r", 1);
                free(tmp);
                return 0;
            }
        }
        w[0] = '\0';
    }

    if (strncasecmp(buf, "password", sizeof("password") - 1) == 0) {
        write(c->wfd, pinfo->password, strlen(pinfo->password));
        write(c->wfd, "\r", 1);
        return 0;
    }
#endif

    /* 因为在拿到了sid时，会进行一次登录尝试，所以能走到这里的流程，都认为是能登录成功的，除非网络原因 */
    /* 部分服务器在登录成功时，不会返回任何明确标识，所以这里增加一步密码输入，用来在逻辑上明确登录成功状态 */

    const char *s_pwd = NULL;
    s_pwd = find_last_word(buf, len, 0);
    if (s_pwd == NULL) {
        return -1;
    }

    proxy_info_st *pinfo = &(c->proxy_info);
    if (strncasecmp(s_pwd, "password", sizeof("password") - 1) == 0) {
        write(c->wfd, pinfo->password, strlen(pinfo->password));
        write(c->wfd, "\n", 1);
        c->proxy_state = PROXY_STATE_LOGIN_OK;
        return 0;
    }

    return -1;
}

/**
 * \brief 对字符编码进行转码
 *
 * \param [in] from_charset     源码编码格式
 * \param [in] to_charset       期望的输入编码格式
 * \param [in] inbuf            源码
 * \param [in] inlen            源长度
 * \param [out] outbuf          输出缓冲空间
 * \param [in|out] outlen       in:输出空间总长度  out:已使用的长度
 * \return int                  0:成功      非0:失败
 */
int code_convert(char *from_charset, char *to_charset,
                 char *inbuf, size_t inlen,
                 char *outbuf, size_t *outlen)
{
    //--input param judge
    if (NULL == from_charset
        || NULL == to_charset
        || NULL == inbuf
        || inlen <= 0
        || NULL == outbuf
        || outlen == NULL
        || *outlen <= 0) {

        return -1;
    }

    //variable initial
    int ret = 0;
    iconv_t cd = {0};
    char **pin = &inbuf;
    char **pout = &outbuf;
    size_t outlen_b = *outlen;

    cd = iconv_open(to_charset, from_charset);//iconv open
    if (cd == (iconv_t)-1) {
        debug_p("iconv_open error %s",strerror(errno));
        return -1;
    }

    memset(outbuf, 0, *outlen);
    if (iconv(cd, pin, &inlen, pout, outlen) == (size_t)-1) {
        debug_p("iconv error %s", strerror(errno));
        ret = -1;
    } else {
        debug_p("iconv success");
        ret = 0;
    }
    *outlen = outlen_b - *outlen;
    iconv_close(cd);
    return ret;
}

int convert_encode_2_utf8(code_type_em from_type, char *inbuf, size_t inlen, char *outbuf, size_t *outlen)
{
    //input param judge
    if (from_type <= 0 || NULL == inbuf || inlen <= 0 || NULL == outbuf || outlen == NULL) {
        return -1;
    }

    int ret = -1;
    switch (from_type) {
    case BIG5:
        ret = code_convert("BIG5", "UTF8", inbuf, inlen, outbuf, outlen);
        break;
    case GBK:
        ret = code_convert("GBK", "UTF8", inbuf, inlen, outbuf, outlen);
        break;
    case EUC_JP:
        ret = code_convert("EUC-JP", "UTF8", inbuf, inlen, outbuf, outlen);
        break;
    case EUC_KR:
        ret = code_convert("EUC-KR", "UTF8", inbuf, inlen, outbuf, outlen);
        break;
    case GB2312:
        ret = code_convert("GB2312", "UTF8", inbuf, inlen, outbuf, outlen);
        break;
    case GB18030:
        ret = code_convert("GB18030", "UTF8", inbuf, inlen, outbuf, outlen);
        break;
    case ISO_88592:
        ret = code_convert("ISO88592", "UTF8", inbuf, inlen, outbuf, outlen);
        break;
    case KOI8_R:
        ret = code_convert("KOI8R", "UTF8", inbuf, inlen, outbuf, outlen);
        break;
    case SHIFT_JIS:
        ret = code_convert("SHIFT-JIS", "UTF8", inbuf, inlen, outbuf, outlen);
        break;
    case WINDOW874:
        ret = code_convert("WINDOWS-874", "UTF8", inbuf, inlen, outbuf, outlen);
        break;
    default:
        break;
    }

    return ret;
}

inline int need_convert(Channel *c)
{
    return c->proxy_info.encode != UTF_8;
}

#define CONVERT_STEP    2

char *convert_encode(Channel *c, char *inbuf, size_t inlen, size_t *outlen)
{
    proxy_info_st *pinfo = &(c->proxy_info);

    if (!need_convert(c)) {
        *outlen = inlen;
        return inbuf;
    }

    size_t olen = inlen << CONVERT_STEP;        /* 扩大4倍 */
    char *outbuf = (char *)malloc(olen);
    memset(outbuf, 0, *outlen);
    if (convert_encode_2_utf8(pinfo->encode, inbuf, inlen, outbuf, &olen) != 0) {
        free(outbuf);
        return NULL;
    }

    *outlen = olen;
    return outbuf;
}

void convert_free(Channel *c, char **s)
{
    if (s != NULL && need_convert(c)) {
        free(*s);
        *s = NULL;
    }
}

int cmd_log_send(Channel *c, const char *buf, int len)
{
    return 0;
}

static int protocol_to_pt(proxy_info_st *pinfo)
{
    int i = 0;
    int tsize = sizeof(g_protocol_info)/sizeof(g_protocol_info[0]);
    for (; i < tsize; ++i) {
        if (strcmp(g_protocol_info[i].protocol, pinfo->protocol_type) == 0) {
            pinfo->pt = g_protocol_info[i].pt;
            return 0;
        }
    }

    return -1;
}

//通过db_sid获取信息，填充会话结构
int get_proxy_info_by_sid(proxy_info_st *pinfo, char *sid)
{
    char cmd[256] = {'\0'};
    char *value = NULL;
    cJSON *root = NULL;
    cJSON *node = NULL;

    if ((pinfo == NULL) || (sid == NULL) || (pinfo->redis_conn == NULL) || (strlen(sid) == 0)) {
        error_p("pinfo, redis_conn, sid is NULL or empty");
        return -1;
    }

    snprintf(cmd, 256, "connection_session::%s", sid);
    if (Redis_Query(pinfo->redis_conn, cmd, 0, &value) < 0) {
        error_p("excute cmd[%s] failed", cmd);
        if (value != NULL) {
            free(value);
        }
        return -1;
    }

    debug_p("redis value=%s", value);
    root = cJSON_Parse(value);
    if (root == NULL) {
        error_p("turn redis value to json failed!");
        free(value);
        return -1;
    }

    node = cJSON_GetObjectItem(root, "sid");
    if ((node != NULL) && (node->valuestring != NULL)) {
        snprintf(pinfo->sid, sizeof(pinfo->sid), "%s", node->valuestring); //sid赋值
    }
    node = cJSON_GetObjectItem(root, "uid");
    if ((node != NULL) && (node->valuestring != NULL)) {
        snprintf(pinfo->uid, sizeof(pinfo->uid), "%s", node->valuestring); //uid赋值
    }
    node = cJSON_GetObjectItem(root, "protocol");
    if ((node != NULL) && (node->valuestring != NULL)) {
        snprintf(pinfo->protocol_type, sizeof(pinfo->protocol_type), "%s", node->valuestring); //协议名称赋值
    }
    node = cJSON_GetObjectItem(root, "hostname");
    if ((node != NULL) && (node->valuestring != NULL)) {
        snprintf(pinfo->hostname, sizeof(pinfo->hostname), "%s", node->valuestring); //数据库服务器IP赋值
    }
    node = cJSON_GetObjectItem(root, "username");
    if ((node != NULL) && (node->valuestring != NULL)) {
        snprintf(pinfo->username, sizeof(pinfo->username), "%s", node->valuestring); //数据库服务器usernmae赋值
    }
    node = cJSON_GetObjectItem(root, "password");
    if ((node != NULL) && (node->valuestring != NULL)) {
        snprintf(pinfo->password, sizeof(pinfo->password), "%s", node->valuestring); //数据库服务器password赋值
    }
    node = cJSON_GetObjectItem(root, "port");
	if ((node != NULL) && (node->valuestring != NULL)) {
        pinfo->port = atoi(node->valuestring); //数据库服务器port赋值
	}
    node = cJSON_GetObjectItem(root, "remote_ip");
    if ((node != NULL) && (node->valuestring != NULL)) {
        snprintf(pinfo->remote_ip, sizeof(pinfo->remote_ip), "%s", node->valuestring); //客户端赋值
    }
    node = cJSON_GetObjectItem(root, "client_name");
    if ((node != NULL) && (node->valuestring != NULL)) {
        if (strlen(node->valuestring) > 0) {
            snprintf(pinfo->cli_pname, sizeof(pinfo->cli_pname), "%s", node->valuestring); //客户端程序名赋值
        }
    }

    if (value != NULL) {
        free(value);
    }

    if (protocol_to_pt(pinfo)) {
        error_p("not support protocol[%s]", pinfo->protocol_type);
        return -1;
    }

    cJSON_Delete(root);
    debug_p("===============session info=============");
    debug_p("session->sid=%s", pinfo->sid);
    debug_p("session->uid=%s", pinfo->uid);
    debug_p("session->protocol_type=%s", pinfo->protocol_type);
    debug_p("session->hostname=%s", pinfo->hostname);
    debug_p("session->username=%s", pinfo->username);
    debug_p("session->password=%s", pinfo->password);
    debug_p("session->port=%d", pinfo->port);
    debug_p("session->cli_pname=%s", pinfo->cli_pname);
    debug_p("session->remote_ip=%s", pinfo->remote_ip);

    return 0;
}

int proxy_popen(const char *command)
{
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        error_p("popen failed (%s)", strerror(errno));
        return -1;
    }

    char retstr[1024];
    while (fgets(retstr, sizeof(retstr), fp) != NULL) {
        debug_p("%s", retstr);
    }

    int ret = pclose(fp);
    if(WIFEXITED(ret) && WEXITSTATUS(ret) == 0) {
        debug_p("success");
        return 0;
    }

    debug_p("failed");
    fprintf(stderr, "%s", retstr);
    return -1;
}


/**
 * \brief 通过sid验证真实服务器的用户名密码
 *
 * \param [in|out] sid
 * \param [in|out] passwd
 * \return int
 */
int proxy_auth_password(proxy_info_st *pinfo, char *sid)
{
    if (get_proxy_info_by_sid(pinfo, sid) != 0) {
        error_p("get proxy info failed, exit");
        return -1;
    }

    /* 自定义的-h选项，用来判断服务登陆是否成功，
       有些网络设备不支持exit命令，即使退出成功，退出码也是255 */
    char cmd[1024] = {0};
    snprintf(cmd, sizeof(cmd), SSH_PROXY_CMD" -h 2>&1",
             pinfo->username,
             pinfo->hostname,
             pinfo->port,
             pinfo->password);
    debug_p("cmd=%s", cmd);
    return proxy_popen(cmd);
}

proxy_info_st *proxy_info_init()
{
    mr_info_st mri = {{0}};
    if (mysql_redis_info_get(&mri)) {
        error_p("get mysql redis conf failed !!!");
        return NULL;
    }

    proxy_info_st *pinfo = (proxy_info_st *)xcalloc(1, sizeof(proxy_info_st));
    pinfo->redis_conn = redis_connect(&mri);
    pinfo->mysql_conn = mysql_connect(&mri);
    return pinfo;
}

void proxy_info_destroy(proxy_info_st *pinfo)
{
    free(pinfo);
    return ;
}

int proxy_cmd_get(char *cmd, int clen, proxy_info_st *pinfo, const char *command)
{
    const char *suffix = (command == NULL) ? "" : command;

    switch (pinfo->pt) {
    case PT_SSH:
        snprintf(cmd, clen, SSH_NOPWD_PROXY_CMD" %s", pinfo->username, pinfo->hostname, pinfo->port, suffix);
        break;
    case PT_SFTP:
        snprintf(cmd, clen, SSH_NOPWD_PROXY_CMD" -s sftp", pinfo->username, pinfo->hostname, pinfo->port);
        break;
    case PT_SCP:
        snprintf(cmd, clen, SSH_NOPWD_PROXY_CMD" %s", pinfo->username, pinfo->hostname, pinfo->port, suffix);
        break;
    case PT_FTP:
        //snprintf(cmd, clen, "/home/xiaoke/netkit-ftp/ftp/ftp -H 192.168.45.24 -u root -s %s", pinfo->password);
        break;
    case PT_RLOGIN:
        snprintf(cmd, clen, RLOGIN_PROXY_CMD, pinfo->username, pinfo->port, pinfo->hostname);
        break;
    case PT_TELNET:
        snprintf(cmd, clen, TELNET_PROXY_CMD, pinfo->username, pinfo->hostname, pinfo->port);
        break;
    default:
        debug_p("not support proxy type %s", pinfo->protocol_type);
        return -1;
    }

    debug_p("cmd => %s", cmd);
    return 0;
}

#ifdef UNITTEST_CMD_COMMON
#include "./tests/cmd-common-test.c"
#endif