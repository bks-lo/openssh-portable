#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-common.h"
#include "cmd-define.h"

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

char *strip_whitespace_head(char *line)
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
    int r;
    char *line = NULL, *cp;
    size_t linesize = 0;
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
    //while (getline(&line, &linesize, fp) != -1) {
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
    //free(line);

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
             SSH_ETC_DIR, protocol_type, (is_fail ? "fail" : "ok"));

    return get_simple_file_content(lrfile, lrstr_arr, lrsize);
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
    int i = 0;
    int ret = 0;
    int lrok_num = 0;
    int lrfail_num = 0;
    char *result = NULL;
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

    result = strip_whitespace_head(buf);
    for (i = 0; i < lrfail_num; ++i) {
        if (strncasecmp(result, lrfail_arr[i], strlen(lrfail_arr[i])) == 0) {
            c->proxy_state = PROXY_STATE_LOGIN_FAILED;
            debug_p("login failed");
            break;
        }
    }

    for (i = 0; i < lrok_num; ++i) {
        if (strncasecmp(result, lrok_arr[i], strlen(lrok_arr[i])) == 0) {
            c->proxy_state = PROXY_STATE_LOGIN_OK;
            debug_p("login success 1");
            break;
        }
    }

    return 0;
}


int code_convert(char *from_charset, char *to_charset,
                 char *inbuf, size_t inlen,
                 char *outbuf, size_t outlen)
{
    //--input param judge
    if (NULL == from_charset
        || NULL == to_charset
        || NULL == inbuf
        || inlen <= 0
        || NULL == outbuf
        || outlen <= 0) {

        return -1;
    }

    //variable initial
    int ret = 0;
    iconv_t cd = {0};
    char **pin = &inbuf;
    char **pout = &outbuf;

    cd = iconv_open(to_charset, from_charset);//iconv open
    if (cd == (iconv_t)-1) {
        debug_p("iconv_open error %s",strerror(errno));
        return -1;
    }

    memset(outbuf, 0, outlen);
    if ((ret = iconv(cd, pin, &inlen, pout, &outlen)) == (size_t)-1) {
        debug_p("iconv error %s", strerror(errno));
    }
    iconv_close(cd);
    return ret;
}

int convert_encode_2_utf8(code_type_em from_type, char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
    //input param judge
    if (from_type <= 0 || NULL == inbuf || inlen <= 0 || NULL == outbuf || outlen <= 0) {
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
    proxy_info_st *pinfo = &(c->proxy_info);
    return (pinfo->encode != UTF_8);
}

char *convert_encode(Channel *c, char *inbuf, size_t inlen)
{
    proxy_info_st *pinfo = &(c->proxy_info);

    if (!need_convert) {
        return inbuf;
    }
}

int cmd_log_send(Channel *c, char *buf, int len)
{
    proxy_info_st *pinfo = &(c->proxy_info);
    if (pinfo->encode != UTF_8) {

    }
    return 0;
}


#ifdef UNITTEST_CMD_COMMON
#include "./tests/cmd-common-test.c"
#endif