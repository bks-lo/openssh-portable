#ifndef __CMD_COMMON_H__
#define __CMD_COMMON_H__
#include "cmd-define.h"
#include "misc.h"
#include "xmalloc.h"

int strcasecmp_r(const char *str1, int len1, const char *str2, int len2);
int login_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

int proxy_auth_password(proxy_info_st *pinfo, char *sid);

int cmd_log_send(Channel *c, const char *buf, int len);

int convert_encode_2_utf8(code_type_em from_type, char *inbuf, size_t inlen, char *outbuf, size_t *outlen);
int get_proxy_info_by_sid(proxy_info_st *pinfo, char *sid);


proxy_info_st *proxy_info_init();
void proxy_info_destroy(proxy_info_st *pinfo);

const char *strspn_r(const char *s1, const char *s2);
int strncmp_r(const char *s1, const char *s2, int n);
int strncasecmp_r(const char *s1, const char *s2, int n);

#define PKT_GET_U64(out, data, len, err_ret) do { \
    if (len < 4) { \
        error("pkt_get_u64 need len[%d] >= 4", len); \
        return err_ret; \
    } \
    out = get_u64(data); \
    data += 8; \
    len -= 8; \
} while(0)

#define PKT_GET_U32(out, data, len, err_ret) do { \
    if (len < 4) { \
        error("pkt_get_u32 need len[%d] >= 4", len); \
        return err_ret; \
    } \
    out = get_u32(data); \
    data += 4; \
    len -= 4; \
} while(0)

#define PKT_GET_U8(out, data, len, err_ret) do { \
    if (len < 1) { \
        error("pkt_get_u8 need len[%d] >= 1", len); \
        return err_ret; \
    } \
    out = get_u8(data); \
    data += 1; \
    len -= 1; \
} while(0)


#define PKT_GET_LEN4_STRING(out_s, out_l, data, len, err_ret) do { \
    PKT_GET_U32(out_l, data, len, err_ret);      \
                                                \
    if (len < out_l) { \
        error("pkt_get_len4_string need ptk_len[%d] >= str_len[%d]", len, out_l); \
        return err_ret; \
    } \
    out_s = data; \
    data += out_l; \
    len -= out_l; \
} while(0)


#define PKT_GET_LEN1_STRING(out_s, out_l, data, len, err_ret) do { \
    PKT_GET_U8(out_l, data, len, err_ret);      \
                                                \
    if (len < out_l) { \
        error("pkt_get_len1_string need ptk_len[%d] >= str_len[%d]", len, out_l); \
        return err_ret; \
    } \
    out_s = data; \
    data += out_l; \
    len -= out_l; \
} while(0)

#endif