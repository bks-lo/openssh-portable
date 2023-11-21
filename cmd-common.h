#ifndef __CMD_COMMON_H__
#define __CMD_COMMON_H__
#include "cmd-define.h"
int strcasecmp_r(const char *str1, int len1, const char *str2, int len2);
int login_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

int proxy_auth_password(proxy_info_st *pinfo, char *sid);

int cmd_log_send(Channel *c, const char *buf, int len);

int convert_encode_2_utf8(code_type_em from_type, char *inbuf, size_t inlen, char *outbuf, size_t *outlen);
int get_proxy_info_by_sid(proxy_info_st *pinfo, char *sid);


proxy_info_st *proxy_info_init();
void proxy_info_destroy(proxy_info_st *pinfo);

#endif