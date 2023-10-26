#ifndef __CMD_COMMON_H__
#define __CMD_COMMON_H__

int strcasecmp_r(const char *str1, int len1, const char *str2, int len2);
int login_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

int cmd_log_send(Channel *c, char *buf, int len);

#endif