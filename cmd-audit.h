#ifndef __CMD_AUDIT_H__
#define __CMD_AUDIT_H__

/**
 * \brief 根据协议类型不同，给channel上设置对应的私有数据和清理回调等。
 */
void proxy_channel_handler_set(Channel *c);

int cmd_audit_wfd_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len);

int cmd_audit_rfd_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len);

int cmd_audit_efd_read_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len);

int cmd_audit_efd_write_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len);

#endif