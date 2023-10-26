#ifndef __CMD_AUDIT_H__
#define __CMD_AUDIT_H__

int cmd_audit_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

int cmd_audit_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

int cmd_audit_efd_read_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

int cmd_audit_efd_write_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

#endif