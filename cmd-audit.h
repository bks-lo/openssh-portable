#ifndef CMD_AUDIT_H
#define CMD_AUDIT_H

int cmd_audit_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

int cmd_audit_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

#endif