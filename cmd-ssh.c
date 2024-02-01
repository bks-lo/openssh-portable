#include <string.h>
#include <linux/types.h>
#include <stdbool.h>
#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-ssh.h"
#include "cmd-common.h"
#include "cmd-vc.h"
#include "xmalloc.h"

static struct vc_data *vc = NULL;
static struct vc_data *vc_cmd = NULL;


static int login_ok_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    if (vc == NULL) {
        vc = vc_data_creat();
        if (vc_do_resize(vc, 120, 100) != 0) {
            debug_p("vc_do_resize failed");
            return -1;
        }
        vc_data_init(vc);
    }

    do_con_write(vc, buf, len);

    sshbuf_reset(vc->prompt);
    uints_to_sshbuf(vc->vc_uni_lines[vc->state.y], vc->state.x, vc->prompt);
    debug_p("prompt [%u]>>%s", sshbuf_len(vc->prompt), sshbuf_ptr(vc->prompt));
    //snprintf(c->prompt, sizeof(c->prompt), "%s", buf);
    return 0;
}



static int wfd_cmd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    int ret = 0;

    if (vc_cmd == NULL) {
        vc_cmd = vc_data_creat();
        if (vc_do_resize(vc_cmd, 120, 100) != 0) {
            debug_p("vc_do_resize failed");
            return -1;
        }
        vc_data_init(vc_cmd);
    }

    return do_cmd_con_write(vc_cmd, buf, len);
}

static int rfd_respd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    int ret = 0;


    if (vc == NULL) {
        vc = vc_data_creat();
        if (vc_do_resize(vc, 120, 100) != 0) {
            debug_p("vc_do_resize failed");
            return -1;
        }
        vc_data_init(vc);
    }

    return do_con_write(vc, buf, len);
}

int cmd_ssh_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN_OK:
        /* 为了让rfd退出 PROXY_STATE_LOGIN_OK 状态，避免一直记录prompt */
        c->proxy_state = PROXY_STATE_CMD_START;
        // fallthrough
    case PROXY_STATE_CMD_START:
        if (vc_is_control(vc, 1, buf[0])) {
            c->proxy_state = PROXY_STATE_CMD_ECHO;
            break;
        }

        c->proxy_state = PROXY_STATE_CMD;
        // fallthrough
    case PROXY_STATE_CMD:
        wfd_cmd_handle(ssh, c, buf, len);
        break;
    default:
        fatal("state = %d, invalid", c->proxy_state);
        break;
    }


    return 0;
}

int cmd_ssh_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN:
        login_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_LOGIN_OK:
        login_ok_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_CMD:
        rfd_respd_handle(ssh, c, buf, len);
        break;
    default:
        fatal("state = %d, invalid", c->proxy_state);
        break;
    }

    return 0;
}


#ifdef UNITTEST_CMD_SSH
#include "./tests/cmd-ssh-test.c"
#endif