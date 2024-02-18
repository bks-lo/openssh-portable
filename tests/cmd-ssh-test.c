#include <check.h>

#define vcx vc->state.x
#define vcy vc->state.y
#define vce vc->vc_cols
#define STR_LEN(str)    str, sizeof(str) - 1

#define  compare_cmd_sshbuf(c, str) do {                    \
    sshbuf_reset(c->cmd);                                   \
    vc_data_to_sshbuf(c->vc, c->cmd);                       \
    ck_assert_msg(strncmp(sshbuf_ptr(c->cmd), STR_LEN(str)) == 0, "sshbuf[%s] != exp["str"]", sshbuf_ptr(c->cmd)); \
} while(0)

#define  compare_orig_cmd_sshbuf(c, str) do {               \
    ck_assert_msg(strncmp(sshbuf_ptr(c->cmd), STR_LEN(str)) == 0, "sshbuf[%s] != exp["str"]", sshbuf_ptr(c->cmd)); \
} while(0)

#define compare_prompt(c, str) do {                    \
    ck_assert_msg(strcmp(sshbuf_ptr(c->prompt), str) == 0, "sshbuf[%s] != exp["str"]", sshbuf_ptr(c->prompt)); \
} while(0)

#define compare_rspd_sshbuf(c, str) do {                    \
    sshbuf_reset(c->rspd);                                  \
    vc_data_to_sshbuf(c->vc, c->rspd);                      \
    ck_assert_msg(strcmp(sshbuf_ptr(c->rspd), str) == 0, "sshbuf[%s] != exp["str"]", sshbuf_ptr(c->rspd)); \
} while(0)

#define compare_orig_rspd_sshbuf(c, str) do {               \
    ck_assert_msg(strcmp(sshbuf_ptr(c->rspd), str) == 0, "sshbuf[%s] != exp["str"]", sshbuf_ptr(c->rspd)); \
} while(0)

#define compare_proxy_state(c, exp_state) do {              \
    ck_assert_msg(c->proxy_state == exp_state, "c->proxy_state[%d] != "#exp_state "[%d]", c->proxy_state, exp_state); \
} while(0)

static void init_ssh_channal(struct ssh *ssh, Channel *c)
{
    c->proxy_state = PROXY_STATE_NONE;
    c->vc = vc_data_creat();
    if (vc_do_resize(c->vc, 120, 100))
        fatal_f("resize vc falied");
    vc_data_init(c->vc);

    c->prompt = sshbuf_new();
    c->cmd = sshbuf_new();
    c->rspd = sshbuf_new();
}

static void free_ssh_channal(struct ssh *ssh, Channel *c)
{
    vc_data_destroy(c->vc);
    c->vc = NULL;

    sshbuf_free(c->prompt);
    sshbuf_free(c->cmd);
    sshbuf_free(c->rspd);
}

START_TEST(test_do_con_trol_ctrl_find1)
{
    struct ssh xssh = {NULL};
    Channel xc = {0};
    struct ssh *ssh = &xssh;
    Channel *c = &xc;
    init_ssh_channal(ssh, c);
    struct vc_data *vc = c->vc;


    c->proxy_state = PROXY_STATE_LOGIN_PROMPT;
    unsigned char buf0[] = {
        0x72, 0x6f, 0x6f, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x74, 0x3a, 0x7e, 0x23, 0x20
    };
    cmd_ssh_rfd_handle(ssh, c, buf0, sizeof(buf0));
    compare_prompt(c, "root@fort:~# ");

    reset_cmd_status(c);
    c->proxy_state = PROXY_STATE_CMD_ECHO;
    unsigned char buf1[] = {
        0x0d, 0x1b, 0x5b, 0x39, 0x40, 0x28, 0x72, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x2d, 0x69, 0x2d,
        0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x29, 0x60, 0x27, 0x3a, 0x1b, 0x5b, 0x43
    };
    cmd_ssh_rfd_handle(ssh, c, buf1, sizeof(buf1));
    compare_cmd_sshbuf(c, "(reverse-i-search)`':");

    unsigned char buf2[] = {
        0x08, 0x08, 0x08, 0x61, 0x27, 0x3a, 0x20, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x22, 0x61, 0x65, 0x61,
        0x65, 0x22, 0x08, 0x08, 0x08
    };
    cmd_ssh_rfd_handle(ssh, c, buf2, sizeof(buf2));
    compare_cmd_sshbuf(c, "(reverse-i-search)`a': echo \"aeae\"");

    unsigned char buf3[] = {
        0x07
    };
    cmd_ssh_rfd_handle(ssh, c, buf3, sizeof(buf3));
    compare_cmd_sshbuf(c, "(reverse-i-search)`a': echo \"aeae\"");

    unsigned char buf4[] = {
        0x08, 0x08, 0x68, 0x61, 0x68, 0x61, 0x22, 0x08, 0x08
    };
    cmd_ssh_rfd_handle(ssh, c, buf4, sizeof(buf4));
    compare_cmd_sshbuf(c, "(reverse-i-search)`a': echo \"haha\"");

    unsigned char buf5[] = {
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x1b, 0x5b, 0x31,
        0x50, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43
    };
    cmd_ssh_rfd_handle(ssh, c, buf5, sizeof(buf5));
    compare_cmd_sshbuf(c, "(reverse-i-search)`': echo \"haha\"");

    unsigned char buf6[] = {
        /*0000*/ 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x62, 0x27, 0x3a, 0x20,    // aabb
        /*0000*/ 0x63, 0x64, 0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x78, 0x69, 0x61, 0x6f, 0x6b, 0x65, 0x2f, 0x6f,    // ccdd
        /*0000*/ 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2d, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x08,    // eeff
        /*0000*/ 0x08, 0x08,                                                                                        // xxvv
    };
    cmd_ssh_rfd_handle(ssh, c, buf6, sizeof(buf6));
    compare_cmd_sshbuf(c, "(reverse-i-search)`b': cd/home/xiaoke/openssh-portable");

    free_ssh_channal(ssh, c);
}
END_TEST


START_TEST(test_do_con_trol_ctrl_echo)
{
    struct ssh xssh = {NULL};
    Channel xc = {0};
    struct ssh *ssh = &xssh;
    Channel *c = &xc;
    init_ssh_channal(ssh, c);
    struct vc_data *vc = c->vc;


    c->proxy_state = PROXY_STATE_CMD_ECHO;
    unsigned char buf1[] = {"(reverse-i-search)`ha': echo \"haha\""};
    cmd_ssh_rfd_handle(ssh, c, buf1, sizeof(buf1));
    compare_rspd_sshbuf(c, "(reverse-i-search)`ha': echo \"haha\"");

    unsigned char buf2[] = {0x0d};
    cmd_ssh_wfd_handle(ssh, c, buf2, sizeof(buf2));
    compare_rspd_sshbuf(c, "");

    //reset_rspd_status(c);
    unsigned char buf3[] = {
        /*0000*/  13,  27,  91,  49,  49,  80, 114, 111,  111, 116,  64, 102, 111, 114, 116,  58, //..[11Pro ot@fort:
        /*0010*/ 126,  35,  27,  91,  67,  27,  91,  67,   27,  91,  67,  27,  91,  67,  27,  91, //~#.[C.[C .[C.[C.[
        /*0020*/  67,  27,  91,  67,  27,  91,  67,  27,   91,  67,  27,  91,  67,  13,  10, 104, //C.[C.[C. [C.[C..h
        /*0030*/  97, 104,  97,  13,  10, 114, 111, 111,  116,  64, 102, 111, 114, 116,  58, 126, //aha..roo t@fort:~
        /*0040*/  35,  32,                                                                        //#
    };
    cmd_ssh_rfd_handle(ssh, c, buf3, sizeof(buf3));
    compare_rspd_sshbuf(c, "root@fort:~#\nhaha\nroot@fort:~# ");

    free_ssh_channal(ssh, c);
}
END_TEST

START_TEST(test_do_con_trol_ctrl_su)
{
    struct ssh xssh = {NULL};
    Channel xc = {0};
    struct ssh *ssh = &xssh;
    Channel *c = &xc;
    init_ssh_channal(ssh, c);
    struct vc_data *vc = c->vc;


    c->proxy_state = PROXY_STATE_LOGIN_PROMPT;
    unsigned char buf1[] = {
        /*0000*/  27,  91,  63,  50,  48,  48,  52, 104,   91, 115,  98, 114,  64,  86,  77,  45, //.[?2004h [sbr@VM-
        /*0010*/  52,  45,  55,  45,  99, 101, 110, 116,  111, 115,  32, 126,  93,  36,  32,      //4-7-cent os ~]$
    };
    cmd_ssh_rfd_handle(ssh, c, buf1, sizeof(buf1));
    compare_rspd_sshbuf(c, "[sbr@VM-4-7-centos ~]$ ");

    unsigned char buf2[] = {'s'};
    cmd_ssh_wfd_handle(ssh, c, buf2, sizeof(buf2));
    compare_proxy_state(c, PROXY_STATE_CMD_ECHO_START);

    unsigned char buf3[] = {"su root"};
    cmd_ssh_rfd_handle(ssh, c, buf3, sizeof(buf3) - 1);
    compare_proxy_state(c, PROXY_STATE_CMD_ECHO);
    compare_cmd_sshbuf(c, "su root");

    unsigned char buf3_1[] = {
        /*0000*/  13,                                                                             //.
    };
    cmd_ssh_wfd_handle(ssh, c, buf3_1, sizeof(buf3_1));
    compare_orig_cmd_sshbuf(c, "su root");
    compare_proxy_state(c, PROXY_STATE_RSPD);

    //reset_rspd_status(c);
    unsigned char buf4[] = {
        /*0000*/  13,  10,  27,  91,  63,  50,  48,  48,   52, 108,  13,                          //...[?200 4l.
    };
    cmd_ssh_rfd_handle(ssh, c, buf4, sizeof(buf4));
    compare_rspd_sshbuf(c, "\n");

    unsigned char buf5[] = {
        /*0000*/  80,  97, 115, 115, 119, 111, 114, 100,   58,  32,                               //Password :
    };
    cmd_ssh_rfd_handle(ssh, c, buf5, sizeof(buf5));
    compare_rspd_sshbuf(c, "\nPassword: ");

    unsigned char buf6[] = {
        /*0000*/ 106, 117, 109, 112,  49,  57,  57,  57,   64,                                    //jump1999 @
    };
    cmd_ssh_wfd_handle(ssh, c, buf6, sizeof(buf6));
    compare_proxy_state(c, PROXY_STATE_CMD);
    compare_rspd_sshbuf(c, "\nPassword: jump1999@");


    unsigned char buf7[] = {
        /*0000*/  13,                                                                             //.
    };
    cmd_ssh_wfd_handle(ssh, c, buf7, sizeof(buf7));
    compare_rspd_sshbuf(c, "root@fort:~#\nhaha\nroot@fort:~# ");
    compare_proxy_state(c, PROXY_STATE_LOGIN_PROMPT);

    unsigned char buf8[] = {
        /*0000*/  13,  10,                                                                        //..
    };
    cmd_ssh_rfd_handle(ssh, c, buf8, sizeof(buf8));
    compare_rspd_sshbuf(c, "root@fort:~#\nhaha\nroot@fort:~# ");

    unsigned char buf9[] = {
        /*0000*/  27,  91,  63,  50,  48,  48,  52, 104,   91, 114, 111, 111, 116,  64,  86,  77, //.[?2004h [root@VM
        /*0010*/  45,  52,  45,  55,  45,  99, 101, 110,  116, 111, 115,  32, 115,  98, 114,  93, //-4-7-cen tos sbr]
        /*0020*/  35,  32,                                                                        //#
    };
    cmd_ssh_rfd_handle(ssh, c, buf9, sizeof(buf9));
    compare_rspd_sshbuf(c, "root@fort:~#\nhaha\nroot@fort:~# ");


    free_ssh_channal(ssh, c);
}
END_TEST


Suite *make_suite(void)
{
	Suite *s = suite_create("test");
	TCase *tc = tcase_create("cmd-ssh-test");
    tcase_add_test(tc, test_do_con_trol_ctrl_find1);
    tcase_add_test(tc, test_do_con_trol_ctrl_echo);
    tcase_add_test(tc, test_do_con_trol_ctrl_su);

	suite_add_tcase(s, tc);
	return s;
}

int main()
{
	int nf;
	Suite *s = make_suite();
	SRunner *sr = srunner_create(s);

    log_init("cmd-ssh-test", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_DAEMON, 1);
	srunner_set_fork_status(sr, CK_NOFORK);
	srunner_run_all(sr, CK_VERBOSE);
	nf = srunner_ntests_failed(sr);

	free_ast_memory();
	srunner_free(sr);
	return nf;
}