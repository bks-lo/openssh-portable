#include <check.h>

#define vcx vc->state.x
#define vcy vc->state.y
#define vce vc->vc_cols
#define STR_LEN(str)    str, sizeof(str) - 1

#define  compare_cmd_sshbuf(ssh_pd, str) do {                    \
    struct sshbuf *cmd = sshbuf_fromd(ssh_pd->cmd);              \
    vc_data_to_sshbuf(ssh_pd->vc, cmd);                          \
    ck_assert_msg(strncmp(sshbuf_ptr(cmd), STR_LEN(str)) == 0, "sshbuf[%s] != exp["str"]", sshbuf_ptr(cmd)); \
    sshbuf_free(cmd);                                       \
} while(0)

#define  compare_orig_cmd_sshbuf(ssh_pd, str) do {               \
    ck_assert_msg(strncmp(sshbuf_ptr(ssh_pd->cmd), STR_LEN(str)) == 0, "sshbuf[%s] != exp["str"]", sshbuf_ptr(ssh_pd->cmd)); \
} while(0)

#define compare_prompt(ssh_pd, str) do {                         \
    ck_assert_msg(strcmp(sshbuf_ptr(ssh_pd->prompt), str) == 0, "sshbuf[%s] != exp["str"]", sshbuf_ptr(ssh_pd->prompt)); \
} while(0)

#define compare_rspd_sshbuf(ssh_pd, str) do {                    \
    struct sshbuf *rspd = sshbuf_fromd(ssh_pd->rspd);            \
    vc_data_to_sshbuf(ssh_pd->vc, rspd);                         \
    ck_assert_msg(strcmp(sshbuf_ptr(rspd), str) == 0, "sshbuf[%s] != exp["str"]", sshbuf_ptr(rspd)); \
    sshbuf_free(rspd);                                      \
} while(0)

#define compare_orig_rspd_sshbuf(ssh_pd, str) do {               \
    ck_assert_msg(strcmp(sshbuf_ptr(ssh_pd->rspd), str) == 0, "sshbuf[%s] != exp["str"]", sshbuf_ptr(ssh_pd->rspd)); \
} while(0)

#define compare_proxy_state(ssh_pd, exp_state) do {              \
    ck_assert_msg(c->proxy_state == exp_state, "c->proxy_state[%d] != "#exp_state "[%d]", c->proxy_state, exp_state); \
} while(0)

static void init_ssh_channal(struct ssh *ssh, Channel *c)
{
    c->proxy_state = PROXY_STATE_NONE;
    c->proxy_data = proxy_ssh_pd_create();
}

static void free_ssh_channal(struct ssh *ssh, Channel *c)
{
    proxy_ssh_pd_destroy(c->proxy_data);
}

START_TEST(test_do_con_trol_ctrl_find1)
{
    struct ssh xssh = {NULL};
    Channel xc = {0};
    struct ssh *ssh = &xssh;
    Channel *c = &xc;
    init_ssh_channal(ssh, c);
    proxy_ssh_st *ssh_pd = (proxy_ssh_st *)c->proxy_data;
    struct vc_data *vc = ssh_pd->vc;


    c->proxy_state = PROXY_STATE_LOGIN_PROMPT;
    unsigned char buf0[] = {
        0x72, 0x6f, 0x6f, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x74, 0x3a, 0x7e, 0x23, 0x20
    };
    cmd_ssh_rfd_handle(ssh, c, buf0, sizeof(buf0));
    compare_prompt(ssh_pd, "root@fort:~# ");

    reset_cmd_status(ssh_pd);
    c->proxy_state = PROXY_STATE_CMD_ECHO;
    unsigned char buf1[] = {
        0x0d, 0x1b, 0x5b, 0x39, 0x40, 0x28, 0x72, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x2d, 0x69, 0x2d,
        0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x29, 0x60, 0x27, 0x3a, 0x1b, 0x5b, 0x43
    };
    cmd_ssh_rfd_handle(ssh, c, buf1, sizeof(buf1));
    compare_cmd_sshbuf(ssh_pd, "(reverse-i-search)`':");

    unsigned char buf2[] = {
        0x08, 0x08, 0x08, 0x61, 0x27, 0x3a, 0x20, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x22, 0x61, 0x65, 0x61,
        0x65, 0x22, 0x08, 0x08, 0x08
    };
    cmd_ssh_rfd_handle(ssh, c, buf2, sizeof(buf2));
    compare_cmd_sshbuf(ssh_pd, "(reverse-i-search)`a': echo \"aeae\"");

    unsigned char buf3[] = {
        0x07
    };
    cmd_ssh_rfd_handle(ssh, c, buf3, sizeof(buf3));
    compare_cmd_sshbuf(ssh_pd, "(reverse-i-search)`a': echo \"aeae\"");

    unsigned char buf4[] = {
        0x08, 0x08, 0x68, 0x61, 0x68, 0x61, 0x22, 0x08, 0x08
    };
    cmd_ssh_rfd_handle(ssh, c, buf4, sizeof(buf4));
    compare_cmd_sshbuf(ssh_pd, "(reverse-i-search)`a': echo \"haha\"");

    unsigned char buf5[] = {
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x1b, 0x5b, 0x31,
        0x50, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43
    };
    cmd_ssh_rfd_handle(ssh, c, buf5, sizeof(buf5));
    compare_cmd_sshbuf(ssh_pd, "(reverse-i-search)`': echo \"haha\"");

    unsigned char buf6[] = {
        /*0000*/ 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x62, 0x27, 0x3a, 0x20,    // aabb
        /*0000*/ 0x63, 0x64, 0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x78, 0x69, 0x61, 0x6f, 0x6b, 0x65, 0x2f, 0x6f,    // ccdd
        /*0000*/ 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2d, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x08,    // eeff
        /*0000*/ 0x08, 0x08,                                                                                        // xxvv
    };
    cmd_ssh_rfd_handle(ssh, c, buf6, sizeof(buf6));
    compare_cmd_sshbuf(ssh_pd, "(reverse-i-search)`b': cd/home/xiaoke/openssh-portable");

    free_ssh_channal(ssh, c);
}
END_TEST


START_TEST(test_do_con_trol_ctrl_echo)
{
#if 0
    struct ssh xssh = {NULL};
    Channel xc = {0};
    struct ssh *ssh = &xssh;
    Channel *c = &xc;
    init_ssh_channal(ssh, c);
    struct vc_data *vc = c->vc;


    c->proxy_state = PROXY_STATE_CMD_ECHO;
    unsigned char buf1[] = {"(reverse-i-search)`ha': echo \"haha\""};
    cmd_ssh_rfd_handle(ssh, c, buf1, sizeof(buf1));
    compare_rspd_sshbuf(ssh_pd, "(reverse-i-search)`ha': echo \"haha\"");

    unsigned char buf2[] = {0x0d};
    cmd_ssh_wfd_handle(ssh, c, buf2, sizeof(buf2));
    compare_rspd_sshbuf(ssh_pd, "");

    //reset_rspd_status(c);
    unsigned char buf3[] = {
        /*0000*/ 0x0d, 0x1b, 0x5b, 0x31, 0x31, 0x50, 0x72, 0x6f,  0x6f, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x74, 0x3a, //..[11Pro ot@fort:
        /*0010*/ 0x7e, 0x23, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,  0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, //~#.[C.[C .[C.[C.[
        /*0020*/ 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,  0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x0d, 0x0a, 0x68, //C.[C.[C. [C.[C..h
        /*0030*/ 0x61, 0x68, 0x61, 0x0d, 0x0a, 0x72, 0x6f, 0x6f,  0x74, 0x40, 0x66, 0x6f, 0x72, 0x74, 0x3a, 0x7e, //aha..roo t@fort:~
        /*0040*/ 0x23, 0x20,                                                                                      //#
    };
    cmd_ssh_rfd_handle(ssh, c, buf3, sizeof(buf3));
    compare_rspd_sshbuf(ssh_pd, "root@fort:~#\nhaha\nroot@fort:~# ");

    free_ssh_channal(ssh, c);
#endif
    struct ssh xssh = {NULL};
    Channel xc = {0};
    struct ssh *ssh = &xssh;
    Channel *c = &xc;
    init_ssh_channal(ssh, c);
    proxy_ssh_st *ssh_pd = (proxy_ssh_st *)c->proxy_data;
    struct vc_data *vc = ssh_pd->vc;

    c->proxy_state = PROXY_STATE_LOGIN_PROMPT;

    unsigned char buf1[] = {
        /*0000*/ 0x72, 0x6f, 0x6f, 0x74, 0x40, 0x66, 0x6f, 0x72,  0x74, 0x3a, 0x7e, 0x23, 0x20,                   //root@for t:~#
    };
    cmd_ssh_rfd_handle(ssh, c, buf1, sizeof(buf1));

    unsigned char buf2[] = {
        /*0000*/ 0x12,                                                                                            //.
    };
    cmd_ssh_wfd_handle(ssh, c, buf2, sizeof(buf2));

    unsigned char buf3[] = {
        /*0000*/ 0x0d, 0x1b, 0x5b, 0x39, 0x40, 0x28, 0x72, 0x65,  0x76, 0x65, 0x72, 0x73, 0x65, 0x2d, 0x69, 0x2d, //..[9@(re verse-i-
        /*0010*/ 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x29, 0x60,  0x27, 0x3a, 0x1b, 0x5b, 0x43,                   //search)` ':.[C
    };
    cmd_ssh_rfd_handle(ssh, c, buf3, sizeof(buf3));
    compare_proxy_state(ssh_pd, PROXY_STATE_CMD_ECHO);
    compare_rspd_sshbuf(ssh_pd, "(reverse-i-search)`':");

    unsigned char buf4[] = {
        /*0000*/ 0x08, 0x08, 0x08, 0x68, 0x27, 0x3a, 0x20, 0x65,  0x63, 0x68, 0x6f, 0x20, 0x22, 0x68, 0x61, 0x68, //...h': e cho "hah
        /*0010*/ 0x61, 0x22, 0x08, 0x08, 0x08,                                                                    //a"...
    };
    cmd_ssh_rfd_handle(ssh, c, buf4, sizeof(buf4));
    compare_rspd_sshbuf(ssh_pd, "(reverse-i-search)`h': echo \"haha\"");


    unsigned char buf5[] = {
        /*0000*/ 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,  0x08, 0x08, 0x08, 0x1b, 0x5b, 0x31, 0x40, 0x61, //........ ....[1@a
        /*0010*/ 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b,  0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, //.[C.[C.[ C.[C.[C.
        /*0020*/ 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,  0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, //[C.[C.[C .[C.[C.[
        /*0030*/ 0x43,                                                                                            //C

    };
    cmd_ssh_rfd_handle(ssh, c, buf5, sizeof(buf5));
    compare_rspd_sshbuf(ssh_pd, "(reverse-i-search)`ha': echo \"haha\"");

    unsigned char buf6[] = {
        /*0000*/ 0x0d,                                                                                            //.
    };
    cmd_ssh_wfd_handle(ssh, c, buf6, sizeof(buf6));

    unsigned char buf7[] = {
        /*0000*/ 0x0d, 0x1b, 0x5b, 0x31, 0x31, 0x50, 0x72, 0x6f,  0x6f, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x74, 0x3a, //..[11Pro ot@fort:
        /*0010*/ 0x7e, 0x23, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,  0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, //~#.[C.[C .[C.[C.[
        /*0020*/ 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,  0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x0d, 0x0a, 0x68, //C.[C.[C. [C.[C..h
        /*0030*/ 0x61, 0x68, 0x61, 0x0d, 0x0a, 0x72, 0x6f, 0x6f,  0x74, 0x40, 0x66, 0x6f, 0x72, 0x74, 0x3a, 0x7e, //aha..roo t@fort:~
        /*0040*/ 0x23, 0x20,                                                                                      //#
    };
    cmd_ssh_rfd_handle(ssh, c, buf7, sizeof(buf7));
    /*
      这里真正的预期 "root@fort:~# echo \"haha\"\nhaha\nroot@fort:~# "
      因为状态转换过，导致vc缓存都被清理
    */
    compare_rspd_sshbuf(ssh_pd, "root@fort:~#\nhaha\nroot@fort:~# ");


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
    proxy_ssh_st *ssh_pd = (proxy_ssh_st *)c->proxy_data;
    struct vc_data *vc = ssh_pd->vc;


    c->proxy_state = PROXY_STATE_LOGIN_PROMPT;
    unsigned char buf1[] = {
        /*0000*/  27,  91,  63,  50,  48,  48,  52, 104,   91, 115,  98, 114,  64,  86,  77,  45, //.[?2004h [sbr@VM-
        /*0010*/  52,  45,  55,  45,  99, 101, 110, 116,  111, 115,  32, 126,  93,  36,  32,      //4-7-cent os ~]$
    };
    cmd_ssh_rfd_handle(ssh, c, buf1, sizeof(buf1));
    compare_rspd_sshbuf(ssh_pd, "[sbr@VM-4-7-centos ~]$ ");

    unsigned char buf2[] = {'s'};
    cmd_ssh_wfd_handle(ssh, c, buf2, sizeof(buf2));
    compare_proxy_state(ssh_pd, PROXY_STATE_CMD_ECHO_START);

    unsigned char buf3[] = {"su root"};
    cmd_ssh_rfd_handle(ssh, c, buf3, sizeof(buf3) - 1);
    compare_proxy_state(ssh_pd, PROXY_STATE_CMD_ECHO);
    compare_cmd_sshbuf(ssh_pd, "su root");

    unsigned char buf3_1[] = {
        /*0000*/  13,                                                                             //.
    };
    cmd_ssh_wfd_handle(ssh, c, buf3_1, sizeof(buf3_1));
    compare_orig_cmd_sshbuf(ssh_pd, "su root");
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    //reset_rspd_status(c);
    unsigned char buf4[] = {
        /*0000*/  13,  10,  27,  91,  63,  50,  48,  48,   52, 108,  13,                          //...[?200 4l.
    };
    cmd_ssh_rfd_handle(ssh, c, buf4, sizeof(buf4));

    unsigned char buf5[] = {
        /*0000*/  80,  97, 115, 115, 119, 111, 114, 100,   58,  32,                               //Password :
    };
    cmd_ssh_rfd_handle(ssh, c, buf5, sizeof(buf5));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    unsigned char buf6[] = {
        /*0000*/ 106, 117, 109, 112,  49,  57,  57,  57,   64,                                    //jump1999 @
    };
    cmd_ssh_wfd_handle(ssh, c, buf6, sizeof(buf6));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD_INPUT);
    compare_orig_rspd_sshbuf(ssh_pd, "\nPassword: ");


    unsigned char buf7[] = {
        /*0000*/  13,                                                                             //.
    };
    cmd_ssh_wfd_handle(ssh, c, buf7, sizeof(buf7));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    unsigned char buf8[] = {
        /*0000*/  13,  10,                                                                        //..
    };
    cmd_ssh_rfd_handle(ssh, c, buf8, sizeof(buf8));
    //compare_orig_rspd_sshbuf(ssh_pd, "\nPassword: \n");

    unsigned char buf9[] = {
        /*0000*/  27,  91,  63,  50,  48,  48,  52, 104,   91, 114, 111, 111, 116,  64,  86,  77, //.[?2004h [root@VM
        /*0010*/  45,  52,  45,  55,  45,  99, 101, 110,  116, 111, 115,  32, 115,  98, 114,  93, //-4-7-cen tos sbr]
        /*0020*/  35,  32,                                                                        //#
    };
    cmd_ssh_rfd_handle(ssh, c, buf9, sizeof(buf9));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);
    compare_rspd_sshbuf(ssh_pd, "\nPassword: \n[root@VM-4-7-centos sbr]# ");

    unsigned char buf10[] = {
        /*0000*/  'h', 'a', '\r'
    };
    cmd_ssh_wfd_handle(ssh, c, buf10, sizeof(buf10));
    compare_proxy_state(ssh_pd, PROXY_STATE_CMD);
    compare_cmd_sshbuf(ssh_pd, "ha");

    free_ssh_channal(ssh, c);
}
END_TEST

START_TEST(test_do_con_trol_ctrl_adduser)
{
    struct ssh xssh = {NULL};
    Channel xc = {0};
    struct ssh *ssh = &xssh;
    Channel *c = &xc;
    init_ssh_channal(ssh, c);
    proxy_ssh_st *ssh_pd = (proxy_ssh_st *)c->proxy_data;
    struct vc_data *vc = ssh_pd->vc;


    c->proxy_state = PROXY_STATE_LOGIN_PROMPT;
    unsigned char buf1[] = {
        /*0000*/ 0x72, 0x6f, 0x6f, 0x74, 0x40, 0x66, 0x6f, 0x72,  0x74, 0x3a, 0x7e, 0x23, 0x20,                   //root@for t:~#
    };
    cmd_ssh_rfd_handle(ssh, c, buf1, sizeof(buf1));
    compare_rspd_sshbuf(ssh_pd, "root@fort:~# ");

    unsigned char buf2[] = {'a'};
    cmd_ssh_wfd_handle(ssh, c, buf2, sizeof(buf2));
    compare_proxy_state(ssh_pd, PROXY_STATE_CMD_ECHO_START);

    unsigned char buf3[] = {"adduser test4"};
    cmd_ssh_rfd_handle(ssh, c, buf3, sizeof(buf3) - 1);
    compare_proxy_state(ssh_pd, PROXY_STATE_CMD_ECHO);
    compare_cmd_sshbuf(ssh_pd, "adduser test4");

    unsigned char buf3_1[] = {
        /*0000*/  13,                                                                             //.
    };
    cmd_ssh_wfd_handle(ssh, c, buf3_1, sizeof(buf3_1));
    compare_orig_cmd_sshbuf(ssh_pd, "adduser test4");
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    //reset_rspd_status(c);
    unsigned char buf4[] = {
        /*0000*/ 0x41, 0x64, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x75,  0x73, 0x65, 0x72, 0x20, 0x60, 0x74, 0x65, 0x73, //Adding u ser `tes
        /*0010*/ 0x74, 0x34, 0x27, 0x20, 0x2e, 0x2e, 0x2e, 0x0d,  0x0a, 0x41, 0x64, 0x64, 0x69, 0x6e, 0x67, 0x20, //t4' .... .Adding
        /*0020*/ 0x6e, 0x65, 0x77, 0x20, 0x67, 0x72, 0x6f, 0x75,  0x70, 0x20, 0x60, 0x74, 0x65, 0x73, 0x74, 0x34, //new grou p `test4
        /*0030*/ 0x27, 0x20, 0x28, 0x31, 0x30, 0x30, 0x38, 0x29,  0x20, 0x2e, 0x2e, 0x2e, 0x0d, 0x0a,             //' (1008)  .....
    };
    cmd_ssh_rfd_handle(ssh, c, buf4, sizeof(buf4));
    compare_rspd_sshbuf(ssh_pd, "Adding user `test4' ...\n"
                            "Adding new group `test4' (1008) ...\n");

    unsigned char buf5[] = {
        /*0000*/ 0x41, 0x64, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x6e,  0x65, 0x77, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, //Adding n ew user
        /*0010*/ 0x60, 0x74, 0x65, 0x73, 0x74, 0x34, 0x27, 0x20,  0x28, 0x31, 0x30, 0x30, 0x37, 0x29, 0x20, 0x77, //`test4'  (1007) w
        /*0020*/ 0x69, 0x74, 0x68, 0x20, 0x67, 0x72, 0x6f, 0x75,  0x70, 0x20, 0x60, 0x74, 0x65, 0x73, 0x74, 0x34, //ith grou p `test4
        /*0030*/ 0x27, 0x20, 0x2e, 0x2e, 0x2e, 0x0d, 0x0a,                                                        //' .....
    };
    cmd_ssh_rfd_handle(ssh, c, buf5, sizeof(buf5));
    compare_rspd_sshbuf(ssh_pd, "Adding user `test4' ...\n"
                            "Adding new group `test4' (1008) ...\n"
                            "Adding new user `test4' (1007) with group `test4' ...\n");

    unsigned char buf6[] = {
        /*0000*/ 0x43, 0x72, 0x65, 0x61, 0x74, 0x69, 0x6e, 0x67,  0x20, 0x68, 0x6f, 0x6d, 0x65, 0x20, 0x64, 0x69, //Creating  home di
        /*0010*/ 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x20,  0x60, 0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x74, //rectory  `/home/t
        /*0020*/ 0x65, 0x73, 0x74, 0x34, 0x27, 0x20, 0x2e, 0x2e,  0x2e, 0x0d, 0x0a,                               //est4' .. ...
    };
    cmd_ssh_rfd_handle(ssh, c, buf6, sizeof(buf6));
    compare_rspd_sshbuf(ssh_pd, "Adding user `test4' ...\n"
                            "Adding new group `test4' (1008) ...\n"
                            "Adding new user `test4' (1007) with group `test4' ...\n"
                            "Creating home directory `/home/test4' ...\n");

    unsigned char buf7[] = {
        /*0000*/ 0x43, 0x6f, 0x70, 0x79, 0x69, 0x6e, 0x67, 0x20,  0x66, 0x69, 0x6c, 0x65, 0x73, 0x20, 0x66, 0x72, //Copying  files fr
        /*0010*/ 0x6f, 0x6d, 0x20, 0x60, 0x2f, 0x65, 0x74, 0x63,  0x2f, 0x73, 0x6b, 0x65, 0x6c, 0x27, 0x20, 0x2e, //om `/etc /skel' .
        /*0020*/ 0x2e, 0x2e, 0x0d, 0x0a,                                                                          //....
    };
    cmd_ssh_rfd_handle(ssh, c, buf7, sizeof(buf7));
    compare_rspd_sshbuf(ssh_pd, "Adding user `test4' ...\n"
                            "Adding new group `test4' (1008) ...\n"
                            "Adding new user `test4' (1007) with group `test4' ...\n"
                            "Creating home directory `/home/test4' ...\n"
                            "Copying files from `/etc/skel' ...\n");

    unsigned char buf8[] = {
        /*0000*/ 0x45, 0x6e, 0x74, 0x65, 0x72, 0x20, 0x6e, 0x65,  0x77, 0x20, 0x55, 0x4e, 0x49, 0x58, 0x20, 0x70, //Enter ne w UNIX p
        /*0010*/ 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x3a,  0x20,                                           //assword:
    };
    cmd_ssh_rfd_handle(ssh, c, buf8, sizeof(buf8));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);
    compare_rspd_sshbuf(ssh_pd,  "Adding user `test4' ...\n"
                            "Adding new group `test4' (1008) ...\n"
                            "Adding new user `test4' (1007) with group `test4' ...\n"
                            "Creating home directory `/home/test4' ...\n"
                            "Copying files from `/etc/skel' ...\n"
                            "Enter new UNIX password: ");

    unsigned char buf9[] = { "aabbcc" };
    cmd_ssh_wfd_handle(ssh, c, buf9, sizeof(buf9) - 1);
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD_INPUT);

    unsigned char buf9_1[] = { "\r" };
    cmd_ssh_wfd_handle(ssh, c, buf9_1, sizeof(buf9_1) - 1);
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    unsigned char buf10[] = {
        /*0000*/ 0x0d, 0x0a, 0x52, 0x65, 0x74, 0x79, 0x70, 0x65,  0x20, 0x6e, 0x65, 0x77, 0x20, 0x55, 0x4e, 0x49, //..Retype  new UNI
        /*0010*/ 0x58, 0x20, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f,  0x72, 0x64, 0x3a, 0x20,                         //X passwo rd:
    };
    cmd_ssh_rfd_handle(ssh, c, buf10, sizeof(buf10));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);
    compare_rspd_sshbuf(ssh_pd, "Adding user `test4' ...\n"
                            "Adding new group `test4' (1008) ...\n"
                            "Adding new user `test4' (1007) with group `test4' ...\n"
                            "Creating home directory `/home/test4' ...\n"
                            "Copying files from `/etc/skel' ...\n"
                            "Enter new UNIX password: \n"
                            "Retype new UNIX password: ");

    unsigned char buf10_1[] = {
        /*0000*/ 0x0d, 0x0a
    };
    cmd_ssh_rfd_handle(ssh, c, buf10_1, sizeof(buf10_1));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    unsigned char buf11[] = {
        /*0000*/ 0x70, 0x61, 0x73, 0x73, 0x77, 0x64, 0x3a, 0x20,  0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, //passwd:  password
        /*0010*/ 0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64,  0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, // updated  success
        /*0020*/ 0x66, 0x75, 0x6c, 0x6c, 0x79, 0x0d, 0x0a,                                                        //fully..
    };
    cmd_ssh_rfd_handle(ssh, c, buf11, sizeof(buf11));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    unsigned char buf12[] = {
        /*0000*/ 0x43, 0x68, 0x61, 0x6e, 0x67, 0x69, 0x6e, 0x67,  0x20, 0x74, 0x68, 0x65, 0x20, 0x75, 0x73, 0x65, //Changing  the use
        /*0010*/ 0x72, 0x20, 0x69, 0x6e, 0x66, 0x6f, 0x72, 0x6d,  0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x6f, //r inform ation fo
        /*0020*/ 0x72, 0x20, 0x74, 0x65, 0x73, 0x74, 0x34, 0x0d,  0x0a, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x20, 0x74, //r test4. .Enter t
        /*0030*/ 0x68, 0x65, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x76,  0x61, 0x6c, 0x75, 0x65, 0x2c, 0x20, 0x6f, 0x72, //he new v alue, or
        /*0040*/ 0x20, 0x70, 0x72, 0x65, 0x73, 0x73, 0x20, 0x45,  0x4e, 0x54, 0x45, 0x52, 0x20, 0x66, 0x6f, 0x72, // press E NTER for
        /*0050*/ 0x20, 0x74, 0x68, 0x65, 0x20, 0x64, 0x65, 0x66,  0x61, 0x75, 0x6c, 0x74, 0x0d, 0x0a, 0x09, 0x46, // the def ault...F
        /*0060*/ 0x75, 0x6c, 0x6c, 0x20, 0x4e, 0x61, 0x6d, 0x65,  0x20, 0x5b, 0x5d, 0x3a, 0x20,                   //ull Name  []:
    };
    cmd_ssh_rfd_handle(ssh, c, buf12, sizeof(buf12));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);
    compare_rspd_sshbuf(ssh_pd, "Adding user `test4' ...\n"
                            "Adding new group `test4' (1008) ...\n"
                            "Adding new user `test4' (1007) with group `test4' ...\n"
                            "Creating home directory `/home/test4' ...\n"
                            "Copying files from `/etc/skel' ...\n"
                            "Enter new UNIX password: \n"
                            "Retype new UNIX password: \n"
                            "passwd: password updated successfully\n"
                            "Changing the user information for test4\n"
                            "Enter the new value, or press ENTER for the default\n"
                            "Full Name []: ");

    unsigned char buf13_1[] = { 'a' };
    cmd_ssh_wfd_handle(ssh, c, buf13_1, sizeof(buf13_1));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD_INPUT);

    unsigned char buf13_2[] = { 'a' };
    cmd_ssh_rfd_handle(ssh, c, buf13_2, sizeof(buf13_2));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD_INPUT);

    unsigned char buf13_3[] = { 'a' };
    cmd_ssh_wfd_handle(ssh, c, buf13_3, sizeof(buf13_3));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD_INPUT);

    unsigned char buf13_4[] = { 'a' };
    cmd_ssh_rfd_handle(ssh, c, buf13_4, sizeof(buf13_4));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD_INPUT);

    unsigned char buf13_5[] = { 'a' };
    cmd_ssh_wfd_handle(ssh, c, buf13_5, sizeof(buf13_5));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD_INPUT);

    unsigned char buf13_6[] = { 'a' };
    cmd_ssh_rfd_handle(ssh, c, buf13_6, sizeof(buf13_6));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD_INPUT);

    unsigned char buf13_7[] = { '\r' };
    cmd_ssh_wfd_handle(ssh, c, buf13_7, sizeof(buf13_7));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    compare_rspd_sshbuf(ssh_pd, "Adding user `test4' ...\n"
                            "Adding new group `test4' (1008) ...\n"
                            "Adding new user `test4' (1007) with group `test4' ...\n"
                            "Creating home directory `/home/test4' ...\n"
                            "Copying files from `/etc/skel' ...\n"
                            "Enter new UNIX password: \n"
                            "Retype new UNIX password: \n"
                            "passwd: password updated successfully\n"
                            "Changing the user information for test4\n"
                            "Enter the new value, or press ENTER for the default\n"
                            "Full Name []: aaa");

    unsigned char buf14[] = {
        /*0000*/ 0x0d, 0x0a, 0x09, 0x52, 0x6f, 0x6f, 0x6d, 0x20,  0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x20, 0x5b, //...Room  Number [
        /*0010*/ 0x5d, 0x3a, 0x20,                                                                                //]:
    };
    cmd_ssh_rfd_handle(ssh, c, buf14, sizeof(buf14));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    unsigned char buf15[] = {
        'b', 'b', 'b'
    };
    cmd_ssh_rfd_handle(ssh, c, buf15, sizeof(buf15));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    unsigned char buf16[] = {
        /*0000*/ 0x0d, 0x0a, 0x09, 0x57, 0x6f, 0x72, 0x6b, 0x20,  0x50, 0x68, 0x6f, 0x6e, 0x65, 0x20, 0x5b, 0x5d, //...Work  Phone []
        /*0010*/ 0x3a, 0x20,                                                                                      //:
    };
    cmd_ssh_rfd_handle(ssh, c, buf16, sizeof(buf16));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    unsigned char buf17[] = {
        'c', 'c', 'c'
    };
    cmd_ssh_rfd_handle(ssh, c, buf17, sizeof(buf17));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    unsigned char buf18[] = {
        /*0000*/ 0x0d, 0x0a, 0x09, 0x48, 0x6f, 0x6d, 0x65, 0x20,  0x50, 0x68, 0x6f, 0x6e, 0x65, 0x20, 0x5b, 0x5d, //...Home  Phone []
        /*0010*/ 0x3a, 0x20,                                                                                      //:
    };
    cmd_ssh_rfd_handle(ssh, c, buf18, sizeof(buf18));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    unsigned char buf19[] = {
        'd', 'd', 'd'
    };
    cmd_ssh_rfd_handle(ssh, c, buf19, sizeof(buf19));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    unsigned char buf20[] = {
        /*0000*/ 0x0d, 0x0a, 0x09, 0x4f, 0x74, 0x68, 0x65, 0x72,  0x20, 0x5b, 0x5d, 0x3a, 0x20,                   //...Other  []:
    };
    cmd_ssh_rfd_handle(ssh, c, buf20, sizeof(buf20));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);

    unsigned char buf21[] = {
        'e', 'e', 'e'
    };
    cmd_ssh_rfd_handle(ssh, c, buf21, sizeof(buf21));
    compare_proxy_state(ssh_pd, PROXY_STATE_RSPD);
    compare_rspd_sshbuf(ssh_pd, "Adding user `test4' ...\n"
                            "Adding new group `test4' (1008) ...\n"
                            "Adding new user `test4' (1007) with group `test4' ...\n"
                            "Creating home directory `/home/test4' ...\n"
                            "Copying files from `/etc/skel' ...\n"
                            "Enter new UNIX password: \n"
                            "Retype new UNIX password: \n"
                            "passwd: password updated successfully\n"
                            "Changing the user information for test4\n"
                            "Enter the new value, or press ENTER for the default\n"
                            "Full Name []: aaa\n"
                            "Room Number []: bbb\n"
                            "Work Phone []: ccc\n"
                            "Home Phone []: ddd\n"
                            "Other []: eee");


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
    tcase_add_test(tc, test_do_con_trol_ctrl_adduser);

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


	srunner_free(sr);
	return nf;
}