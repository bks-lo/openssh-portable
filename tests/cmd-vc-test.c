#include <check.h>

#define vcx vc->state.x
#define vcy vc->state.y
#define vce vc->vc_cols
#define STR_LEN(str)    str, sizeof(str) - 1

#define compare_n_sshbuf(y, x, str) do {          \
    struct sshbuf *sbuf = sshbuf_new();                 \
    sshbuf_reset(sbuf);                                 \
    uints_to_sshbuf(vc->vc_uni_lines[y], x, sbuf);      \
    ck_assert_msg(strncmp(sshbuf_ptr(sbuf), STR_LEN(str)) == 0, "sshbuf[%s] != exp["str"]", sshbuf_ptr(sbuf)); \
    sshbuf_free(sbuf);                                  \
} while(0)

#define compare_sshbuf(y, x, str) do {          \
    struct sshbuf *sbuf = sshbuf_new();                 \
    sshbuf_reset(sbuf);                                 \
    uints_to_sshbuf(vc->vc_uni_lines[y], x, sbuf);      \
    ck_assert_msg(strcmp(sshbuf_ptr(sbuf), str) == 0, "sshbuf[%s] != exp["str"]", sshbuf_ptr(sbuf)); \
    sshbuf_free(sbuf);                                  \
} while(0)


START_TEST(test_do_con_trol)
{
    struct vc_data *vc = vc_data_creat();
    int ret = vc_do_resize(vc, 80, 50);
    ck_assert_msg(ret == 0, "ret != 0", ret);
    ck_assert_msg(vc->vc_cols == 80, "vc->vc_cols = %u", vc->vc_cols);

    vc_data_init(vc);
    ck_assert_msg(vc->vc_size_row == vc->vc_cols << 1, "vc_size_row = %u, vc_cols = %d", vc->vc_size_row, vc->vc_cols);
    ck_assert_msg(vc->vc_screenbuf_size == vc->vc_rows * vc->vc_size_row, "vc_screenbuf_size = %u", vc->vc_screenbuf_size);

    unsigned char buf[] = {"cd /home/xiaoke"};
    do_rspd_con_write(vc, buf, sizeof(buf) - 1);
    compare_sshbuf(0, vcx, "cd /home/xiaoke");

    unsigned char buf1[] = {0x1b, 0x5b, 0x3f, 0x32, 0x30, 0x30, 0x34, 0x6c};
    do_rspd_con_write(vc, buf1, sizeof(buf1));
    compare_sshbuf(0, vce, "cd /home/xiaoke");

    unsigned char buf2[] = {0x1b, 0x5b, 0x30, 0x6d};
    do_rspd_con_write(vc, buf2, sizeof(buf2));
    compare_sshbuf(0, vce, "cd /home/xiaoke");

    unsigned char buf3[] = {0x1b, 0x5b, 0x30, 0x31, 0x3b, 0x33, 0x34, 0x6d};
    do_rspd_con_write(vc, buf3, sizeof(buf3));
    compare_sshbuf(0, vce, "cd /home/xiaoke");

    unsigned char buf4[] = {0x1b, 0x5b, 0x30, 0x31, 0x3b, 0x33, 0x34, 0x6d};
    do_rspd_con_write(vc, buf4, sizeof(buf4));
    compare_sshbuf(0, vce, "cd /home/xiaoke");

    vc_data_destroy(vc);
}
END_TEST

START_TEST(test_conv_uni_to_pc)
{
    struct vc_data *vc = vc_data_creat();
    int ret = vc_do_resize(vc, 80, 50);
    ck_assert_msg(ret == 0, "ret != 0", ret);
    ck_assert_msg(vc->vc_cols == 80, "vc->vc_cols = %u", vc->vc_cols);

    vc_data_init(vc);
    ck_assert_msg(vc->vc_size_row == vc->vc_cols << 1, "vc_size_row = %u, vc_cols = %d", vc->vc_size_row, vc->vc_cols);
    ck_assert_msg(vc->vc_screenbuf_size == vc->vc_rows * vc->vc_size_row, "vc_screenbuf_size = %u", vc->vc_screenbuf_size);
    ck_assert_msg(vc->uni_pagedict_loc != NULL, "vc->uni_pagedict_loc == NULL");

    long c = 'a';
    int cc = conv_uni_to_pc(vc, c);
    ck_assert_msg(cc == c, "cc[%c] != c", cc);

    c = 0x27;
    cc = conv_uni_to_pc(vc, c);
    ck_assert_msg(cc == c, "cc[%c] != c", cc);
    vc_data_destroy(vc);
}
END_TEST

START_TEST(test_do_con_trol_dbmy)
{
    struct vc_data *vc = vc_data_creat();
    int ret = vc_do_resize(vc, 80, 50);
    ck_assert_msg(ret == 0, "ret != 0", ret);
    ck_assert_msg(vc->vc_cols == 80, "vc->vc_cols = %u", vc->vc_cols);

    vc_data_init(vc);
    ck_assert_msg(vc->vc_size_row == vc->vc_cols << 1, "vc_size_row = %u, vc_cols = %d", vc->vc_size_row, vc->vc_cols);
    ck_assert_msg(vc->vc_screenbuf_size == vc->vc_rows * vc->vc_size_row, "vc_screenbuf_size = %u", vc->vc_screenbuf_size);

    unsigned char buf1[] = {0x72, 0x6f, 0x6f, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x74, 0x3a, 0x7e, 0x23, 0x20};      // root@fort:~#
    do_rspd_con_write(vc, buf1, sizeof(buf1));
    compare_sshbuf(0, vce, "root@fort:~# ");

    unsigned char buf2[] = {
        0x63, 0x64, 0x20, 0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x78, 0x69, 0x61, 0x6f, 0x6b, 0x65, 0x2f,
        0x64, 0x62, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2d,
        0x70, 0x6f, 0x72, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x2f
    };
    do_rspd_con_write(vc, buf2, sizeof(buf2));
    compare_sshbuf(0, vce, "root@fort:~# cd /home/xiaoke/dbproxy/openssh-portable/");

    unsigned char buf3[] = {
        0x0d, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43
    };
    do_rspd_con_write(vc, buf3, sizeof(buf3));
    compare_n_sshbuf(0, vce, "root@fort:~# ");

    unsigned char buf4[] = {
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43
    };
    do_rspd_con_write(vc, buf4, sizeof(buf4));
    compare_n_sshbuf(0, vce, "root@fort:~# cd ");

    unsigned char buf5[] = {
        0x08, 0x1b, 0x5b, 0x31, 0x50, 0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x78, 0x69, 0x61, 0x6f, 0x6b,
        0x65, 0x2f, 0x64, 0x62, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73,
        0x68, 0x2d, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x2f, 0x0d, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b,
        0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43
    };
    do_rspd_con_write(vc, buf5, sizeof(buf5));
    compare_sshbuf(0, vce, "root@fort:~# cd/home/xiaoke/dbproxy/openssh-portable/");

    unsigned char buf6[] = {
        0x20, 0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x78, 0x69, 0x61, 0x6f, 0x6b, 0x65, 0x2f, 0x64, 0x62,
        0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2d, 0x70, 0x6f,
        0x72, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x2f, 0x0d, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b,
        0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43
    };
    do_rspd_con_write(vc, buf6, sizeof(buf6));
    compare_sshbuf(0, vce, "root@fort:~# cd /home/xiaoke/dbproxy/openssh-portable/");

    unsigned char buf7[] = {
        0x20, 0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x78, 0x69, 0x61, 0x6f, 0x6b, 0x65, 0x2f, 0x64, 0x62,
        0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2d, 0x70, 0x6f,
        0x72, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x2f, 0x0d, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b,
        0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43
    };
    do_rspd_con_write(vc, buf7, sizeof(buf7));
    compare_sshbuf(0, vce, "root@fort:~# cd  /home/xiaoke/dbproxy/openssh-portable/");
    vc_data_destroy(vc);
}
END_TEST

START_TEST(test_do_con_trol_tencent)
{
    struct vc_data *vc = vc_data_creat();
    int ret = vc_do_resize(vc, 100, 50);
    ck_assert_msg(ret == 0, "ret != 0", ret);
    ck_assert_msg(vc->vc_cols == 100, "vc->vc_cols = %u", vc->vc_cols);

    vc_data_init(vc);
    ck_assert_msg(vc->vc_size_row == vc->vc_cols << 1, "vc_size_row = %u, vc_cols = %d", vc->vc_size_row, vc->vc_cols);
    ck_assert_msg(vc->vc_screenbuf_size == vc->vc_rows * vc->vc_size_row, "vc_screenbuf_size = %u", vc->vc_screenbuf_size);

    unsigned char buf1[] = {
        0x1b, 0x5b, 0x3f, 0x32, 0x30, 0x30, 0x34, 0x68, 0x5b, 0x72, 0x6f, 0x6f, 0x74, 0x40, 0x56, 0x4d,
        0x2d, 0x34, 0x2d, 0x37, 0x2d, 0x63, 0x65, 0x6e, 0x74, 0x6f, 0x73, 0x20, 0x7e, 0x5d, 0x23, 0x20
    };      // [root@VM-4-7-centos ~]#
    do_rspd_con_write(vc, buf1, sizeof(buf1));
    compare_sshbuf(0, vce, "[root@VM-4-7-centos ~]# ");

    unsigned char buf1_2[] = {
        0x65, 0x78, 0x69, 0x74
    };  // exit
    do_rspd_con_write(vc, buf1_2, sizeof(buf1_2));
    compare_sshbuf(0, vce, "[root@VM-4-7-centos ~]# exit");

    unsigned char buf2[] = {
        0x08, 0x08, 0x08, 0x08, 0x61, 0x74, 0x20, 0x2f, 0x62, 0x6f, 0x6f, 0x74, 0x2f, 0x63, 0x6f, 0x6e,
        0x66, 0x69, 0x67, 0x2d, 0x2a, 0x20, 0x7c, 0x20, 0x67, 0x72, 0x65, 0x70, 0x20, 0x43, 0x4f, 0x4e,
        0x46, 0x49, 0x47, 0x5f, 0x43, 0x4f, 0x4e, 0x53, 0x4f, 0x4c, 0x45, 0x5f, 0x54, 0x52, 0x41, 0x4e,
        0x53, 0x4c, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x53
    };  //[root@VM-4-7-centos ~]# at /boot/config-* | grep CONFIG_CONSOLE_TRANSLATIONS
    do_rspd_con_write(vc, buf2, sizeof(buf2));
    compare_sshbuf(0, vce, "[root@VM-4-7-centos ~]# at /boot/config-* | grep CONFIG_CONSOLE_TRANSLATIONS");

    unsigned char buf3[] = {
        0x0d, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b,
        0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x31, 0x40, 0x63, 0x1b, 0x5b,
        0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b,
        0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b,
        0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b,
        0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43
    };      //[root@VM-4-7-centos ~]# cat /boot/config-* | grep CONFIG_CONSOLE_TRANSLATIONS
    do_rspd_con_write(vc, buf3, sizeof(buf3));
    compare_sshbuf(0, vce, "[root@VM-4-7-centos ~]# cat /boot/config-* | grep CONFIG_CONSOLE_TRANSLATIONS");

    unsigned char buf5[] = {
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
        0x08, 0x08, 0x08, 0x08, 0x08, 0x1b, 0x5b, 0x33, 0x40, 0x61, 0x61, 0x61, 0x61, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b,
        0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b,
        0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43
    };      //[root@VM-4-7-centos ~]# cat /boot/configaaaa* | grep CONFIG_CONSOLE_TRANSLATIONS
    do_rspd_con_write(vc, buf5, sizeof(buf5));
    compare_sshbuf(0, vce, "[root@VM-4-7-centos ~]# cat /boot/configaaaa* | grep CONFIG_CONSOLE_TRANSLATIONS");

    unsigned char buf6[] = {
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
        0x08, 0x08, 0x08, 0x08, 0x1b, 0x5b, 0x4b
    };      //[root@VM-4-7-centos ~]# cat /boot/configaaaa
    do_rspd_con_write(vc, buf6, sizeof(buf6));
    compare_n_sshbuf(0, vce, "[root@VM-4-7-centos ~]# cat /boot/configaaaa");

    unsigned char buf7[] = {
        0x0d, 0x0a, 0x1b, 0x5b, 0x3f, 0x32, 0x30, 0x30, 0x34, 0x6c, 0x0d, 0x63, 0x61, 0x74, 0x3a, 0x20,
        0x2f, 0x62, 0x6f, 0x6f, 0x74, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x61, 0x61, 0x61, 0x61,
        0x3a, 0x20, 0xc3, 0xbb, 0xd3, 0xd0, 0xc4, 0xc7, 0xb8, 0xf6, 0xce, 0xc4, 0xbc, 0xfe, 0xbb, 0xf2,
        0xc4, 0xbf, 0xc2, 0xbc, 0x0d, 0x0a, 0x1b, 0x5b, 0x3f, 0x32, 0x30, 0x30, 0x34, 0x68, 0x5b, 0x72,
        0x6f, 0x6f, 0x74, 0x40, 0x56, 0x4d, 0x2d, 0x34, 0x2d, 0x37, 0x2d, 0x63, 0x65, 0x6e, 0x74, 0x6f,
        0x73, 0x20, 0x7e, 0x5d, 0x23, 0x20
    };      // cat: /boot/configaaaa: 没有那个文件或目录    gb2312
    do_rspd_con_write(vc, buf7, sizeof(buf7));
    compare_n_sshbuf(1, vce, "cat: /boot/configaaaa: ");
    vc_data_destroy(vc);

}
END_TEST


START_TEST(test_do_con_trol_newline)
{
    struct vc_data *vc = vc_data_creat();
    int ret = vc_do_resize(vc, 10, 3);
    ck_assert_msg(ret == 0, "ret != 0", ret);
    ck_assert_msg(vc->vc_cols == 10, "vc->vc_cols = %u", vc->vc_cols);

    vc_data_init(vc);
    ck_assert_msg(vc->vc_size_row == vc->vc_cols << 1, "vc_size_row = %u, vc_cols = %d", vc->vc_size_row, vc->vc_cols);
    ck_assert_msg(vc->vc_screenbuf_size == vc->vc_rows * vc->vc_size_row, "vc_screenbuf_size = %u", vc->vc_screenbuf_size);

    unsigned char buf0[] = {"01234567\n89abcdefg"};      // 换行
    do_rspd_con_write(vc, buf0, sizeof(buf0) - 1);
    compare_sshbuf(0, vce, "01234567");
    compare_sshbuf(1, vce, "89abcdefg");

    gotoxy(vc, 0, 0);
    unsigned char buf1[] = {"0123456789abcdefg"};      // 自动换行
    do_rspd_con_write(vc, buf1, sizeof(buf1) - 1);

    compare_sshbuf(0, vce, "0123456789");
    compare_sshbuf(1, vcx, "abcdefg");

    unsigned char buf2[] = {"hij0123456789abcdef"};      // 超过了 最大行数
    do_rspd_con_write(vc, buf2, sizeof(buf2) - 1);

    compare_sshbuf(0, vce, "0123456789");
    compare_sshbuf(1, vce, "abcdefghij");
    compare_sshbuf(2, vce, "0123456789");
    vc_data_destroy(vc);

}
END_TEST

START_TEST(test_do_con_trol_120)
{
    struct vc_data *vc = vc_data_creat();
    int ret = vc_do_resize(vc, 120, 10);
    ck_assert_msg(ret == 0, "ret != 0", ret);
    ck_assert_msg(vc->vc_cols == 120, "vc->vc_cols = %u", vc->vc_cols);

    vc_data_init(vc);
    ck_assert_msg(vc->vc_size_row == vc->vc_cols << 1, "vc_size_row = %u, vc_cols = %d", vc->vc_size_row, vc->vc_cols);
    ck_assert_msg(vc->vc_screenbuf_size == vc->vc_rows * vc->vc_size_row, "vc_screenbuf_size = %u", vc->vc_screenbuf_size);

    unsigned char buf0[] = {"\r\n-bash: 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789: command not found\r\n"};      // 换行
    do_rspd_con_write(vc, buf0, sizeof(buf0) - 1);
    compare_sshbuf(1, vce, "-bash: 01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012");
    compare_sshbuf(2, vce, "34567890123456789: command not found");

    struct sshbuf *sbuf = sshbuf_new();
    vc_data_to_sshbuf(vc, sbuf);
    ck_assert_msg(strcmp(sshbuf_ptr(sbuf), "\n-bash: 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789: command not found\n") == 0, "error");

    sshbuf_free(sbuf);
    vc_data_destroy(vc);

}
END_TEST

START_TEST(test_do_con_trol_request)
{
    struct vc_data *vc = vc_data_creat();
    int ret = vc_do_resize(vc, 120, 10);
    ck_assert_msg(ret == 0, "ret != 0", ret);
    ck_assert_msg(vc->vc_cols == 120, "vc->vc_cols = %u", vc->vc_cols);

    vc_data_init(vc);
    ck_assert_msg(vc->vc_size_row == vc->vc_cols << 1, "vc_size_row = %u, vc_cols = %d", vc->vc_size_row, vc->vc_cols);
    ck_assert_msg(vc->vc_screenbuf_size == vc->vc_rows * vc->vc_size_row, "vc_screenbuf_size = %u", vc->vc_screenbuf_size);

    /*
    echo "haha"
    echo "hehe"
    echo "aeae"
    echo "ahah"
    */
    unsigned char buf0[] = {
        0x65, 0x63, 0x68, 0x6f, 0x20, 0x22, 0x68, 0x61, 0x68, 0x61, 0x22, 0x0d, 0x65, 0x63, 0x68, 0x6f,
        0x20, 0x22, 0x68, 0x65, 0x68, 0x65, 0x22, 0x0d, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x22, 0x61, 0x65,
        0x61, 0x65, 0x22, 0x0d, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x22, 0x61, 0x68, 0x61, 0x68, 0x22, 0x0d
    };      // 换行
    do_rqst_con_write(vc, buf0, sizeof(buf0));
    compare_sshbuf(0, vce, "echo \"haha\"");
    compare_sshbuf(1, vce, "echo \"hehe\"");
    compare_sshbuf(2, vce, "echo \"aeae\"");
    compare_sshbuf(3, vce, "echo \"ahah\"");
    vc_data_destroy(vc);
}
END_TEST

START_TEST(test_do_con_trol_ctrl_R)
{
    struct vc_data *vc = vc_data_creat();
    int ret = vc_do_resize(vc, 120, 10);
    ck_assert_msg(ret == 0, "ret != 0", ret);
    ck_assert_msg(vc->vc_cols == 120, "vc->vc_cols = %u", vc->vc_cols);

    vc_data_init(vc);
    ck_assert_msg(vc->vc_size_row == vc->vc_cols << 1, "vc_size_row = %u, vc_cols = %d", vc->vc_size_row, vc->vc_cols);
    ck_assert_msg(vc->vc_screenbuf_size == vc->vc_rows * vc->vc_size_row, "vc_screenbuf_size = %u", vc->vc_screenbuf_size);

    unsigned char buf0[] = {"root@fort:~# "};
    do_rspd_con_write(vc, buf0, sizeof(buf0) - 1);

    unsigned char buf1[] = {
        0x0d, 0x1b, 0x5b, 0x39, 0x40, 0x28, 0x72, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x2d, 0x69, 0x2d,
        0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x29, 0x60, 0x27, 0x3a, 0x1b, 0x5b, 0x43
    };      //  ..[9@(re verse-i-)`':.[C
    do_rspd_con_write(vc, buf1, sizeof(buf1));
    compare_sshbuf(0, vce, "(reverse-i-search)`': ");

    unsigned char buf2[] = {
        0x08, 0x08, 0x08, 0x61, 0x27, 0x3a, 0x20, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x22, 0x61, 0x68, 0x61,
        0x68, 0x22, 0x08, 0x08, 0x08
    };      //  ...a': echo "ahah"...
    do_rspd_con_write(vc, buf2, sizeof(buf2));
    compare_sshbuf(0, vce, "(reverse-i-search)`a': echo \"ahah\"");
}
END_TEST

START_TEST(test_do_con_trol_ctrl_dirty)
{
    struct vc_data *vc = vc_data_creat();
    int ret = vc_do_resize(vc, 120, 10);
    ck_assert_msg(ret == 0, "ret != 0", ret);
    ck_assert_msg(vc->vc_cols == 120, "vc->vc_cols = %u", vc->vc_cols);

    vc_data_init(vc);
    ck_assert_msg(vc->vc_size_row == vc->vc_cols << 1, "vc_size_row = %u, vc_cols = %d", vc->vc_size_row, vc->vc_cols);
    ck_assert_msg(vc->vc_screenbuf_size == vc->vc_rows * vc->vc_size_row, "vc_screenbuf_size = %u", vc->vc_screenbuf_size);

    unsigned char buf0[] = {"abcdefghijklmnopqrstuvwxyz"};
    do_rspd_con_write(vc, buf0, sizeof(buf0) - 1);
    compare_sshbuf(0, vce, "abcdefghijklmnopqrstuvwxyz");

    unsigned char buf1[] = {"\r123456789"};
    do_rspd_con_write(vc, buf1, sizeof(buf1) - 1);
    compare_sshbuf(0, vce, "123456789jklmnopqrstuvwxyz");

    unsigned char buf2[] = {'\r', '1', '2', '3', '4', '5', '6', '7', '8', '9', 0x1b, '[', 'K'};
    do_rspd_con_write(vc, buf2, sizeof(buf2));
    compare_sshbuf(0, vce, "123456789                                                                                                               ");
}
END_TEST

START_TEST(test_do_con_trol_ctrl_dirty2)
{
    struct vc_data *vc = vc_data_creat();
    int ret = vc_do_resize(vc, 120, 10);
    ck_assert_msg(ret == 0, "ret != 0", ret);
    ck_assert_msg(vc->vc_cols == 120, "vc->vc_cols = %u", vc->vc_cols);

    vc_data_init(vc);
    ck_assert_msg(vc->vc_size_row == vc->vc_cols << 1, "vc_size_row = %u, vc_cols = %d", vc->vc_size_row, vc->vc_cols);
    ck_assert_msg(vc->vc_screenbuf_size == vc->vc_rows * vc->vc_size_row, "vc_screenbuf_size = %u", vc->vc_screenbuf_size);

    unsigned char buf0_1[] = {
        0x0d, 0x0a
    };
    do_rspd_con_write(vc, buf0_1, sizeof(buf0_1));
    compare_sshbuf(0, vce, "");

    //Last login: Sun Feb  4 13:52:04 2024 from 113.143.196.97...
    unsigned char buf0[] = {
        0x4c, 0x61, 0x73, 0x74, 0x20, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x3a, 0x20, 0x53, 0x75, 0x6e, 0x20,
        0x46, 0x65, 0x62, 0x20, 0x20, 0x34, 0x20, 0x31, 0x33, 0x3a, 0x35, 0x32, 0x3a, 0x30, 0x34, 0x20,
        0x32, 0x30, 0x32, 0x34, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x31, 0x31, 0x33, 0x2e, 0x31, 0x34,
        0x33, 0x2e, 0x31, 0x39, 0x36, 0x2e, 0x39, 0x37, 0x0d, 0x0d, 0x0a
    };
    do_rspd_con_write(vc, buf0, sizeof(buf0));
    compare_sshbuf(1, vce, "Last login: Sun Feb  4 13:52:04 2024 from 113.143.196.97");


    //[root@VM-4-7-centos ~]#
    //[root@VM-4-7-centos ~]#
    unsigned char buf1[] = {
        0x1b, 0x5b, 0x3f, 0x32, 0x30, 0x30, 0x34, 0x68, 0x5b, 0x72, 0x6f, 0x6f, 0x74, 0x40, 0x56, 0x4d,
        0x2d, 0x34, 0x2d, 0x37, 0x2d, 0x63, 0x65, 0x6e, 0x74, 0x6f, 0x73, 0x20, 0x7e, 0x5d, 0x23, 0x20,
        0x0d, 0x0a, 0x1b, 0x5b, 0x3f, 0x32, 0x30, 0x30, 0x34, 0x6c, 0x0d, 0x1b, 0x5b, 0x3f, 0x32, 0x30,
        0x30, 0x34, 0x68, 0x5b, 0x72, 0x6f, 0x6f, 0x74, 0x40, 0x56, 0x4d, 0x2d, 0x34, 0x2d, 0x37, 0x2d,
        0x63, 0x65, 0x6e, 0x74, 0x6f, 0x73, 0x20, 0x7e, 0x5d, 0x23, 0x20
    };
    do_rspd_con_write(vc, buf1, sizeof(buf1));
    compare_sshbuf(2, vce, "[root@VM-4-7-centos ~]# ");
    compare_sshbuf(3, vce, "[root@VM-4-7-centos ~]# ");


    reset_terminal(vc);
    vc_uniscr_memset(vc);

    unsigned char buf2[] = {
        0x1b, 0x5b, 0x37, 0x6d, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x22, 0x68, 0x61, 0x68, 0x61, 0x22, 0x1b,
        0x5b, 0x32, 0x37, 0x6d, 0x0d, 0x0a, 0x0d, 0x1b, 0x5b, 0x37, 0x6d, 0x65, 0x63, 0x68, 0x6f, 0x20,
        0x22, 0x68, 0x65, 0x68, 0x65, 0x22, 0x1b, 0x5b, 0x32, 0x37, 0x6d, 0x0d, 0x0a, 0x0d, 0x1b, 0x5b,
        0x37, 0x6d, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x22, 0x61, 0x65, 0x61, 0x65, 0x22, 0x1b, 0x5b, 0x32,
        0x37, 0x6d, 0x0d, 0x0a, 0x0d, 0x1b, 0x5b, 0x37, 0x6d, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x22, 0x61,
        0x68, 0x61, 0x68, 0x22, 0x1b, 0x5b, 0x32, 0x37, 0x6d, 0x0d, 0x0a, 0x0d
    };
    do_rspd_con_write(vc, buf2, sizeof(buf2));
    compare_sshbuf(0, vce, "echo \"haha\"");
    compare_sshbuf(1, vce, "echo \"hehe\"");
    compare_sshbuf(2, vce, "echo \"aeae\"");
    compare_sshbuf(3, vce, "echo \"ahah\"");

    struct sshbuf *sbuf = sshbuf_new();
    vc_data_to_sshbuf(vc, sbuf);
    ck_assert_msg(strcmp(sshbuf_ptr(sbuf), "echo \"haha\"\necho \"hehe\"\necho \"aeae\"\necho \"ahah\"\n") == 0, "multi line format invalid");


    sshbuf_free(sbuf);
    vc_data_destroy(vc);


}
END_TEST

START_TEST(test_do_con_trol_ctrl_find1)
{
    struct vc_data *vc = vc_data_creat();
    int ret = vc_do_resize(vc, 120, 10);
    ck_assert_msg(ret == 0, "ret != 0", ret);
    ck_assert_msg(vc->vc_cols == 120, "vc->vc_cols = %u", vc->vc_cols);

    vc_data_init(vc);
    ck_assert_msg(vc->vc_size_row == vc->vc_cols << 1, "vc_size_row = %u, vc_cols = %d", vc->vc_size_row, vc->vc_cols);
    ck_assert_msg(vc->vc_screenbuf_size == vc->vc_rows * vc->vc_size_row, "vc_screenbuf_size = %u", vc->vc_screenbuf_size);

    unsigned char buf0[] = {
        0x72, 0x6f, 0x6f, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x74, 0x3a, 0x7e, 0x23, 0x20
    };
    do_rspd_con_write(vc, buf0, sizeof(buf0));
    compare_sshbuf(0, vce, "root@fort:~# ");


    unsigned char buf1[] = {
        0x0d, 0x1b, 0x5b, 0x39, 0x40, 0x28, 0x72, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x2d, 0x69, 0x2d,
        0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x29, 0x60, 0x27, 0x3a, 0x1b, 0x5b, 0x43
    };
    do_rspd_con_write(vc, buf1, sizeof(buf1));
    compare_sshbuf(0, vce, "(reverse-i-search)`': ");


    unsigned char buf2[] = {
        0x08, 0x08, 0x08, 0x61, 0x27, 0x3a, 0x20, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x22, 0x61, 0x65, 0x61,
        0x65, 0x22, 0x08, 0x08, 0x08
    };
    do_rspd_con_write(vc, buf2, sizeof(buf2));
    compare_sshbuf(0, vce, "(reverse-i-search)`a': echo \"aeae\"");

    unsigned char buf3[] = {
        0x07
    };
    do_rspd_con_write(vc, buf3, sizeof(buf3));
    compare_sshbuf(0, vce, "(reverse-i-search)`a': echo \"aeae\"");

    unsigned char buf4[] = {
        0x08, 0x08, 0x68, 0x61, 0x68, 0x61, 0x22, 0x08, 0x08
    };
    do_rspd_con_write(vc, buf4, sizeof(buf4));
    compare_sshbuf(0, vce, "(reverse-i-search)`a': echo \"haha\"");

    unsigned char buf5[] = {
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x1b, 0x5b, 0x31,
        0x50, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43,
        0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x43, 0x1b,
        0x5b, 0x43, 0x1b, 0x5b, 0x43
    };
    do_rspd_con_write(vc, buf5, sizeof(buf5));
    compare_sshbuf(0, vce, "(reverse-i-search)`': echo \"haha\"");

    unsigned char buf6[] = {
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x62, 0x27, 0x3a, 0x20,
        0x63, 0x64, 0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x78, 0x69, 0x61, 0x6f, 0x6b, 0x65, 0x2f, 0x6f,
        0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2d, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x08,
        0x08, 0x08
    };
    do_rspd_con_write(vc, buf6, sizeof(buf6));
    compare_sshbuf(0, vce, "(reverse-i-search)`b': cd/home/xiaoke/openssh-portable");


    struct sshbuf *sbuf = sshbuf_new();
    vc_data_to_sshbuf(vc, sbuf);
    ck_assert_msg(strcmp(sshbuf_ptr(sbuf), "(reverse-i-search)`b': cd/home/xiaoke/openssh-portable") == 0, "multi line format invalid");


    sshbuf_free(sbuf);
    vc_data_destroy(vc);

    //reset_terminal(vc);
    //vc_uniscr_memset(vc);
}
END_TEST


Suite *make_suite(void)
{
	Suite *s = suite_create("test");
	TCase *tc = tcase_create("cmd-vc-test");

    tcase_add_test(tc, test_do_con_trol);
    tcase_add_test(tc, test_conv_uni_to_pc);
    tcase_add_test(tc, test_do_con_trol_dbmy);
    tcase_add_test(tc, test_do_con_trol_tencent);
    tcase_add_test(tc, test_do_con_trol_newline);
    tcase_add_test(tc, test_do_con_trol_120);
    tcase_add_test(tc, test_do_con_trol_request);
    tcase_add_test(tc, test_do_con_trol_ctrl_R);
    tcase_add_test(tc, test_do_con_trol_ctrl_dirty);
    tcase_add_test(tc, test_do_con_trol_ctrl_dirty2);
    tcase_add_test(tc, test_do_con_trol_ctrl_find1);

	suite_add_tcase(s, tc);
	return s;
}

int main()
{
	int nf;
	Suite *s = make_suite();
	SRunner *sr = srunner_create(s);

    log_init("cmd-vc-test", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_DAEMON, 1);
	srunner_set_fork_status(sr, CK_NOFORK);
	srunner_run_all(sr, CK_VERBOSE);
	nf = srunner_ntests_failed(sr);

	free_ast_memory();
	srunner_free(sr);
	return nf;
}