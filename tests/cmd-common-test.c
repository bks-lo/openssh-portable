#include <check.h>

START_TEST(test_get_simple_file_content)
{
    debug_p("===============================================get_login_rstr_by_proto"
            "===============================================");
    // int get_simple_file_content(const char *file, char ***line_arr, int *line_num)
    char **content_arr = NULL;
    int line_num = 0;
    int ret = get_simple_file_content("/tmp/aaa", &content_arr, &line_num);
    ck_assert_msg(ret == -1, "ret != -1");

    //sleep(100000);
    ret = get_simple_file_content("./tests/simple_file_1.test", &content_arr, &line_num);
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(line_num == 3, "line_num[%d] != 3", line_num);
    ck_assert_msg(strcmp(content_arr[2], "     dda  aaa   aaaa") == 0, "content_arr[2]=%s != \"     dda  aaa   aaaa\"", content_arr[0]);
}
END_TEST

/* 需要先 make install-lr  将配置文件放到对应目录 */
START_TEST(test_get_login_rstr_by_proto)
{
    debug_p("===============================================get_login_rstr_by_proto"
            "===============================================");
    // int get_simple_file_content(const char *file, char ***line_arr, int *line_num)
    char **content_arr = NULL;
    int line_num = 0;
    int ret = get_login_rstr_by_proto("ssh", 0, &content_arr, &line_num);
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(line_num == 1, "line_num[%d] != 1", line_num);
    ck_assert_msg(strcmp(content_arr[0], "Last") == 0, "content_arr[0]=%s != \"Last\"", content_arr[0]);

    ret = get_login_rstr_by_proto("ssh", 1, &content_arr, &line_num);
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(line_num == 1, "line_num[%d] != 1", line_num);
    ck_assert_msg(strcmp(content_arr[0], "Permission") == 0, "content_arr[0]=%s != \"Permission\"", content_arr[0]);
}
END_TEST

START_TEST(test_convert_encode_2_utf8)
{
    debug_p("===============================================get_convert_encode_2_utf8"
            "===============================================");
    size_t outlen = 0;
    char out_buf_gb2312[512] = {0};
    char orig_buf[] = {"哈哈"};
    outlen = sizeof(out_buf_gb2312);
    // int code_convert(char *from_charset, char *to_charset, char *inbuf, size_t inlen, char *outbuf, size_t outlen)
    int ret = code_convert("UTF8", "GB2312", orig_buf, sizeof(orig_buf), out_buf_gb2312, &outlen);
    ck_assert_msg(ret != -1, "ret == -1");

    char out_buf[512] = {0};
    outlen = sizeof(out_buf);
    ret = convert_encode_2_utf8(GB2312, out_buf_gb2312, strlen(out_buf_gb2312), out_buf, &outlen);
    ck_assert_msg(ret != -1, "ret == -1");
    ck_assert_msg(strcmp(out_buf, orig_buf) == 0, "out_buf[%s] != orig_buf[%s]", out_buf, orig_buf);

    char out_buf_shift_jis[512] = {0};
    outlen = sizeof(out_buf_shift_jis);
    ret = code_convert("GB2312", "SHIFT_JIS", out_buf_gb2312, strlen(out_buf_gb2312), out_buf_shift_jis, &outlen);
    ck_assert_msg(ret != -1, "ret == -1");

    memset(out_buf, 0, sizeof(out_buf));
    outlen = sizeof(out_buf);
    ret = convert_encode_2_utf8(SHIFT_JIS, out_buf_shift_jis, strlen(out_buf_shift_jis), out_buf, &outlen);
    ck_assert_msg(ret != -1, "ret == -1");
    ck_assert_msg(strcmp(out_buf, orig_buf) == 0, "out_buf[%s] != orig_buf[%s]", out_buf, orig_buf);
}
END_TEST

START_TEST(test_proxy_info)
{
    proxy_info_st *pinfo = proxy_info_init();
    ck_assert_msg(pinfo != NULL, "pinfo == NULL");
    ck_assert_msg(pinfo->redis_conn != NULL, "pinfo->redis_conn == NULL");
    ck_assert_msg(pinfo->mysql_conn != NULL, "pinfo->mysql_conn == NULL");

    int ret = Redis_Exec(pinfo->redis_conn, "set  connection_session::cmd-common-test-key  {\"protocol\":\"ssh\",\"hostname\":\"1.2.3.4\",\"password\":\"AAbbccDD%%d@s\",\"port\":\"22\",\"username\":\"root\",\"remote_ip\":\"192.168.68.1\",\"charset\":\"UTF-8\",\"sid\":\"cmd-common-test-key\",\"uid\":\"uid-cmd-common-test-key\"}");
    ck_assert_msg(ret == 0, "ret != 0");

    ret = get_proxy_info_by_sid(pinfo, "cmd-common-test-key");
    ck_assert_msg(ret == 0, "ret != 0");

    ck_assert_msg(strcmp(pinfo->sid, "cmd-common-test-key") == 0, "pinfo->sid[%s] invalid", pinfo->sid);
    ck_assert_msg(strcmp(pinfo->hostname, "1.2.3.4") == 0, "pinfo->hostnam[%s] invalid", pinfo->hostname);
    ck_assert_msg(strcmp(pinfo->password, "AAbbccDD%d@s") == 0, "pinfo->password[%s] invalid", pinfo->password);

    ret = proxy_auth_password(pinfo, "cmd-common-test-key");
    ck_assert_msg(ret == -1, "ret != -1");

    ret = Redis_Exec(pinfo->redis_conn, "del  connection_session::cmd-common-test-key");
    ck_assert_msg(ret == 0, "ret != 0");
}
END_TEST

START_TEST(test_proxy_popen)
{
    int ret = proxy_popen("getconf ARG_MAX");
    ck_assert_msg(ret == 0, "ret != 0");
}
END_TEST

START_TEST(test_find_last_word)
{
#define STR_LEN(s)  s, sizeof(s) - 1
    const char *ret = NULL;
    int i = 0;

    ++i;
    ret = find_last_word(STR_LEN("hahah"), 0);
    ck_assert_msg(strncmp(ret, STR_LEN("hahah")) == 0, "[%d] != hahah", i);

    ++i;
    ret = find_last_word(STR_LEN("hahah "), 0);
    ck_assert_msg(strncmp(ret, STR_LEN("hahah")) == 0, "[%d] != hahah", i);

    ++i;
    ret = find_last_word(STR_LEN(" hahah"), 0);
    ck_assert_msg(strncmp(ret, STR_LEN("hahah")) == 0, "[%d] != hahah", i);

    ++i;
    ret = find_last_word(STR_LEN(" hahah "), 0);
    ck_assert_msg(strncmp(ret, STR_LEN("hahah")) == 0, "[%d] != hahah", i);

    ++i;
    ret = find_last_word(STR_LEN(" hahah :"), 0);
    ck_assert_msg(strncmp(ret, STR_LEN("hahah")) == 0, "[%d] != hahah", i);

    ++i;
    ret = find_last_word(STR_LEN("hahah :"), 0);
    ck_assert_msg(strncmp(ret, STR_LEN("hahah")) == 0, "[%d] != hahah", i);

    ++i;
    ret = find_last_word(STR_LEN("hahah >"), 0);
    ck_assert_msg(strncmp(ret, STR_LEN("hahah")) == 0, "[%d] != hahah", i);

    ++i;
    ret = find_last_word(STR_LEN(" hahah ha >"), 3);
    ck_assert_msg(strncmp(ret, STR_LEN("hahah")) == 0, "[%d] != hahah", i);

    ++i;
    ret = find_last_word(STR_LEN(" hahah ha>"), 3);
    ck_assert_msg(strncmp(ret, STR_LEN("hahah")) != 0, "[%d] != hahah", i);

    ++i;
    ret = find_last_word(STR_LEN(" hahah ha >"), 0);
    ck_assert_msg(strncmp(ret, STR_LEN("hahah")) != 0, "[%d] != hahah", i);

    ++i;
    ret = find_last_word(STR_LEN(" hahah: "), 0);
    ck_assert_msg(strncmp(ret, STR_LEN("hahah:")) == 0, "[%d] != hahah", i);

    ++i;
    ret = find_last_word("abcd efgh ijkl", 10, 0);
    ck_assert_msg(strncmp(ret, STR_LEN("efgh")) == 0, "[%d] != efgh", i);
}
END_TEST


Suite *make_suite(void)
{
	Suite *s = suite_create("test");
	TCase *tc = tcase_create("cmd-common-test");

	tcase_add_test(tc, test_get_simple_file_content);
	tcase_add_test(tc, test_get_login_rstr_by_proto);
    tcase_add_test(tc, test_convert_encode_2_utf8);
    tcase_add_test(tc, test_proxy_info);
    tcase_add_test(tc, test_proxy_popen);
    tcase_add_test(tc, test_find_last_word);

	suite_add_tcase(s, tc);
	return s;
}

int main()
{
	int nf;
	Suite *s = make_suite();
	SRunner *sr = srunner_create(s);

    log_init("cmd-common-test", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_DAEMON, 1);
	srunner_set_fork_status(sr, CK_NOFORK);
	srunner_run_all(sr, CK_VERBOSE);
	nf = srunner_ntests_failed(sr);

	free_ast_memory();
	srunner_free(sr);
	return nf;
}
