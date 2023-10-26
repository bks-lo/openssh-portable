#include <check.h>
#include "../log.h"


START_TEST(test_mprintf)
{
	debug_p("===============================================test_mprintf"
		"===============================================\n");

    int ret = mprintf("%s", "haha");
    ck_assert_msg(ret == 4, "ret[%d] != 4", ret);

    ret = mprintf("%s", "haha\n");
    ck_assert_msg(ret == 5, "ret[%d] != 5", ret);

    ret = mprintf("%s", "哈哈\n");
    ck_assert_msg(ret == 25, "ret[%d] != 25", ret);
}
END_TEST


Suite *make_suite(void)
{
	Suite *s = suite_create("test");
	TCase *tc = tcase_create("utf8-test");

	tcase_add_test(tc, test_mprintf);
	suite_add_tcase(s, tc);
	return s;
}

int main()
{
	int nf;
	Suite *s = make_suite();
	SRunner *sr = srunner_create(s);

    log_init("utf8-test", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_DAEMON, 1);
	srunner_set_fork_status(sr, CK_NOFORK);
	srunner_run_all(sr, CK_VERBOSE);
	nf = srunner_ntests_failed(sr);

	free_ast_memory();
	srunner_free(sr);
	return nf;
}
