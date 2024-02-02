#include <check.h>


Suite *make_suite(void)
{
	Suite *s = suite_create("test");
	TCase *tc = tcase_create("cmd-ssh-test");

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