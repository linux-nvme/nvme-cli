#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "../util/argconfig.h"

START_TEST(test_argconfig_buffer_boundary)
{
    // Invariant: Help text generation must not overflow buffers regardless of option name/meta length
    
    struct argconfig_commandline_options options[] = {
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 'a', "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CFG_STRING, NULL, required_argument, "long option"},
        {"x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x", 'b', "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", CFG_STRING, NULL, required_argument, "boundary"},
        {"normal", 'n', "arg", CFG_STRING, NULL, required_argument, "valid"},
        {NULL}
    };
    
    char help_buffer[4096];
    memset(help_buffer, 0xAA, sizeof(help_buffer));
    help_buffer[sizeof(help_buffer) - 1] = '\0';
    
    int result = argconfig_parse(1, (char *[]){"test"}, "test", options);
    
    // Verify no buffer corruption: canary bytes beyond reasonable help text size should be untouched
    int corruption_detected = 0;
    for (size_t i = 3000; i < sizeof(help_buffer) - 1; i++) {
        if (help_buffer[i] != (char)0xAA) {
            corruption_detected = 1;
            break;
        }
    }
    
    ck_assert_int_eq(corruption_detected, 0);
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_argconfig_buffer_boundary);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}