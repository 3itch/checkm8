/*
 * Copyright 2024 Jakub Czapiga <mordijc@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <errno.h>
#include <cmocka.h>

#include "../src/cmocka.c"

static void test_strreplace_null(void **state)
{
    int rc;
    char data[64] = "DATA";
    int out = 0;

    (void)state;

    rc = c_strreplace(NULL, sizeof(data), "A", "B", &out);
    assert_int_equal(rc, -1);
    assert_int_equal(out, 0);
    assert_int_equal(errno, EINVAL);

    rc = c_strreplace(data, 0, "A", "B", &out);
    assert_int_equal(rc, -1);
    assert_int_equal(out, 0);
    assert_int_equal(errno, EINVAL);

    rc = c_strreplace(data, sizeof(data), NULL, "B", &out);
    assert_int_equal(rc, -1);
    assert_int_equal(out, 0);
    assert_int_equal(errno, EINVAL);

    rc = c_strreplace(data, sizeof(data), "A", NULL, &out);
    assert_int_equal(rc, -1);
    assert_int_equal(out, 0);
    assert_int_equal(errno, EINVAL);
}

static void test_strreplace_no_pattern(void **state)
{
    int rc;
    char data[64] = "DATA";
    int out = 0;

    (void) state;

    rc = c_strreplace(data, sizeof(data), "X", "Y", &out);
    assert_int_equal(rc, 0);
    assert_int_equal(out, 0);
}

static void test_strreplace_patterns(void **state)
{
    int rc;
    const char base_data[] = "THIS IS THE DATA";
    char data[64] = "THIS IS THE DATA";
    int out = 0;

    (void) state;

    // Simple character substitution
    rc = c_strreplace(data, sizeof(data), "T", "D", &out);
    assert_int_equal(rc, 0);
    assert_int_equal(out, 1);
    assert_string_equal(data, "DHIS IS DHE DADA");

    // Reset data
    memcpy(data, base_data, sizeof(base_data));

    // Superset pattern
    out = 0;
    rc = c_strreplace(data, sizeof(data), " IS", " ISN'T", &out);
    assert_int_equal(rc, 0);
    assert_int_equal(out, 1);
    assert_string_equal(data, "THIS ISN'T THE DATA");

    // Subset pattern
    memcpy(data, base_data, sizeof(base_data));
    out = 0;
    rc = c_strreplace(data, sizeof(data), "THIS", "TIS", &out);
    assert_int_equal(rc, 0);
    assert_int_equal(out, 1);
    assert_string_equal(data, "TIS IS THE DATA");

    // Partial replacement
    memcpy(data, base_data, sizeof(base_data));
    out = 0;
    rc = c_strreplace(data, sizeof(data), "THIS", "THOSE", &out);
    assert_int_equal(rc, 0);
    assert_int_equal(out, 1);
    assert_string_equal(data, "THOSE IS THE DATA");

    // Outer extension
    memcpy(data, base_data, sizeof(base_data));
    out = 0;
    rc = c_strreplace(data, sizeof(data), "THE", "_THE_", &out);
    assert_int_equal(rc, 0);
    assert_int_equal(out, 1);
    assert_string_equal(data, "THIS IS _THE_ DATA");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_strreplace_null),
        cmocka_unit_test(test_strreplace_no_pattern),
        cmocka_unit_test(test_strreplace_patterns),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
