#!/usr/bin/env python3
"""Compile and run C99/C++11 SQL public API consumers against make lib output."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEADERS = ("qihse_sql_fts.h", "qihse_sql_parser.h", "qihse_sql_row_index.h",
           "qihse_kv_store.h")
SOURCE = r'''
#include "qihse_sql_fts.h"
#include "qihse_sql_parser.h"
#include "qihse_sql_row_index.h"
#include "qihse_kv_store.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#ifdef __cplusplus
#include <type_traits>
#define OP operator_name
static_assert(std::is_standard_layout<qihse_sql_condition_t>::value, "C layout");
#else
#define OP operator
#endif
struct legacy_condition {
    char *column_name, *op, *value;
    int value_is_string;
    qihse_sql_type_t value_cast_type;
    uint16_t value_parameter_index;
    qihse_sql_subq_kind_t subq_kind;
    struct qihse_sql_ast_s* subquery;
};
struct alignment { char byte; qihse_sql_condition_t value; };
struct legacy_alignment { char byte; struct legacy_condition value; };
#define CHECK(member, old) assert(offsetof(qihse_sql_condition_t, member) == offsetof(struct legacy_condition, old)); printf("%zu ", offsetof(qihse_sql_condition_t, member))
int main(void) {
    /* Force C/C++ linkage without opening a default store or using a NULL user. */
    qihse_kv_store_t *(*volatile create_user)(qihse_user_t *) =
        qihse_kv_store_create_user;
    if (!create_user) return 1;
    assert(sizeof(qihse_sql_condition_t) == sizeof(struct legacy_condition));
    assert(offsetof(struct alignment, value) == offsetof(struct legacy_alignment, value));
    printf("%zu %zu ", sizeof(qihse_sql_condition_t), offsetof(struct alignment, value));
    CHECK(column_name, column_name);
    CHECK(OP, op);
    CHECK(value, value);
    CHECK(value_is_string, value_is_string);
    CHECK(value_cast_type, value_cast_type);
    CHECK(value_parameter_index, value_parameter_index);
    CHECK(subq_kind, subq_kind);
    CHECK(subquery, subquery);
    printf("%zu %zu\n", sizeof(qihse_sql_ast_t), sizeof(qihse_schema_index_t));
    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast("SELECT id FROM header_smoke WHERE id = $1");
    assert(ast && ast->num_where_conditions == 1);
    assert(strcmp(ast->where_conditions[0].OP, "=") == 0);
    assert(ast->where_conditions[0].value_parameter_index == 1);
    assert(qihse_sql_ast_parameter_count(ast) == 1);
    assert(qihse_sql_ast_parameters_valid(ast));
    assert(strcmp(qihse_sql_type_name(QIHSE_TYPE_TSVECTOR), "TSVECTOR") == 0);
    qihse_sql_ast_free(ast);
    /* Invalid-input calls force real references without retrieving any data. */
    char* vector = NULL;
    assert(!qihse_sql_to_tsvector_english(NULL, &vector));
    assert(vector == NULL);
    qihse_sql_row_index_t* index = NULL;
    assert(!qihse_sql_row_index_build(NULL, NULL, NULL, NULL, &index));
    assert(index == NULL);
    size_t* rows = NULL;
    size_t count = 1;
    assert(!qihse_sql_row_index_equal(index, NULL, NULL, NULL, NULL, 0, &rows, &count));
    assert(rows == NULL && count == 0);
    count = 1;
    assert(!qihse_sql_row_index_gin(index, NULL, NULL, NULL, NULL, "word", &rows, &count));
    assert(rows == NULL && count == 0);
    qihse_sql_row_index_destroy(index);
    return 0;
}
'''


class SqlCppHeaders(unittest.TestCase):
    def test_public_headers_and_real_library_abi(self):
        self.assertTrue((ROOT / "libqihse.so").is_file(), "run make lib first")
        outputs = []
        with tempfile.TemporaryDirectory(prefix="qihse-sql-headers-") as tmp:
            for compiler, standard, language, suffix in (
                (os.environ.get("CC", "cc"), "c99", "c", ".c"),
                (os.environ.get("CXX", "c++"), "c++11", "c++", ".cpp"),
            ):
                flags = shlex.split(compiler) + [
                    "-std=" + standard, "-D_GNU_SOURCE", "-Wall", "-Wextra",
                    "-Werror", "-I" + str(ROOT), "-I" + str(ROOT / "include"),
                    "-I" + str(ROOT / "core"),
                ]
                for header in HEADERS:
                    with self.subTest(language=language, header=header):
                        subprocess.run(flags + ["-fsyntax-only", "-x", language, "-"],
                                       input='#include "' + header + '"\n', text=True, check=True)
                source = Path(tmp) / ("consumer" + suffix)
                binary = Path(tmp) / ("consumer" + suffix + ".bin")
                source.write_text(SOURCE)
                subprocess.run(flags + [str(source), "-L" + str(ROOT),
                                        "-Wl,-rpath," + str(ROOT), "-lqihse",
                                        "-o", str(binary)], check=True)
                env = os.environ.copy()
                env["LD_LIBRARY_PATH"] = str(ROOT) + os.pathsep + env.get("LD_LIBRARY_PATH", "")
                result = subprocess.run([str(binary)], check=True, text=True,
                                        capture_output=True, env=env)
                outputs.append(result.stdout)
        self.assertEqual(outputs[0], outputs[1], "C and C++ layouts differ")


if __name__ == "__main__":
    unittest.main()
