# Phase 5: QIHSE Query Language (QQL) Engine

## 1. Overview
The QQL Engine will parse and execute text-based queries against the QIHSE databases. It will use a formal Grammar generated via **Tree-Sitter** to parse queries into an Abstract Syntax Tree (AST), which our C execution engine will traverse to invoke the underlying Vector, KV, Document, or Columnar stores.

## 2. Team Plan
To build this rapidly, we will deploy a **Subagent Team**:

- **Agent 1: Tree-Sitter Grammar Architect**
  - **Goal**: Initialize the Tree-sitter project, write the `grammar.js` for QQL, and generate the `parser.c`.
  - **Syntax Goal**: 
    `SEARCH VECTOR [...] FROM vectors WHERE age > 20 LIMIT 10;`
    `SEARCH TEXT "query" FROM documents LIMIT 5;`
    `INSERT INTO kv (key, value) VALUES ("foo", "bar");`
  - **Tasks**:
    1. Create `qql-grammar/grammar.js`.
    2. Run `npx tree-sitter-cli generate`.
    3. Vendor the Tree-Sitter core C headers/lib so the main Makefile can compile it without system dependencies.

- **Agent 2: QQL Execution Integrator**
  - **Goal**: Implement the AST traversal in `src/qihse_qql_parser.c`.
  - **Tasks**:
    1. Hook `ts_parser_new()` and `ts_parser_parse_string()`.
    2. Walk the Tree-sitter AST and map it to QIHSE Engine API calls (e.g. `qihse_doc_store_query`, `qihse_kv_set`).
    3. Update `Makefile` to compile `qql-grammar/src/parser.c` and tree-sitter core.
    4. Write `tests/test_qql.c`.

## 3. Completion
Once both agents sync their work, QQL text queries coming over the UWP TCP port will be fully parsed and executed.

## 4. Grammar Definitions

The chosen Tree-Sitter grammar definition (`grammar.js`) supports:
- `search_statement`: `SEARCH VECTOR [1.0, 2.0] FROM table WHERE col > 5 LIMIT 10` or `SEARCH TEXT "query" FROM table LIMIT 5`
- `insert_statement`: `INSERT INTO table (col1, col2) VALUES (1, "two")`
- `condition`: `identifier operator value` (operators: `=`, `!=`, `>`, `<`, `>=`, `<=`)
- `value`: string literal, number, boolean
