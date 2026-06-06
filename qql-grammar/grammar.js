module.exports = grammar({
  name: 'qql',

  extras: $ => [
    /\s/,
    /--.*/, // Single line comments
  ],

  rules: {
    source_file: $ => repeat($.statement),

    statement: $ => choice(
      $.search_statement,
      $.insert_statement
    ),

    search_statement: $ => seq(
      field('command', /SEARCH/i),
      field('mode', choice(
        seq(/VECTOR/i, field('vector', $.vector)),
        seq(/TEXT/i, field('query_string', $.string))
      )),
      /FROM/i,
      field('table', $.identifier),
      optional(seq(/WHERE/i, field('condition', $.condition))),
      optional(seq(/LIMIT/i, field('limit', $.number))),
      ';'
    ),

    insert_statement: $ => seq(
      /INSERT/i, /INTO/i, field('table', $.identifier),
      '(', field('col1', $.identifier), ',', field('col2', $.identifier), ')',
      /VALUES/i,
      '(', field('val1', choice($.string, $.number)), ',', field('val2', choice($.string, $.number)), ')',
      ';'
    ),

    condition: $ => seq(
      field('left', $.identifier),
      field('op', $.operator),
      field('right', choice($.number, $.string))
    ),

    operator: $ => choice('>', '<', '=', '>=', '<=', '!=', /LIKE/i),

    vector: $ => seq(
      '[',
      optional(seq(
        $.number,
        repeat(seq(',', $.number))
      )),
      ']'
    ),

    identifier: $ => /[a-zA-Z_][a-zA-Z0-9_]*/,
    
    string: $ => choice(
      seq('"', /[^"]*/, '"'),
      seq("'", /[^']*/, "'")
    ),

    number: $ => /-?[0-9]+(\.[0-9]+)?/
  }
});
