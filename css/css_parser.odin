package css

import "core:fmt"
import "core:io"
import "core:container/queue"
import "core:strings"
import "core:strconv"

import "../codepoints"

report_parse_error :: proc() {
    fmt.eprintln("[ERROR:CSS Parser]")
}

Numeric_Value :: union{int, f32}
Numeric_Type :: enum{Integer, Number}

// https://www.w3.org/TR/css-syntax-3/#tokenization
Ident_Token :: struct {
    value: string,
}

Function_Token :: distinct Ident_Token
At_Keyword_Token :: distinct Ident_Token
Url_Token :: distinct Ident_Token

String_Token :: struct {
    value: strings.Builder,
}

Hash_Token :: struct {
    value: string,
    type_flag: enum{Unrestricted, Id},
}

Delim_Token :: struct {value: rune}

Percentage_Token :: struct {
    value: Numeric_Value,
}

Number_Token :: struct {
    value: Numeric_Value,
    type_flag: Numeric_Type,
}

Dimension_Token :: struct {
    value: Numeric_Value,
    type_flag: Numeric_Type,
    unit: string,
}

Bad_String_Token :: struct {}
Bad_Url_Token :: struct {}
Whitespace_Token :: struct {}
Cdo_Token :: struct {}
Cdc_Token :: struct {}
Eof_Token :: struct {}

Punctuation_Token :: distinct Delim_Token

Css_Token :: union {
    Ident_Token,
    Function_Token,
    At_Keyword_Token,
    String_Token,
    Url_Token,
    Hash_Token,
    Delim_Token,
    Percentage_Token,
    Number_Token,
    Dimension_Token,
    Bad_String_Token,
    Bad_Url_Token,
    Whitespace_Token,
    Cdo_Token,
    Cdc_Token,
    Eof_Token,
    Punctuation_Token,
}

Css_Tokenizer :: struct {
    input_stream: io.Reader,
    consumed_characters: queue.Queue(rune), // Peeked characters are stored here
    // @NOTE: Maybe this can be used to eliminate the need for last_character

    // Used for reconsuming
    last_character: rune,

    // Holds the tokens that are to be emitted. We use a queue because the specification sometimes forces the tokenizer to emit multiple tokens.
    to_emit: queue.Queue(Css_Token),
}

tokenizer_init :: proc(tokenizer: ^Css_Tokenizer, input_stream: io.Reader) {
    tokenizer.input_stream = input_stream
}

peek_next_character :: proc(tokenizer: ^Css_Tokenizer) -> (char: rune, error: io.Error) {
    if queue.len(tokenizer.consumed_characters) == 0 {
        err := consume_character_from_input_stream(tokenizer)
        if err != .None do return 0, err
    }
    return queue.peek_front(&tokenizer.consumed_characters)^, .None
}

// @Speedup: We can do this without allocating, but this is the easiest and closest to the spec that I can come up with for now
peek_character_at_index :: proc(tokenizer: ^Css_Tokenizer, n: int) -> (char: rune, error: io.Error) {
    for queue.len(tokenizer.consumed_characters) < n {
        err := consume_character_from_input_stream(tokenizer)
        if err != .None do return 0, err
    }

    peeked_index := (n + cast(int)tokenizer.consumed_characters.offset) % len(tokenizer.consumed_characters.data)
    return tokenizer.consumed_characters.data[peeked_index], .None
}

get_next_character :: proc(tokenizer: ^Css_Tokenizer) -> (char: rune, error: io.Error) {
    if queue.len(tokenizer.consumed_characters) == 0 {
        err := consume_character_from_input_stream(tokenizer)
        if err != .None do return 0, err
    }
    tokenizer.last_character = queue.pop_front(&tokenizer.consumed_characters)
    return tokenizer.last_character, .None
}

reconsume :: proc(tokenizer: ^Css_Tokenizer) {
    queue.push_front(&tokenizer.consumed_characters, tokenizer.last_character) 
}

// https://www.w3.org/TR/css-syntax-3/#input-preprocessing
consume_character_from_input_stream :: proc(tokenizer: ^Css_Tokenizer) -> io.Error {
    r, _, err := io.read_rune(tokenizer.input_stream)
    if err != .None do return err

    // The input stream consists of the filtered code points pushed into it as the input byte stream is decoded.
    // To filter code points from a stream of (unfiltered) code points input:

    //     Replace any U+000D CARRIAGE RETURN (CR) code points, U+000C FORM FEED (FF) code points, or pairs of U+000D CARRIAGE RETURN (CR) followed
    // by U+000A LINE FEED (LF) in input by a single U+000A LINE FEED (LF) code point.
    //     Replace any U+0000 NULL or surrogate code points in input with U+FFFD REPLACEMENT CHARACTER (�). 

    switch r {
        case '\f': r = '\n'
        case '\r':
            r_next, _, r_next_err := io.read_rune(tokenizer.input_stream)
            if r_next_err != .None do return r_next_err
            if r_next == '\n' do r = '\n'
            else {
                queue.push_back(&tokenizer.consumed_characters, '\n')
                r = r_next
            }
        case '\u0000': r = '\uFFFD'
    }

    queue.push_back(&tokenizer.consumed_characters, r)
    return .None
}

input_starts_with :: proc(tokenizer: ^Css_Tokenizer, prefix: string) -> bool {
    prefix_len := len(prefix)
    for prefix_len > queue.len(tokenizer.consumed_characters) {
        consume_character_from_input_stream(tokenizer)
    }

    for r, index in prefix {
        peeked_index := (index + cast(int)tokenizer.consumed_characters.offset) % len(tokenizer.consumed_characters.data)
        if r != tokenizer.consumed_characters.data[peeked_index] do return false
    }
    return true
}

// https://www.w3.org/TR/css-syntax-3/#ident-start-code-point
// A letter, a non-ASCII code point, or U+005F LOW LINE (_). 
is_ident_start_codepoint :: proc(r: rune) -> bool {
    return codepoints.is_ascii_alpha(r) || codepoints.is_non_ascii(r) || r == '_'
}

// https://www.w3.org/TR/css-syntax-3/#ident-code-point
// An ident-start code point, a digit, or U+002D HYPHEN-MINUS (-). 
is_ident_codepoint :: proc(r: rune) -> bool {
    return is_ident_start_codepoint(r) || codepoints.is_ascii_digit(r) || r == '-'
}

// https://www.w3.org/TR/css-syntax-3/#consume-token
// This section describes how to consume a token from a stream of code points. It will return a single token of any type.
get_next_token :: proc(tokenizer: ^Css_Tokenizer) -> Css_Token {
    // Consume comments.

    // Consume the next input code point.
    r, r_err := get_next_character(tokenizer)

    if r_err == .EOF { // EOF
        return Eof_Token{} // Return an <EOF-token>. 
    }

    switch {
    // whitespace
    case r == '\n': fallthrough
    case r == '\t': fallthrough
    case r == ' ':
        for r == '\n' || r == '\t' || r == ' ' {
            r_next, r_err := peek_next_character(tokenizer)
            if r_err == .EOF do break 
            if r_next != '\n' && r_next != '\t' && r_next != ' ' do break
            get_next_character(tokenizer)
            r = r_next
        }
        return Whitespace_Token{}
    
    // U+0022 QUOTATION MARK (")
    case r == '"':
        // Consume a string token and return it. 
        return consume_string_token(tokenizer, '"')

    // U+0023 NUMBER SIGN (#)
    case r == '#':
        // If the next input code point is an ident code point or the next two input code points are a valid escape, then:
        r_next, r_next_err := peek_next_character(tokenizer)
        if is_ident_codepoint(r_next) || is_valid_escape_sequence(tokenizer){
            // Create a <hash-token>.
            token := Hash_Token{}
            // If the next 3 input code points would start an ident sequence, set the <hash-token>’s type flag to "id".
            if would_start_ident_sequence(tokenizer) do token.type_flag = .Id
            // Consume an ident sequence, and set the <hash-token>’s value to the returned string.
            token.value = consume_ident_sequence(tokenizer)
            // Return the <hash-token>. 
            return token
        }
        else { // Otherwise, return a <delim-token> with its value set to the current input code point.
            return Delim_Token{r}
        }
        

        /*
    U+0027 APOSTROPHE (')
        Consume a string token and return it. 
    U+0028 LEFT PARENTHESIS (()
        Return a <(-token>. 
    */
    // U+0029 RIGHT PARENTHESIS ())
    case r == ')':
        // Return a <)-token>. 
        return Punctuation_Token{')'}
    /*
    U+002B PLUS SIGN (+)
        If the input stream starts with a number, reconsume the current input code point, consume a numeric token, and return it.

        Otherwise, return a <delim-token> with its value set to the current input code point.
    */
    // U+002C COMMA (,)
    case r == ',':
        // Return a <comma-token>. 
        return Punctuation_Token{','}
    /*
    U+002D HYPHEN-MINUS (-)
        If the input stream starts with a number, reconsume the current input code point, consume a numeric token, and return it.

        Otherwise, if the next 2 input code points are U+002D HYPHEN-MINUS U+003E GREATER-THAN SIGN (->), consume them and return a <CDC-token>.

        Otherwise, if the input stream starts with an ident sequence, reconsume the current input code point, consume an ident-like token, and return it.

        Otherwise, return a <delim-token> with its value set to the current input code point.
    */
    // U+002E FULL STOP (.)
    case r == '.':
        // If the input stream starts with a number, reconsume the current input code point, consume a numeric token, and return it.
        r_next, _ := peek_next_character(tokenizer)
        if codepoints.is_ascii_digit(r_next) {
            reconsume(tokenizer)
            return consume_numeric_token(tokenizer)
        }
        else { // Otherwise, return a <delim-token> with its value set to the current input code point.
            return Delim_Token{r}
        }
    // U+003A COLON (:)
    case r == ':':
        // Return a <colon-token>. 
        return Punctuation_Token{':'}

    // U+003B SEMICOLON (;)
    case r == ';':
        // Return a <semicolon-token>. 
        return Punctuation_Token{';'}
    /*
    U+003C LESS-THAN SIGN (<)
        If the next 3 input code points are U+0021 EXCLAMATION MARK U+002D HYPHEN-MINUS U+002D HYPHEN-MINUS (!--), consume them and return a <CDO-token>.

        Otherwise, return a <delim-token> with its value set to the current input code point.
    */
    // U+0040 COMMERCIAL AT (@)
    case r == '@':
        // If the next 3 input code points would start an ident sequence, consume an ident sequence, create an <at-keyword-token> with its value set to the
        // returned value, and return it.
        if would_start_ident_sequence(tokenizer) {
            token := At_Keyword_Token{}
            token.value = consume_ident_sequence(tokenizer)
            return token
        }
        else { // Otherwise, return a <delim-token> with its value set to the current input code point.
            return Delim_Token{r}
        }
    /*
    U+005B LEFT SQUARE BRACKET ([)
        Return a <[-token>. 
    U+005C REVERSE SOLIDUS (\)
        If the input stream starts with a valid escape, reconsume the current input code point, consume an ident-like token, and return it.

        Otherwise, this is a parse error. Return a <delim-token> with its value set to the current input code point.
    U+005D RIGHT SQUARE BRACKET (])
        Return a <]-token>. 
    */
    // U+007B LEFT CURLY BRACKET ({)
    case r == '{':
        // Return a <{-token>. 
        return Punctuation_Token{'{'}

    // U+007D RIGHT CURLY BRACKET (})
    case r == '}':
        // Return a <}-token>. 
        return Punctuation_Token{'}'}

    // digit
    case codepoints.is_ascii_digit(r):
        // Reconsume the current input code point, consume a numeric token, and return it. 
        reconsume(tokenizer)
        return consume_numeric_token(tokenizer)

    // ident-start code point
    case is_ident_start_codepoint(r):
        // Reconsume the current input code point, consume an ident-like token, and return it. 
        reconsume(tokenizer)
        return consume_ident_like_token(tokenizer)
    
    /*
    anything else
        Return a <delim-token> with its value set to the current input code point. 
    */
        case:
            fmt.panicf("Unhandled character %v", r)
    }

    return nil
}

// https://www.w3.org/TR/css-syntax-3/#consume-comments
// This section describes how to consume comments from a stream of code points. It returns nothing.
consume_comments :: proc(tokenizer: ^Css_Tokenizer) {
    for input_starts_with(tokenizer, "/*") {
        // If the next two input code point are U+002F SOLIDUS (/) followed by a U+002A ASTERISK (*), consume them and all following code points up to and
        // including the first U+002A ASTERISK (*) followed by a U+002F SOLIDUS (/), or up to an EOF code point. Return to the start of this step.
        star_found := false
        for {
            r, r_err := get_next_character(tokenizer)
            // If the preceding paragraph ended by consuming an EOF code point, this is a parse error.
            if r_err == .EOF {
                report_parse_error()
                return
            }
            if r == '*' do star_found = true
            if star_found && r == '/' do return
        }
    }
}

// https://www.w3.org/TR/css-syntax-3/#consume-a-string-token
// This section describes how to consume a string token from a stream of code points. It returns either a <string-token> or <bad-string-token>.
// This algorithm may be called with an ending code point, which denotes the code point that ends the string. If an ending code point is not specified, the current
// input code point is used.
consume_string_token :: proc(tokenizer: ^Css_Tokenizer, ending_codepoint: rune) -> Css_Token {
    // Initially create a <string-token> with its value set to the empty string.
    token := String_Token{}
    // Repeatedly consume the next input code point from the stream:
    for {
        r, r_err := get_next_character(tokenizer)
        if r_err == .EOF { // EOF
            // This is a parse error. Return the <string-token>. 
            report_parse_error()
            return token
        }

        switch r {
            // ending code point
            case ending_codepoint:
                // Return the <string-token>. 
                return token

            // newline
            case '\n':
                // This is a parse error. Reconsume the current input code point, create a <bad-string-token>, and return it. 
                report_parse_error()
                reconsume(tokenizer)
                return Bad_String_Token{}

            // U+005C REVERSE SOLIDUS (\)
            case '\\':
                // If the next input code point is EOF, do nothing.
                r_next, r_next_err := peek_next_character(tokenizer)
                if r_next_err == .EOF {
                    // Do nothing
                }
                else if r_next == '\n' { // Otherwise, if the next input code point is a newline, consume it.
                    get_next_character(tokenizer)
                }
                else { // Otherwise, (the stream starts with a valid escape) consume an escaped code point and append the returned code point to the <string-token>’s value.
                    fmt.sbprint(&token.value, consume_escaped_codepoint(tokenizer))
                }

            // anything else
            case:
                // Append the current input code point to the <string-token>’s value. 
                fmt.sbprint(&token.value, r)
        }
    }
}

// https://www.w3.org/TR/css-syntax-3/#consume-ident-like-token
// This section describes how to consume an ident-like token from a stream of code points. It returns an <ident-token>, <function-token>, <url-token>, or <bad-url-token>.
consume_ident_like_token :: proc(tokenizer: ^Css_Tokenizer) -> Css_Token {
    // Consume an ident sequence, and let string be the result.
    str := consume_ident_sequence(tokenizer)
    // @TODO: If string’s value is an ASCII case-insensitive match for "url", and the next input code point is U+0028 LEFT PARENTHESIS ((), consume it. While the next two
    // input code points are whitespace, consume the next input code point. If the next one or two input code points are U+0022 QUOTATION MARK ("), U+0027 APOSTROPHE ('),
    // or whitespace followed by U+0022 QUOTATION MARK (") or U+0027 APOSTROPHE ('), then create a <function-token> with its value set to string and return it. Otherwise, 
    // consume a url token, and return it.
    if false {
        return nil
    }
    
    // Otherwise, if the next input code point is U+0028 LEFT PARENTHESIS ((), consume it. Create a <function-token> with its value set to string and return it.
    if r_next, _ := peek_next_character(tokenizer); r_next == '(' {
        get_next_character(tokenizer)
        return Function_Token{str}
    }

    // Otherwise, create an <ident-token> with its value set to string and return it.
    return Ident_Token{str}
}

// https://www.w3.org/TR/css-syntax-3/#consume-an-ident-sequence
// This section describes how to consume an ident sequence from a stream of code points. It returns a string containing the largest name that can be formed from adjacent code points in the stream, starting from the first.
consume_ident_sequence :: proc(tokenizer: ^Css_Tokenizer) -> string {
    // @Note: This algorithm does not do the verification of the first few code points that are necessary to ensure the returned code points would constitute an <ident-token>. If that is the intended use, ensure that the stream starts with an ident sequence before calling this algorithm.
    // Let result initially be an empty string.
    result: strings.Builder
    // Repeatedly consume the next input code point from the stream:
    for {
        r, r_err := get_next_character(tokenizer)
        switch {
            // ident code point
            case is_ident_codepoint(r):
                // Append the code point to result. 
                fmt.sbprint(&result, r)

            // the stream starts with a valid escape
            case is_valid_escape_sequence(tokenizer):
                // Consume an escaped code point. Append the returned code point to result. 
                fmt.sbprint(&result, consume_escaped_codepoint(tokenizer))

            // anything else
            case:
                // Reconsume the current input code point. Return result. 
                reconsume(tokenizer)
                return strings.to_string(result)
        }
    }
}

// https://www.w3.org/TR/css-syntax-3/#consume-numeric-token
// This section describes how to consume a numeric token from a stream of code points. It returns either a <number-token>, <percentage-token>, or <dimension-token>.
consume_numeric_token :: proc(tokenizer: ^Css_Tokenizer) -> Css_Token {
    // Consume a number and let number be the result.
    number, type := consume_number(tokenizer)
    // If the next 3 input code points would start an ident sequence, then:
    if would_start_ident_sequence(tokenizer) {
        //Create a <dimension-token> with the same value and type flag as number, and a unit set initially to the empty string.
        token := Dimension_Token{value=number, type_flag=type}
        //Consume an ident sequence. Set the <dimension-token>’s unit to the returned value.
        token.unit = consume_ident_sequence(tokenizer)
        //Return the <dimension-token>. 
        return token
    }

    // Otherwise, if the next input code point is U+0025 PERCENTAGE SIGN (%), consume it. Create a <percentage-token> with the same value as number, and return it.
    if r_next, _ := peek_next_character(tokenizer); r_next == '%' {
        get_next_character(tokenizer)
        return Percentage_Token{number}
    }

    // Otherwise, create a <number-token> with the same value and type flag as number, and return it. 
    return Number_Token{number, type}
}

// https://www.w3.org/TR/css-syntax-3/#consume-a-number
// This section describes how to consume a number from a stream of code points. It returns a numeric value, and a type which is either "integer" or "number".

// @Note: This algorithm does not do the verification of the first few code points that are necessary to ensure a number can be obtained from the stream.
// Ensure that the stream starts with a number before calling this algorithm.
consume_number :: proc(tokenizer: ^Css_Tokenizer) -> (value: Numeric_Value, type: Numeric_Type) {
    // Initially set type to "integer". Let repr be the empty string.
    type = .Integer
    repr: strings.Builder

    // If the next input code point is U+002B PLUS SIGN (+) or U+002D HYPHEN-MINUS (-), consume it and append it to repr.
    r_next, _ := peek_next_character(tokenizer)
    if r_next == '+' || r_next == '-' {
        fmt.sbprint(&repr, r_next)
    }
    // While the next input code point is a digit, consume it and append it to repr.
    r_next, _ = peek_next_character(tokenizer)
    for codepoints.is_ascii_digit(r_next) {
        get_next_character(tokenizer)
        fmt.sbprint(&repr, r_next)
        r_next, _ = peek_next_character(tokenizer)
    }
    
    // If the next 2 input code points are U+002E FULL STOP (.) followed by a digit, then:
    r1, _ := peek_next_character(tokenizer)
    r2, _ := peek_character_at_index(tokenizer, 1)
    if r1 == '.' && codepoints.is_ascii_digit(r2) {
        // Consume them.
        get_next_character(tokenizer)
        get_next_character(tokenizer)
        // Append them to repr.
        fmt.sbprintf(&repr, "%v%v", r1, r2)
        // Set type to "number".
        type = .Number
        // While the next input code point is a digit, consume it and append it to repr. 
        r_next, _ = peek_next_character(tokenizer)
        for codepoints.is_ascii_digit(r_next) {
            get_next_character(tokenizer)
            fmt.sbprint(&repr, r_next)
            r_next, _ = peek_next_character(tokenizer)
        }
    }

    // If the next 2 or 3 input code points are U+0045 LATIN CAPITAL LETTER E (E) or U+0065 LATIN SMALL LETTER E (e), optionally followed by U+002D HYPHEN-MINUS
    // (-) or U+002B PLUS SIGN (+), followed by a digit, then:
    r1, _ = peek_next_character(tokenizer)
    r2, _ = peek_character_at_index(tokenizer, 1)
    r3, _ := peek_character_at_index(tokenizer, 2)
    if (r1 == 'e' || r1 == 'E') && (((r2 == '+' || r2 == '-') && codepoints.is_ascii_digit(r3)) || codepoints.is_ascii_digit(r2)) {
        // Consume them.
        get_next_character(tokenizer)
        get_next_character(tokenizer)
        get_next_character(tokenizer)
        // Append them to repr.
        fmt.sbprint(&repr, "%v%v%v", r1, r2, r3)
        // Set type to "number".
        type = .Number
        // While the next input code point is a digit, consume it and append it to repr. 
        r_next, _ = peek_next_character(tokenizer)
        for codepoints.is_ascii_digit(r_next) {
            get_next_character(tokenizer)
            fmt.sbprint(&repr, r_next)
            r_next, _ = peek_next_character(tokenizer)
        }
    }

    // Convert repr to a number, and set the value to the returned value.
    f32_value, f32_ok := strconv.parse_f32(strings.to_string(repr))
    if f32_ok do return f32_value, type

    int_value, int_ok := strconv.parse_int(strings.to_string(repr))
    assert(int_ok)
    return int_value, type
}

would_start_ident_sequence :: proc(tokenizer: ^Css_Tokenizer) -> bool {
    r1, _ := peek_next_character(tokenizer)
    r2, _ := peek_character_at_index(tokenizer, 1)
    r3, _ := peek_character_at_index(tokenizer, 2)
    return would_start_ident_sequence_explicit(r1, r2, r3)
}

// https://www.w3.org/TR/css-syntax-3/#would-start-an-identifier
// This section describes how to check if three code points would start an ident sequence. 
// @Note: This algorithm will not consume any additional code points.
would_start_ident_sequence_explicit :: proc(r1, r2, r3: rune) -> bool {
    // Look at the first code point:

    switch {
        // U+002D HYPHEN-MINUS
        case r1 == '-':
            // If the second code point is an ident-start code point or a U+002D HYPHEN-MINUS, or the second and third code points are a valid escape,
            // return true. Otherwise, return false. 
            return (is_ident_start_codepoint(r2) || r2 == '-') || is_valid_escape_sequence_explicit(r2, r3)

        // ident-start code point
        case is_ident_start_codepoint(r1):
            // Return true. 
            return true

        // U+005C REVERSE SOLIDUS (\)
        case r1 == '/':
            // If the first and second code points are a valid escape, return true. Otherwise, return false. 
            return is_valid_escape_sequence_explicit(r1, r2)

        // anything else
        case:
            // Return false. 
            return false
    }
}

is_valid_escape_sequence :: proc(tokenizer: ^Css_Tokenizer) -> bool {
    r1, _ := peek_next_character(tokenizer)
    r2, _ := peek_character_at_index(tokenizer, 1)
    return is_valid_escape_sequence_explicit(r1, r2)
}

// https://www.w3.org/TR/css-syntax-3/#starts-with-a-valid-escape
// This section describes how to check if two code points are a valid escape.
// @Note: This algorithm will not consume any additional code point.
is_valid_escape_sequence_explicit :: proc(r1, r2: rune) -> bool {
    // If the first code point is not U+005C REVERSE SOLIDUS (\), return false.
    if r1 != '\\' do return false
    // Otherwise, if the second code point is a newline, return false.
    if r2 == '\n' do return false
    // Otherwise, return true.
    return true
}

// https://www.w3.org/TR/css-syntax-3/#consume-escaped-code-point
// This section describes how to consume an escaped code point. It assumes that the U+005C REVERSE SOLIDUS (\) has already been consumed and that the next input code point
// has already been verified to be part of a valid escape. It will return a code point.
consume_escaped_codepoint :: proc(tokenizer: ^Css_Tokenizer) -> rune {
    // Consume the next input code point.
    r, r_err := get_next_character(tokenizer)

    if r_err == .EOF { // EOF
        // This is a parse error. Return U+FFFD REPLACEMENT CHARACTER (�). 
        report_parse_error()
        return '\uFFFD'
    }

    if codepoints.is_hex_digit(r) { // hex digit
        // Consume as many hex digits as possible, but no more than 5. Note that this means 1-6 hex digits have been consumed in total. If the next input code point is
        // whitespace, consume it as well. Interpret the hex digits as a hexadecimal number. If this number is zero, or is for a surrogate, or is greater than the maximum
        // allowed code point, return U+FFFD REPLACEMENT CHARACTER (�). Otherwise, return the code point with that value. 
        repr: strings.Builder
        defer strings.builder_destroy(&repr)
        fmt.sbprint(&repr, r)
        for i in 0..<5 {
            r_next, _ := peek_next_character(tokenizer)
            if !codepoints.is_hex_digit(r_next) do break
            fmt.sbprint(&repr, r_next)
        }

        hex_number, ok := strconv.parse_int(strings.to_string(repr), 16)
        assert(ok)
        if hex_number == 0 || hex_number > cast(int)codepoints.MAX_CODEPOINT || codepoints.is_surrogate(cast(rune)hex_number) {
            return '\uFFFD'
        }
        return cast(rune)hex_number
    }
    else { // anything else
        // Return the current input code point. 
        return r
    }
}
