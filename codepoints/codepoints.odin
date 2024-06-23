package codepoints

// https://www.w3.org/TR/css-syntax-3/#maximum-allowed-code-point
// The greatest code point defined by Unicode: U+10FFFF.
MAX_CODEPOINT :: '\U0010FFFF'

// https://infra.spec.whatwg.org/#leading-surrogate
// A leading surrogate is a code point that is in the range U+D800 to U+DBFF, inclusive. 
is_leading_surrogate :: proc(r: rune) -> bool {
    return r >= '\uD800' && r <= '\uDBFF'
}

// https://infra.spec.whatwg.org/#trailing-surrogate
// A trailing surrogate is a code point that is in the range U+DC00 to U+DFFF, inclusive.
is_trailing_surrogate :: proc(r: rune) -> bool {
    return r >= '\uDC00' && r <= '\uDFFF'
}

// https://infra.spec.whatwg.org/#surrogate
// A surrogate is a leading surrogate or a trailing surrogate. 
is_surrogate :: proc(r: rune) -> bool {
    return is_leading_surrogate(r) || is_trailing_surrogate(r)
}

// https://infra.spec.whatwg.org/#ascii-upper-alpha
// An ASCII upper alpha is a code point in the range U+0041 (A) to U+005A (Z), inclusive. 
is_ascii_upper_alpha :: proc(r: rune) -> bool {
    return r >= 'A' && r <= 'Z'
}

// https://infra.spec.whatwg.org/#ascii-lower-alpha
// An ASCII lower alpha is a code point in the range U+0061 (a) to U+007A (z), inclusive. 
is_ascii_lower_alpha :: proc(r: rune) -> bool {
    return r >= 'a'  && r <= 'z'
}

// https://infra.spec.whatwg.org/#ascii-alpha
// An ASCII alpha is an ASCII upper alpha or ASCII lower alpha. 
is_ascii_alpha :: proc(r: rune) -> bool {
    return is_ascii_upper_alpha(r) || is_ascii_lower_alpha(r)
}

// https://infra.spec.whatwg.org/#ascii-whitespace
// ASCII whitespace is U+0009 TAB, U+000A LF, U+000C FF, U+000D CR, or U+0020 SPACE.
is_ascii_whitespace :: proc(r: rune) -> bool {
    return r == '\t' || r == '\n' || r == '\f' || r == '\r' || r == ' '
}

// https://infra.spec.whatwg.org/#ascii-digit
// An ASCII digit is a code point in the range U+0030 (0) to U+0039 (9), inclusive.
is_ascii_digit :: proc(r: rune) -> bool {
    return r >= '0' && r <= '9'
}

// https://infra.spec.whatwg.org/#ascii-alphanumeric
// An ASCII alphanumeric is an ASCII digit or ASCII alpha.
is_ascii_alphanumeric :: proc(r: rune) -> bool {
    return is_ascii_alpha(r) || is_ascii_digit(r)
}

// https://infra.spec.whatwg.org/#noncharacter
/*
A noncharacter is a code point that is in the range U+FDD0 to U+FDEF, inclusive, or U+FFFE, U+FFFF, U+1FFFE, U+1FFFF, U+2FFFE, U+2FFFF, U+3FFFE, U+3FFFF,
U+4FFFE, U+4FFFF, U+5FFFE, U+5FFFF, U+6FFFE, U+6FFFF, U+7FFFE, U+7FFFF, U+8FFFE, U+8FFFF, U+9FFFE, U+9FFFF, U+AFFFE, U+AFFFF, U+BFFFE, U+BFFFF, U+CFFFE,
U+CFFFF, U+DFFFE, U+DFFFF, U+EFFFE, U+EFFFF, U+FFFFE, U+FFFFF, U+10FFFE, or U+10FFFF.
*/
is_noncharacter :: proc(r: rune) -> bool {
    return (r >= '\uFDD0' && r <= '\uFDEF') \
        || r == '\uFFFE' \
        || r == '\uFFFF' \
        || r == '\U0001FFFE' \
        || r == '\U0001FFFF' \
        || r == '\U0002FFFE' \
        || r == '\U0002FFFF' \
        || r == '\U0003FFFE' \
        || r == '\U0003FFFF' \
        || r == '\U0004FFFE' \
        || r == '\U0004FFFF' \
        || r == '\U0005FFFE' \
        || r == '\U0005FFFF' \
        || r == '\U0006FFFE' \
        || r == '\U0006FFFF' \
        || r == '\U0007FFFE' \
        || r == '\U0007FFFF' \
        || r == '\U0008FFFE' \
        || r == '\U0008FFFF' \
        || r == '\U0009FFFE' \
        || r == '\U0009FFFF' \
        || r == '\U000AFFFE' \
        || r == '\U000AFFFF' \
        || r == '\U000BFFFE' \
        || r == '\U000BFFFF' \
        || r == '\U000CFFFE' \
        || r == '\U000CFFFF' \
        || r == '\U000DFFFE' \
        || r == '\U000DFFFF' \
        || r == '\U000EFFFE' \
        || r == '\U000EFFFF' \
        || r == '\U000FFFFE' \
        || r == '\U000FFFFF' \
        || r == '\U0010FFFE' \
        || r == '\U0010FFFF'
}

// https://infra.spec.whatwg.org/#c0-control
// A C0 control is a code point in the range U+0000 NULL to U+001F INFORMATION SEPARATOR ONE, inclusive.
is_c0_control :: proc(r: rune) -> bool {
    return r >= '\u0000' && r <= '\u001F'
}

// https://infra.spec.whatwg.org/#control
// A control is a C0 control or a code point in the range U+007F DELETE to U+009F APPLICATION PROGRAM COMMAND, inclusive. 
is_control :: proc(r: rune) -> bool {
    return is_c0_control(r) || (r >= '\u007F' && r <= '\u009F')
}

// https://www.w3.org/TR/css-syntax-3/#non-ascii-code-point
// A code point with a value equal to or greater than U+0080 <control>.
is_non_ascii :: proc(r: rune) -> bool {
    return r >= '\u0080'
}

// https://www.w3.org/TR/css-syntax-3/#hex-digit
// A digit, or a code point between U+0041 LATIN CAPITAL LETTER A (A) and U+0046 LATIN CAPITAL LETTER F (F) inclusive, or a code point between U+0061
// LATIN SMALL LETTER A (a) and U+0066 LATIN SMALL LETTER F (f) inclusive.
is_hex_digit :: proc(r: rune) -> bool {
    return is_ascii_digit(r) || (r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f')
}
