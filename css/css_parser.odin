package css

import "core:io"
import "core:container/queue"

Css_Token :: struct {}

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

get_next_character :: proc(tokenizer: ^Css_Tokenizer) -> (char: rune, error: io.Error) {
    if queue.len(tokenizer.consumed_characters) == 0 {
        err := consume_character_from_input_stream(tokenizer)
        if err != .None do return 0, err
    }
    tokenizer.last_character = queue.pop_front(&tokenizer.consumed_characters)
    return tokenizer.last_character, .None
}

Css_Parser :: struct { 
    tokenizer: ^Css_Tokenizer,
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
