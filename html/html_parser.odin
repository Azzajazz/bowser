package html

import "core:strings"
import "core:fmt"
import "core:io"
import "core:slice"
import "core:os"
import "core:unicode"
import "core:container/queue"

import "vendor:sdl2"
import "vendor:sdl2/ttf"

import "../codepoints"

string_is_any_of :: proc(to_match: string, options: ..string) -> bool {
    return slice.contains(options, to_match)
}

HTML_NAMESPACE :: "http://www.w3.org/1999/xhtml"

// https://html.spec.whatwg.org/#parse-errors
Parse_Error :: enum {
    /*
    This error occurs if the parser encounters an empty comment that is abruptly closed by a U+003E (>) code point (i.e., <!--> or <!--->).
    The parser behaves as if the comment is closed correctly.
    */
    AbruptClosingOfEmptyComment,	

    /*
    This error occurs if the parser encounters a U+003E (>) code point in the DOCTYPE public identifier (e.g., <!DOCTYPE html PUBLIC "foo>).
    In such a case, if the DOCTYPE is correctly placed as a document preamble, the parser sets the Document to quirks mode.
    */
    AbruptDoctypePublicIdentifier,

    /*
    This error occurs if the parser encounters a U+003E (>) code point in the DOCTYPE system identifier (e.g., <!DOCTYPE html PUBLIC 
    "-//W3C//DTD HTML 4.01//EN" "foo>). In such a case, if the DOCTYPE is correctly placed as a document preamble, the parser sets the
    Document to quirks mode.
    */
    AbruptDoctypeSystemIdentifier,

    /*
    This error occurs if the parser encounters a numeric character reference that doesn't contain any digits (e.g., &#qux;). In this
    case the parser doesn't resolve the character reference.
    */
    AbsenceOfDigitsInNumericCharacterReference,

    /*
    This error occurs if the parser encounters a CDATA section outside of foreign content (SVG or MathML). The parser treats such CDATA
    sections (including leading "[CDATA[" and trailing "]]" strings) as comments.
    */
    CDataInHtmlContent,

    /*
    This error occurs if the parser encounters a numeric character reference that references a code point that is greater than the valid
    Unicode range. The parser resolves such a character reference to a U+FFFD REPLACEMENT CHARACTER.
    */
    CharacterReferenceOutsideUnicodeRange,

    /*
    This error occurs if the input stream contains a control code point that is not ASCII whitespace or U+0000 NULL. Such code points are
    parsed as-is and usually, where parsing rules don't apply any additional restrictions, make their way into the DOM.
    */
    ControlCharacterInInputStream,

    /*
    This error occurs if the parser encounters a numeric character reference that references a control code point that is not ASCII
    whitespace or is a U+000D CARRIAGE RETURN. The parser resolves such character references asIs except C1 control references that are
    replaced according to the numeric character reference end state.
    */
    ControlCharacterReference,

    /*
    This error occurs if the parser encounters an attribute in a tag that already has an attribute with the same name. The parser
    ignores all such duplicate occurrences of the attribute.
    */
    DuplicateAttribute,

    /*
    This error occurs if the parser encounters an end tag with attributes. Attributes in end tags are ignored and do not make their
    way into the DOM.
    */
    EndTagWithAttributes,

    /*
    This error occurs if the parser encounters an end tag that has a U+002F (/) code point right before the closing U+003E (>) code
    point (e.g., </div/>). Such a tag is treated as a regular end tag.
    */
    EndTagWithTrailingSolidus,

    /*
    This error occurs if the parser encounters the end of the input stream where a tag name is expected. In this case the parser treats
    the beginning of a start tag (i.e., <) or an end tag (i.e., </) as text content.
    */
    EofBeforeTagName,

    /*
    This error occurs if the parser encounters the end of the input stream in a CDATA section. The parser treats such CDATA sections as if
    they are closed immediately before the end of the input stream.
    */
    EofInCdata,

    /*
    This error occurs if the parser encounters the end of the input stream in a comment. The parser treats such comments as if they are closed
    immediately before the end of the input stream.
    */
    EofInComment,

    /*
    This error occurs if the parser encounters the end of the input stream in a DOCTYPE. In such a case, if the DOCTYPE is correctly placed as
    a document preamble, the parser sets the Document to quirks mode.
    */
    EofInDoctype,

    /*
    This error occurs if the parser encounters the end of the input stream in text that resembles an HTML comment inside script element content
    (e.g., <script><!-- foo).
    */
    EofInScriptHtmlCommentLikeText,

    /*
    This error occurs if the parser encounters the end of the input stream in a start tag or an end tag (e.g., <div id=). Such a tag is ignored.
    */
    EofInTag,

    /*
    This error occurs if the parser encounters a comment that is closed by the "--!>" code point sequence. The parser treats such comments as if
    they are correctly closed by the "-->" code point sequence.
    */
    IncorrectlyClosedComment,

    /*
    This error occurs if the parser encounters the "<!" code point sequence that is not immediately followed by two U+002D (-) code points and
    that is not the start of a DOCTYPE or a CDATA section. All content that follows the "<!" code point sequence up to a U+003E (>) code point
    (if present) or to the end of the input stream is treated as a comment.
    */
    IncorrectlyOpenedComment,

    /*
    This error occurs if the parser encounters any code point sequence other than "PUBLIC" and "SYSTEM" keywords after a DOCTYPE name. In such
    a case, the parser ignores any following public or system identifiers, and if the DOCTYPE is correctly placed as a document preamble, and
    if the parser cannot change the mode flag is false, sets the Document to quirks mode.
    */
    InvalidCharacterSequenceAfterDoctypeName,

    /*
    This error occurs if the parser encounters a code point that is not an ASCII alpha where first code point of a start tag name or an end tag
    name is expected. If a start tag was expected such code point and a preceding U+003C (<) is treated as text content, and all content that
    follows is treated as markup. Whereas, if an end tag was expected, such code point and all content that follows up to a U+003E (>) code point
    (if present) or to the end of the input stream is treated as a comment.
    */
    InvalidFirstCharacterOfTagName,

    /*
    This error occurs if the parser encounters a U+003E (>) code point where an attribute value is expected (e.g., <div id=>). The parser treats
    the attribute as having an empty value.
    */
    MissingAttributeValue,

    /*
    This error occurs if the parser encounters a DOCTYPE that is missing a name (e.g., <!DOCTYPE>). In such a case, if the DOCTYPE is correctly
    placed as a document preamble, the parser sets the Document to quirks mode.
    */
    MissingDoctypeName,

    /*
    This error occurs if the parser encounters a U+003E (>) code point where start of the DOCTYPE public identifier is expected
    (e.g., <!DOCTYPE html PUBLIC >). In such a case, if the DOCTYPE is correctly placed as a document preamble, the parser sets the Document to
    quirks mode.
    */
    MissingDoctypePublicIdentifier,

    /*
    This error occurs if the parser encounters a U+003E (>) code point where start of the DOCTYPE system identifier is expected
    (e.g., <!DOCTYPE html SYSTEM >). In such a case, if the DOCTYPE is correctly placed as a document preamble, the parser sets the Document to
    quirks mode.
    */
    MissingDoctypeSystemIdentifier,

    /*
    This error occurs if the parser encounters a U+003E (>) code point where an end tag name is expected, i.e., </>. The parser ignores the whole
    "</>" code point sequence.
    */
    MissingEndTagName,

    /*
    This error occurs if the parser encounters the DOCTYPE public identifier that is not preceded by a quote
    (e.g., <!DOCTYPE html PUBLIC -//W3C//DTD HTML 4.01//EN">). In such a case, the parser ignores the public identifier, and if the DOCTYPE is
    correctly placed as a document preamble, sets the Document to quirks mode.
    */
    MissingQuoteBeforeDoctypePublicIdentifier,

    /*
    This error occurs if the parser encounters the DOCTYPE system identifier that is not preceded by a quote
    (e.g., <!DOCTYPE html SYSTEM http://www.w3.org/TR/xhtml1/DTD/xhtml1Transitional.dtd">). In such a case, the parser ignores the system
    identifier, and if the DOCTYPE is correctly placed as a document preamble, sets the Document to quirks mode.
    */
    MissingQuoteBeforeDoctypeSystemIdentifier,

    /*
    This error occurs if the parser encounters a character reference that is not terminated by a U+003B (;) code point. Usually the parser
    behaves as if character reference is terminated by the U+003B (;) code point; however, there are some ambiguous cases in which the parser
    includes subsequent code points in the character reference.
    */
    MissingSemicolonAfterCharacterReference,

    /*
    This error occurs if the parser encounters a DOCTYPE whose "SYSTEM" keyword and system identifier are not separated by ASCII whitespace. In
    this case the parser behaves as if ASCII whitespace is present.
    */
    MissingWhitespaceAfterDoctypeSystemKeyword,

    /*
    This error occurs if the parser encounters a DOCTYPE whose "DOCTYPE" keyword and name are not separated by ASCII whitespace. In this case
    the parser behaves as if ASCII whitespace is present.
    */
    MissingWhitespaceBeforeDoctypeName,

    /*
    This error occurs if the parser encounters attributes that are not separated by ASCII whitespace (e.g., <div id="foo"class="bar">). In this
    case the parser behaves as if ASCII whitespace is present.
    */
    MissingWhitespaceBetweenAttributes,

    /*
    This error occurs if the parser encounters a DOCTYPE whose public and system identifiers are not separated by ASCII whitespace. In this
    case the parser behaves as if ASCII whitespace is present.
    */
    MissingWhitespaceBetweenDoctypePublicAndSystemIdentifiers,

    /*
    This error occurs if the parser encounters a nested comment (e.g., <!-- <!-- nested --> -->). Such a comment will be closed by the first
    occurring "-->" code point sequence and everything that follows will be treated as markup.
    */
    NestedComment,

    /*
    This error occurs if the parser encounters a numeric character reference that references a noncharacter. The parser resolves such character
    references as-is.
    */
    NoncharacterCharacterReference,

    /*
    This error occurs if the input stream contains a noncharacter. Such code points are parsed asIs and usually, where parsing rules don't apply
    any additional restrictions, make their way into the DOM.
    */
    NoncharacterInInputStream,

    /*
    This error occurs if the parser encounters a start tag for an element that is not in the list of void elements or is not a part of foreign
    content (i.e., not an SVG or MathML element) that has a U+002F (/) code point right before the closing U+003E (>) code point. The parser
    behaves as if the U+002F (/) is not present.
    */
    NonVoidHtmlElementStartTagWithTrailingSolidus,

    /*
    This error occurs if the parser encounters a numeric character reference that references a U+0000 NULL code point. The parser resolves such
    character references to a U+FFFD REPLACEMENT CHARACTER.
    */
    NullCharacterReference,

    /*
    This error occurs if the parser encounters a numeric character reference that references a surrogate. The parser resolves such character
    references to a U+FFFD REPLACEMENT CHARACTER.
    */
    SurrogateCharacterReference,

    /*
    This error occurs if the input stream contains a surrogate. Such code points are parsed asIs and usually, where parsing rules don't apply
    any additional restrictions, make their way into the DOM.
    */
    SurrogateInInputStream,

    /*
    This error occurs if the parser encounters any code points other than ASCII whitespace or closing U+003E (>) after the DOCTYPE system identifier.
    The parser ignores these code points.
    */
    UnexpectedCharacterAfterDoctypeSystemIdentifier,

    /*
    This error occurs if the parser encounters a U+0022 ("), U+0027 ('), or U+003C (<) code point in an attribute name. The parser includes such
    code points in the attribute name.
    */
    UnexpectedCharacterInAttributeName,

    /*
    This error occurs if the parser encounters a U+0022 ("), U+0027 ('), U+003C (<), U+003D (=), or U+0060 (`) code point in an unquoted attribute
    value. The parser includes such code points in the attribute value.
    */
    UnexpectedCharacterInUnquotedAttributeValue,

    /*
    This error occurs if the parser encounters a U+003D (=) code point before an attribute name. In this case the parser treats U+003D (=) as the
    first code point of the attribute name.
    */
    UnexpectedEqualsSignBeforeAttributeName,

    /*
    This error occurs if the parser encounters a U+0000 NULL code point in the input stream in certain positions. In general, such code points are
    either ignored or, for security reasons, replaced with a U+FFFD REPLACEMENT CHARACTER.
    */
    UnexpectedNullCharacter,

    /*
    This error occurs if the parser encounters a U+003F (?) code point where first code point of a start tag name is expected. The U+003F (?) and all
    content that follows up to a U+003E (>) code point (if present) or to the end of the input stream is treated as a comment.
    */
    UnexpectedQuestionMarkInsteadOfTagName,

    /*
    This error occurs if the parser encounters a U+002F (/) code point that is not a part of a quoted attribute value and not immediately followed by
    a U+003E (>) code point in a tag (e.g., <div / id="foo">). In this case the parser behaves as if it encountered ASCII whitespace.
    */
    UnexpectedSolidusInTag,

    /*
    This error occurs if the parser encounters an ambiguous ampersand. In this case the parser doesn't resolve the character reference.
    */
    UnknownNamedCharacterReference,

    // Used for parse errors in the tree construction stage
    ErrorInTreeConstruction,
}

report_parse_error :: proc(error: Parse_Error, location := #caller_location) {
    fmt.eprintfln("[ERROR:Html Parser] %s, %s", error, location)
    if error == .ErrorInTreeConstruction do os.exit(1)
}

// https://html.spec.whatwg.org/#the-insertion-mode
// The insertion mode is a state variable that controls the primary operation of the tree construction stage.
Insertion_Mode :: enum {
    Initial,
    BeforeHtml,
    BeforeHead,
    InHead,
    InHeadNoscript,
    AfterHead,
    InBody,
    Text,
    InTable,
    InTableText,
    InCaption,
    InColumnGroup,
    InTableBody,
    InRow,
    InCell,
    InSelect,
    InSelectInTable,
    InTemplate,
    AfterBody,
    InFrameset,
    AfterFrameset,
    AfterAfterBody,
    AfterAfterFrameset,
}

// https://html.spec.whatwg.org/#tokenization
Html_Token :: union {
    Doctype_Token,
    Tag_Token,
    Comment_Token,
    Character_Token,
    Eof_Token,
}

is_eof :: proc(token: Html_Token) -> bool {
    _, ok := token.(Eof_Token)
    return ok
}

print_token :: proc(token: Html_Token) {
    switch t in token {
        case Doctype_Token:
            fmt.print("DOCTYPE(")
            if t.name_present do fmt.printf("name=%q", strings.to_string(t.name))
            if t.system_id_present do fmt.printf(", SYSTEM=%q", strings.to_string(t.system_id))
            if t.public_id_present do fmt.printf(", PUBLIC=%q", strings.to_string(t.public_id))
            fmt.println(")")

        case Tag_Token:
            if t.is_start do fmt.print("Start_Tag")
            else do fmt.print("End_Tag")
            fmt.printf("(name=%v, self_closing=%v", strings.to_string(t.name), t.self_closing)
            if t.attributes != nil {
                fmt.println(", attributes={")
                for attr in t.attributes {
                    fmt.printfln("  %q=%q,", strings.to_string(attr.name), strings.to_string(attr.value))
                }
                fmt.print("}")
            }
            fmt.println(")")

        case Character_Token:
            fmt.printfln("Character(%v)", t.data)

        case Comment_Token:
            fmt.printfln("Comment(%v)", t.data)

        case Eof_Token:
            fmt.println("EOF")
    }
}

// https://html.spec.whatwg.org/#tokenization
Doctype_Token :: struct {
    name: strings.Builder,
    name_present: bool,
    public_id: strings.Builder,
    public_id_present: bool,
    system_id: strings.Builder,
    system_id_present: bool,
    force_quirks: bool,
}

set_doctype_name :: proc(token: ^Doctype_Token, name: rune) {
    assert(!token.name_present)
    token.name_present = true
    fmt.sbprint(&token.name, name)
}

Attribute :: struct {
    name: strings.Builder,
    value: strings.Builder,
}

// https://html.spec.whatwg.org/#tokenization
Tag_Token :: struct {
    is_start: bool,
    name: strings.Builder,
    self_closing: bool,
    attributes: [dynamic]Attribute,
}

Comment_Token :: struct {
    data: strings.Builder,
}

Character_Token :: struct {
    data: rune,
}

Eof_Token :: struct {}

Html_Tokenizer_State :: enum {
    Data,
    CharacterReference,
    TagOpen,
    RawText,
    RawTextLessThanSign,
    RCData,
    RCDataLessThanSign,
    RCDataEndTagOpen,
    RCDataEndTagName,
    MarkupDeclarationOpen,
    EndTagOpen,
    BogusComment,
    CommentStart,
    Doctype,
    BeforeDoctypeName,
    DoctypeName,
    AfterDoctypeName,
    TagName,
    BeforeAttributeName,
    SelfClosingStartTag,
    AfterAttributeName,
    AttributeName,
    BeforeAttributeValue,
    AttributeValueDoubleQuoted,
    AttributeValueSingleQuoted,
    AttributeValueUnquoted,
    AfterAttributeValueQuoted,
    NumericCharacterReference,
    NamedCharacterReference,
    AmbiguousAmpersand,
    Plaintext,
    RawTextEndTagOpen,
    RawTextEndTagName,
}

Html_Tokenizer :: struct {
    input_stream: io.Reader,
    consumed_characters: queue.Queue(rune), // Peeked characters are stored here
    // @NOTE: Maybe this can be used to eliminate the need for last_character

    state: Html_Tokenizer_State,
    return_state: Html_Tokenizer_State,
    temporary_buffer: strings.Builder, // Used for character references

    current_token: Html_Token,
    // Pointer to the last attribute in the list for the current_token. Ignored if current_token does not have attributes
    current_attribute: ^Attribute,

    // Used for reconsuming
    last_character: rune,

    // Used for determining if an end tag is appropriate (see https://html.spec.whatwg.org/#appropriate-end-tag-token)
    last_start_tag_name: string,
    
    // Holds the tokens that are to be emitted. We use a queue because the specification sometimes forces the tokenizer to emit multiple tokens.
    to_emit: queue.Queue(Html_Token),
}

tokenizer_init :: proc(tokenizer: ^Html_Tokenizer, input_stream: io.Reader) {
    tokenizer.input_stream = input_stream
    tokenizer.state = .Data
    tokenizer.return_state = .Data
}

emit :: proc(tokenizer: ^Html_Tokenizer, token: Html_Token) {
    queue.push_back(&tokenizer.to_emit, token)
    if tag, is_tag := token.(Tag_Token); is_tag && tag.is_start {
        tokenizer.last_start_tag_name = strings.to_string(tag.name)
    }
}

// https://html.spec.whatwg.org/#appropriate-end-tag-token
// An appropriate end tag token is an end tag token whose tag name matches the tag name of the last start tag to have been emitted from this tokenizer,
// if any. If no start tag has been emitted from this tokenizer, then no end tag token is appropriate.
is_appropriate_end_tag :: proc(tokenizer: ^Html_Tokenizer) -> bool {
    tag, is_tag := tokenizer.current_token.(Tag_Token)
    return is_tag && !tag.is_start && strings.to_string(tag.name) == tokenizer.last_start_tag_name
}

// https://html.spec.whatwg.org/#flush-code-points-consumed-as-a-character-reference
flush_code_points :: proc(tokenizer: ^Html_Tokenizer) {
    #partial switch tokenizer.return_state {
        case .AttributeValueDoubleQuoted: fallthrough
        case .AttributeValueSingleQuoted: fallthrough
        case .AttributeValueUnquoted:
           fmt.sbprint(&tokenizer.current_attribute.value, strings.to_string(tokenizer.temporary_buffer))
        case:
            for r in strings.to_string(tokenizer.temporary_buffer) {
                emit(tokenizer, Character_Token{r})
            }
    }

    strings.builder_reset(&tokenizer.temporary_buffer)
}

input_starts_with :: proc(tokenizer: ^Html_Tokenizer, prefix: string) -> bool {
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

input_starts_with_case_insensitive :: proc(tokenizer: ^Html_Tokenizer, prefix: string) -> bool {
    prefix_len := len(prefix)
    for prefix_len > queue.len(tokenizer.consumed_characters) {
        consume_character_from_input_stream(tokenizer)
    }

    for r, index in prefix {
        peeked_index := (index + cast(int)tokenizer.consumed_characters.offset) % len(tokenizer.consumed_characters.data)
        if unicode.to_lower(r) != unicode.to_lower(tokenizer.consumed_characters.data[peeked_index]) do return false
    }
    return true
}

consume :: proc(tokenizer: ^Html_Tokenizer, prefix: string) {
    prefix_len := len(prefix)
    to_consume_from_peeked := min(prefix_len, queue.len(tokenizer.consumed_characters))
    queue.consume_front(&tokenizer.consumed_characters, to_consume_from_peeked)

    io.seek(tokenizer.input_stream, cast(i64)(prefix_len - to_consume_from_peeked), .Current)
}

get_maximal_character_reference :: proc(tokenizer: ^Html_Tokenizer) -> (entry: Reference_Entry, found: bool) {
    for entry in charref_table {
        if input_starts_with(tokenizer, entry.name) {
            consume(tokenizer, entry.name)
            return entry, true
        }
    }
    return Reference_Entry{}, false
}

reconsume :: proc(tokenizer: ^Html_Tokenizer) {
    queue.push_front(&tokenizer.consumed_characters, tokenizer.last_character) 
}

get_next_character :: proc(tokenizer: ^Html_Tokenizer) -> (char: rune, error: io.Error) {
    if queue.len(tokenizer.consumed_characters) == 0 {
        err := consume_character_from_input_stream(tokenizer)
        if err != .None do return 0, err
    }
    tokenizer.last_character = queue.pop_front(&tokenizer.consumed_characters)
    return tokenizer.last_character, .None
}

DEBUG_print_next_few_characters :: proc(tokenizer: ^Html_Tokenizer, n: int) {
    for i in 0..<n {
        r, r_err := get_next_character(tokenizer)
        fmt.print(r)
    }
    fmt.println()
    os.exit(1)
}

peek_next_character :: proc(tokenizer: ^Html_Tokenizer) -> (char: rune, error: io.Error) {
    if queue.len(tokenizer.consumed_characters) == 0 {
        err := consume_character_from_input_stream(tokenizer)
        if err != .None do return 0, err
    }
    return queue.peek_front(&tokenizer.consumed_characters)^, .None
}

// https://html.spec.whatwg.org/#preprocessing-the-input-stream
consume_character_from_input_stream :: proc(tokenizer: ^Html_Tokenizer) -> io.Error {
    r, _, err := io.read_rune(tokenizer.input_stream)
    if err != .None do return err

    // Before the tokenization stage, the input stream must be preprocessed by normalizing newlines.
    // https://infra.spec.whatwg.org/#normalize-newlines
    /*
    To normalize newlines in a string, replace every U+000D CR U+000A LF code point pair with a single U+000A LF code point, and then replace
    every remaining U+000D CR code point with a U+000A LF code point.
    */
    for r == '\r' {
        r_next, _, next_err := io.read_rune(tokenizer.input_stream)
        if next_err != .None do return next_err
        if r_next != '\n' {
            r = r_next
            break
        }

        r, _, err = io.read_rune(tokenizer.input_stream)
        if err != .None do return err
    }


    // Any occurrences of surrogates are surrogate-in-input-stream parse errors.
    if codepoints.is_surrogate(r) do report_parse_error(.SurrogateInInputStream)
    // Any occurrences of noncharacters are noncharacter-in-input-stream parse errors
    if codepoints.is_noncharacter(r) do report_parse_error(.NoncharacterInInputStream)
    // and any occurrences of controls other than ASCII whitespace and U+0000 NULL characters are control-character-in-input-stream parse errors.
    if codepoints.is_control(r) && r != ' ' && r != '\u0000' {
        report_parse_error(.ControlCharacterInInputStream)
    }

    queue.push_back(&tokenizer.consumed_characters, r)
    return .None
}

add_attribute_to_current_token :: proc(tokenizer: ^Html_Tokenizer) {
    tag := &tokenizer.current_token.(Tag_Token)
    append(&tag.attributes, Attribute{})
    tokenizer.current_attribute = slice.last_ptr(tag.attributes[:])
}

get_next_token :: proc(tokenizer: ^Html_Tokenizer) -> Html_Token {
    for queue.len(tokenizer.to_emit) == 0 {
        // fmt.printfln("In %s state", tokenizer.state)
        #partial switch tokenizer.state {
            // Data state
            case .Data: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // Emit an end-of-file token.
                    emit(tokenizer, Eof_Token{})
                }
                else if r == '&' { // U+0026 AMPERSAND (&)
                    // Set the return state to the data state. Switch to the character reference state.
                    tokenizer.return_state = .Data
                    tokenizer.state = .CharacterReference
                }
                else if r == '<' { // U+003C LESS-THAN SIGN (<)
                    // Switch to the tag open state.
                    tokenizer.state = .TagOpen
                }
                else if r == '\u0000' { // U+0000 NULL
                    // This is an unexpected-null-character parse error. Emit the current input character as a character token.
                    report_parse_error(.UnexpectedNullCharacter)
                    emit(tokenizer, Character_Token{r})
                }
                else { // Anything else
                    // Emit the current input character as a character token.
                    emit(tokenizer, Character_Token{r})
                }
            }

            // RCDATA state
            case .RCData: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // Emit an end-of-file token.
                    emit(tokenizer, Eof_Token{})
                }
                else if r == '&' { // U+0026 AMPERSAND (&)
                    // Set the return state to the RCDATA state. Switch to the character reference state.
                    tokenizer.return_state = .RCData
                    tokenizer.state = .CharacterReference
                }
                else if r == '<' { // U+003C LESS-THAN SIGN (<)
                    // Switch to the RCDATA less-than sign state.
                    tokenizer.state = .RCDataLessThanSign
                }
                else if r == '\u0000' { // U+0000 NULL
                    // This is an unexpected-null-character parse error. Emit a U+FFFD REPLACEMENT CHARACTER character token.
                    report_parse_error(.UnexpectedNullCharacter)
                    emit(tokenizer, Character_Token{'\uFFFD'})
                }
                else { // Anything else
                    // Emit the current input character as a character token.
                    emit(tokenizer, Character_Token{r})
                }
            }

            // RAWTEXT state
            case .RawText: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // Emit an end-of-file token.
                    emit(tokenizer, Eof_Token{})
                }
                else if r == '<' { // U+003C LESS-THAN SIGN (<)
                    // Switch to the RAWTEXT less-than sign state.
                    tokenizer.state = .RawTextLessThanSign
                }
                else if r == '\u0000' { // U+0000 NULL
                    // This is an unexpected-null-character parse error. Emit a U+FFFD REPLACEMENT CHARACTER character token.
                    report_parse_error(.UnexpectedNullCharacter)
                    emit(tokenizer, Character_Token{'\uFFFD'})
                }
                else { // Anything else
                    // Emit the current input character as a character token.
                    emit(tokenizer, Character_Token{r})
                }
            }

            // Tag open state
            case .TagOpen: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // This is an eof-before-tag-name parse error. Emit a U+003C LESS-THAN SIGN character token and an end-of-file token.
                    report_parse_error(.EofBeforeTagName)
                    emit(tokenizer, Character_Token{'<'})
                    emit(tokenizer, Eof_Token{})
                }
                else if r == '!' { // U+0021 EXCLAMATION MARK (!)
                    // Switch to the markup declaration open state.
                    tokenizer.state = .MarkupDeclarationOpen
                }
                else if r == '/' { // U+002F SOLIDUS (/)
                    // Switch to the end tag open state.
                    tokenizer.state = .EndTagOpen
                }
                else if codepoints.is_ascii_alpha(r) { // ASCII alpha
                    // Create a new start tag token, set its tag name to the empty string. Reconsume in the tag name state.
                    tokenizer.current_token = Tag_Token{is_start = true}
                    reconsume(tokenizer)
                    tokenizer.state = .TagName
                }
                else if r == '?' { // U+003F QUESTION MARK (?)
                    // This is an unexpected-question-mark-instead-of-tag-name parse error. Create a comment token whose data
                    // is the empty string. Reconsume in the bogus comment state.
                    report_parse_error(.UnexpectedQuestionMarkInsteadOfTagName)
                    tokenizer.current_token = Comment_Token{}
                    reconsume(tokenizer)
                    tokenizer.state = .BogusComment
                }
                else { // Anything else
                    // This is an invalid-first-character-of-tag-name parse error. Emit a U+003C LESS-THAN SIGN character token. Reconsume in the data state.
                    report_parse_error(.InvalidFirstCharacterOfTagName)
                    reconsume(tokenizer)
                    tokenizer.state = .Data
                    emit(tokenizer, Character_Token{'<'})
                }
            }

            // Markup declaration open state
            case .MarkupDeclarationOpen: {
                // If the next few characters are:
                if input_starts_with(tokenizer, "--") { // Two U+002D HYPHEN-MINUS characters (-)
                    // Consume those two characters, create a comment token whose data is the empty string, and switch to the comment start state.
                    consume(tokenizer, "--")
                    tokenizer.current_token = Comment_Token{}
                    tokenizer.state = .CommentStart
                }
                else if input_starts_with_case_insensitive(tokenizer, "DOCTYPE") { // ASCII case-insensitive match for the word "DOCTYPE"
                    // Consume those characters and switch to the DOCTYPE state.
                    consume(tokenizer, "DOCTYPE")
                    tokenizer.state = .Doctype
                }
                else if input_starts_with(tokenizer, "[CDATA[") { // The string "[CDATA["
                    // Consume those characters. If there is an adjusted current node and it is not an element in the HTML namespace, then
                    // switch to the CDATA section state. Otherwise, this is a cdata-in-html-content parse error. Create a comment token whose data is
                    // the "[CDATA[" string. Switch to the bogus comment state.
                    consume(tokenizer, "[CDATA[")
                    assert(false, "TODO")
                }
                else { // Anything else
                    // This is an incorrectly-opened-comment parse error. Create a comment token whose data is the empty string. Switch to the bogus
                    // comment state (don't consume anything in the current state).
                    report_parse_error(.IncorrectlyOpenedComment)
                    tokenizer.current_token = Comment_Token{}
                    tokenizer.state = .BogusComment
                }
            }

            // DOCTYPE state
            case .Doctype: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // This is an eof-in-doctype parse error. Create a new DOCTYPE token. Set its force-quirks flag to on. Emit the current token. Emit an end-of-file token.
                    report_parse_error(.EofInDoctype)
                    tokenizer.current_token = Doctype_Token{force_quirks=true}
                    emit(tokenizer, tokenizer.current_token)
                    emit(tokenizer, Eof_Token{})
                }
                else if r == '\t' || r == '\n' || r == '\f' || r == ' ' {
                // U+0009 CHARACTER TABULATION (tab)
                // U+000A LINE FEED (LF)
                // U+000C FORM FEED (FF)
                // U+0020 SPACE
                    // Switch to the before DOCTYPE name state.
                    tokenizer.state = .BeforeDoctypeName
                }
                else if r == '>' { // U+003E GREATER-THAN SIGN (>)
                    // Reconsume in the before DOCTYPE name state.
                    reconsume(tokenizer)
                    tokenizer.state = .BeforeDoctypeName
                }
                else { // Anything else
                    // This is a missing-whitespace-before-doctype-name parse error. Reconsume in the before DOCTYPE name state. 
                    report_parse_error(.MissingWhitespaceBeforeDoctypeName)
                    reconsume(tokenizer)
                    tokenizer.state = .BeforeDoctypeName
                }
                
            }

            // Before DOCTYPE name state
            case .BeforeDoctypeName: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // This is an eof-in-doctype parse error. Create a new DOCTYPE token. Set its force-quirks flag to on. Emit the current token. Emit an end-of-file token.
                    report_parse_error(.EofInDoctype)
                    tokenizer.current_token = Doctype_Token{force_quirks=true}
                    emit(tokenizer, tokenizer.current_token)
                    emit(tokenizer, Eof_Token{})
                }
                else if r == '\t' || r == '\n' || r == '\f' || r == ' ' {
                // U+0009 CHARACTER TABULATION (tab)
                // U+000A LINE FEED (LF)
                // U+000C FORM FEED (FF)
                // U+0020 SPACE
                    // Ignore the character.
                }
                else if codepoints.is_ascii_upper_alpha(r) { // ASCII upper alpha
                    // Create a new DOCTYPE token. Set the token's name to the lowercase version of the current input character
                    // (add 0x0020 to the character's code point). Switch to the DOCTYPE name state.
                    tokenizer.current_token = Doctype_Token{}
                    current_token := &tokenizer.current_token.(Doctype_Token)
                    fmt.sbprint(&current_token.name, r + cast(rune)0x0020)
                    tokenizer.state = .DoctypeName
                }
                else if r == '\u0000' { // U+0000 NULL
                    // This is an unexpected-null-character parse error. Create a new DOCTYPE token. Set the token's name to a U+FFFD
                    // REPLACEMENT CHARACTER character. Switch to the DOCTYPE name state.
                    report_parse_error(.UnexpectedNullCharacter)
                    tokenizer.current_token = Doctype_Token{}
                    current_token := &tokenizer.current_token.(Doctype_Token)
                    fmt.sbprint(&current_token.name, '\uFFFD')
                    tokenizer.state = .DoctypeName
                }
                else if r == '>' { // U+003E GREATER-THAN SIGN (>)
                    // This is a missing-doctype-name parse error. Create a new DOCTYPE token. Set its force-quirks flag to on. Switch to the data state. Emit the current token.
                    report_parse_error(.MissingDoctypeName)
                    tokenizer.current_token = Doctype_Token{force_quirks=true}
                    tokenizer.state = .Data
                    emit(tokenizer, tokenizer.current_token)
                }
                else { // Anything else
                    // Create a new DOCTYPE token. Set the token's name to the current input character. Switch to the DOCTYPE name state.
                    tokenizer.current_token = Doctype_Token{}
                    set_doctype_name(&tokenizer.current_token.(Doctype_Token), r)
                    tokenizer.state = .DoctypeName
                }
            }

            // DOCTYPE name state
            case .DoctypeName: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // This is an eof-in-doctype parse error. Set the current DOCTYPE token's force-quirks flag to on. Emit the current DOCTYPE token. Emit an end-of-file token.
                    report_parse_error(.EofInDoctype)
                    current_token := &tokenizer.current_token.(Doctype_Token)
                    current_token.force_quirks = true
                    emit(tokenizer, tokenizer.current_token)
                    emit(tokenizer, Eof_Token{})
                }
                else if r == '\t' || r == '\n' || r == '\f' || r == ' ' {
                // U+0009 CHARACTER TABULATION (tab)
                // U+000A LINE FEED (LF)
                // U+000C FORM FEED (FF)
                // U+0020 SPACE
                    // Switch to the after DOCTYPE name state.
                    tokenizer.state = .AfterDoctypeName
                }
                else if r == '>' { // U+003E GREATER-THAN SIGN (>)
                    // Switch to the data state. Emit the current DOCTYPE token.
                    tokenizer.state = .Data
                    emit(tokenizer, tokenizer.current_token)
                }
                else if codepoints.is_ascii_upper_alpha(r) { // ASCII upper alpha
                    // Append the lowercase version of the current input character (add 0x0020 to the character's code point) to the current DOCTYPE token's name.
                    current_token := &tokenizer.current_token.(Doctype_Token)
                    fmt.sbprint(&current_token.name, r + cast(rune)0x0020)
                }
                else if r == '\u0000' { // U+0000 NULL
                    // This is an unexpected-null-character parse error. Append a U+FFFD REPLACEMENT CHARACTER character to the current DOCTYPE token's name.
                    report_parse_error(.UnexpectedNullCharacter)
                    current_token := &tokenizer.current_token.(Doctype_Token)
                    fmt.sbprint(&current_token.name, '\uFFFD')
                }
                else { // Anything else
                    // Append the current input character to the current DOCTYPE token's name.
                    current_token := &tokenizer.current_token.(Doctype_Token)
                    fmt.sbprint(&current_token.name, r)
                }
            }

            // Tag name state
            case .TagName: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // This is an eof-in-tag parse error. Emit an end-of-file token.
                    report_parse_error(.EofInTag)
                    emit(tokenizer, Eof_Token{})
                }
                else if r == '\t' || r == '\n' || r == '\f' || r == ' ' {
                // U+0009 CHARACTER TABULATION (tab)
                // U+000A LINE FEED (LF)
                // U+000C FORM FEED (FF)
                // U+0020 SPACE
                    // Switch to the before attribute name state.
                    tokenizer.state = .BeforeAttributeName
                }
                else if r == '/' { // U+002F SOLIDUS (/)
                    // Switch to the self-closing start tag state.
                    tokenizer.state = .SelfClosingStartTag
                }
                else if r == '>' { // U+003E GREATER-THAN SIGN (>)
                    // Switch to the data state. Emit the current tag token.
                    tokenizer.state = .Data
                    emit(tokenizer, tokenizer.current_token)
                }
                else if codepoints.is_ascii_upper_alpha(r) { // ASCII upper alpha
                    // Append the lowercase version of the current input character (add 0x0020 to the character's code point) to the current tag token's tag name.
                    current_token := &tokenizer.current_token.(Tag_Token)
                    fmt.sbprint(&current_token.name, r + cast(rune)0x0020)
                }
                else if r == '\u0000' { // U+0000 NULL
                    // This is an unexpected-null-character parse error. Append a U+FFFD REPLACEMENT CHARACTER character to the current tag token's tag name.
                    report_parse_error(.UnexpectedNullCharacter)
                    current_token := &tokenizer.current_token.(Tag_Token)
                    fmt.sbprint(&current_token.name, '\uFFFD')
                }
                else { // Anything else
                    // Append the current input character to the current tag token's tag name.
                    current_token := &tokenizer.current_token.(Tag_Token)
                    fmt.sbprint(&current_token.name, r)
                }
            }

            // Before attribute name state
            case .BeforeAttributeName: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                // U+0009 CHARACTER TABULATION (tab)
                // U+000A LINE FEED (LF)
                // U+000C FORM FEED (FF)
                // U+0020 SPACE
                if r == '\t' || r == '\n' || r == '\f' || r == ' ' {
                    // Ignore the character.
                }
                else if r == '/' || r == '>' || r_err == .EOF { // U+002F SOLIDUS (/) or U+003E GREATER-THAN SIGN (>) or EOF
                    // Reconsume in the after attribute name state.
                    reconsume(tokenizer)
                    tokenizer.state = .AfterAttributeName
                }
                else if r == '=' { // U+003D EQUALS SIGN (=)
                    // This is an unexpected-equals-sign-before-attribute-name parse error. Start a new attribute in the current
                    // tag token. Set that attribute's name to the current input character, and its value to the empty string. Switch to the attribute name state.
                    report_parse_error(.UnexpectedEqualsSignBeforeAttributeName)
                    add_attribute_to_current_token(tokenizer)
                    fmt.sbprint(&tokenizer.current_attribute.name, r)
                    tokenizer.state = .AttributeName
                }
                else { // Anything else
                    // Start a new attribute in the current tag token. Set that attribute name and value to the empty string. Reconsume in the attribute name state.
                    add_attribute_to_current_token(tokenizer)
                    reconsume(tokenizer)
                    tokenizer.state = .AttributeName
                }
            }

            // Attribute name state
            case .AttributeName: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                // U+0009 CHARACTER TABULATION (tab)
                // U+000A LINE FEED (LF)
                // U+000C FORM FEED (FF)
                // U+0020 SPACE
                // U+002F SOLIDUS (/)
                // U+003E GREATER-THAN SIGN (>)
                // EOF
                if r == '\t' || r == '\n' || r == '\f' || r == ' ' || r == '/' || r == '>' || r_err == .EOF {
                    // Reconsume in the after attribute name state.
                    reconsume(tokenizer)
                    tokenizer.state = .AfterAttributeName
                }
                else if r == '=' { // U+003D EQUALS SIGN (=)
                    // Switch to the before attribute value state.
                    tokenizer.state = .BeforeAttributeValue
                }
                else if codepoints.is_ascii_upper_alpha(r) { // ASCII upper alpha
                    // Append the lowercase version of the current input character (add 0x0020 to the character's code point) to the current attribute's name.
                    fmt.sbprint(&tokenizer.current_attribute.name, r + cast(rune)0x0020)
                }
                else if r == '\u0000' { // U+0000 NULL
                    // This is an unexpected-null-character parse error. Append a U+FFFD REPLACEMENT CHARACTER character to the current attribute's name.
                    report_parse_error(.UnexpectedNullCharacter)
                    fmt.sbprint(&tokenizer.current_attribute.name, '\uFFFD')
                }
                else if r == '"' || r == '\'' || r == '<' { // U+0022 QUOTATION MARK (") or U+0027 APOSTROPHE (') or U+003C LESS-THAN SIGN (<)
                    // This is an unexpected-character-in-attribute-name parse error. Treat it as per the "anything else" entry below.
                    report_parse_error(.UnexpectedCharacterInAttributeName)
                    fmt.sbprint(&tokenizer.current_attribute.name, r)
                }
                else { //Anything else
                    // Append the current input character to the current attribute's name.
                    fmt.sbprint(&tokenizer.current_attribute.name, r)
                }
            }

            // Before attribute value state
            case .BeforeAttributeValue: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                // U+0009 CHARACTER TABULATION (tab)
                // U+000A LINE FEED (LF)
                // U+000C FORM FEED (FF)
                // U+0020 SPACE
                if r == '\t' || r == '\n' || r == '\f' || r == ' ' {
                    // Ignore the character.
                }
                else if r == '"' { // U+0022 QUOTATION MARK (")
                    // Switch to the attribute value (double-quoted) state.
                    tokenizer.state = .AttributeValueDoubleQuoted
                }
                else if r == '\'' { // U+0027 APOSTROPHE (')
                    // Switch to the attribute value (single-quoted) state.
                    tokenizer.state = .AttributeValueSingleQuoted
                }
                else if r == '>' { // U+003E GREATER-THAN SIGN (>)
                    // This is a missing-attribute-value parse error. Switch to the data state. Emit the current tag token.
                    report_parse_error(.MissingAttributeValue)
                    tokenizer.state = .Data
                    emit(tokenizer, tokenizer.current_token)
                }
                else { // Anything else
                    // Reconsume in the attribute value (unquoted) state.
                    reconsume(tokenizer)
                    tokenizer.state = .AttributeValueUnquoted
                }
            }

            // Attribute value (double-quoted) state
            case .AttributeValueDoubleQuoted: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // This is an eof-in-tag parse error. Emit an end-of-file token.
                    report_parse_error(.EofInTag)
                    emit(tokenizer, Eof_Token{})
                }
                else if r == '"' { // U+0022 QUOTATION MARK (")
                    // Switch to the after attribute value (quoted) state.
                    tokenizer.state = .AfterAttributeValueQuoted
                }
                else if r == '&' { // U+0026 AMPERSAND (&)
                    // Set the return state to the attribute value (double-quoted) state. Switch to the character reference state.
                    tokenizer.return_state = .AttributeValueDoubleQuoted
                    tokenizer.state = .CharacterReference
                }
                else if r == '\u0000' { // U+0000 NULL
                    // This is an unexpected-null-character parse error. Append a U+FFFD REPLACEMENT CHARACTER character to the current attribute's value.
                    report_parse_error(.UnexpectedNullCharacter)
                    fmt.sbprint(&tokenizer.current_attribute.value, '\uFFFD')
                }
                else { // Anything else
                    // Append the current input character to the current attribute's value.
                    fmt.sbprint(&tokenizer.current_attribute.value, r)
                }
            }

            // After attribute value (quoted) state
            case .AfterAttributeValueQuoted: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // This is an eof-in-tag parse error. Emit an end-of-file token.
                    report_parse_error(.EofInTag)
                }
                else if r == '\t' || r == '\n' || r == '\f' || r == ' ' {
                // U+0009 CHARACTER TABULATION (tab)
                // U+000A LINE FEED (LF)
                // U+000C FORM FEED (FF)
                // U+0020 SPACE
                    // Switch to the before attribute name state.
                    tokenizer.state = .BeforeAttributeName
                }
                else if r == '/' { // U+002F SOLIDUS (/)
                    // Switch to the self-closing start tag state.
                    tokenizer.state = .SelfClosingStartTag
                }
                else if r == '>' { // U+003E GREATER-THAN SIGN (>)
                    // Switch to the data state. Emit the current tag token.
                    tokenizer.state = .Data
                    emit(tokenizer, tokenizer.current_token)
                }
                else { // Anything else
                    // This is a missing-whitespace-between-attributes parse error. Reconsume in the before attribute name state. 
                    report_parse_error(.MissingWhitespaceBetweenAttributes)
                    reconsume(tokenizer)
                    tokenizer.state = .BeforeAttributeName
                }
            }
            
            // End tag open state
            case .EndTagOpen: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // This is an eof-before-tag-name parse error. Emit a U+003C LESS-THAN SIGN character token, a U+002F SOLIDUS character token and an end-of-file token. 
                    report_parse_error(.EofBeforeTagName)
                    emit(tokenizer, Character_Token{'<'})
                    emit(tokenizer, Character_Token{'/'})
                    emit(tokenizer, Eof_Token{})
                }
                else if codepoints.is_ascii_alpha(r) { // ASCII alpha
                    // Create a new end tag token, set its tag name to the empty string. Reconsume in the tag name state. 
                    tokenizer.current_token = Tag_Token{is_start=false}
                    reconsume(tokenizer)
                    tokenizer.state = .TagName
                }
                else if r == '>' { // U+003E GREATER-THAN SIGN (>)
                    // This is a missing-end-tag-name parse error. Switch to the data state.
                    report_parse_error(.MissingEndTagName)
                    tokenizer.state = .Data
                }
                else { // Anything else
                    // This is an invalid-first-character-of-tag-name parse error. Create a comment token whose data is the empty string. Reconsume in the bogus comment state.
                    report_parse_error(.InvalidFirstCharacterOfTagName)
                    tokenizer.current_token = Comment_Token{}
                    reconsume(tokenizer)
                    tokenizer.state = .BogusComment
                }
            }

            // After attribute name state
            case .AfterAttributeName: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // This is an eof-in-tag parse error. Emit an end-of-file token.
                    report_parse_error(.EofInTag)
                    emit(tokenizer, Eof_Token{})
                }
                else if r == '\t' || r == '\n' || r == '\f' || r == ' ' {
                // U+0009 CHARACTER TABULATION (tab)
                // U+000A LINE FEED (LF)
                // U+000C FORM FEED (FF)
                // U+0020 SPACE
                    // Ignore the character.
                }
                else if r == '/' { // U+002F SOLIDUS (/)
                    // Switch to the self-closing start tag state.
                    tokenizer.state = .SelfClosingStartTag
                }
                else if r == '=' { // U+003D EQUALS SIGN (=)
                    // Switch to the before attribute value state.
                    tokenizer.state = .BeforeAttributeValue
                }
                else if r == '>' { // U+003E GREATER-THAN SIGN (>)
                    // Switch to the data state. Emit the current tag token.
                    tokenizer.state = .Data
                    emit(tokenizer, tokenizer.current_token)
                }
                else { // Anything else
                    // Start a new attribute in the current tag token. Set that attribute name and value to the empty string. Reconsume in the attribute name state.
                    add_attribute_to_current_token(tokenizer)
                    reconsume(tokenizer)
                    tokenizer.state = .AttributeName
                }
            }

            // Self-closing start tag state
            case .SelfClosingStartTag: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r_err == .EOF { // EOF
                    // This is an eof-in-tag parse error. Emit an end-of-file token.
                    report_parse_error(.EofInTag)
                    emit(tokenizer, Eof_Token{})
                }
                else if r == '>' { // U+003E GREATER-THAN SIGN (>)
                    // Set the self-closing flag of the current tag token. Switch to the data state. Emit the current tag token.
                    current_token := &tokenizer.current_token.(Tag_Token)
                    current_token.self_closing = true
                    tokenizer.state = .Data
                    emit(tokenizer, tokenizer.current_token)
                }
                else { // Anything else
                    // This is an unexpected-solidus-in-tag parse error. Reconsume in the before attribute name state.
                    report_parse_error(.UnexpectedSolidusInTag)
                    reconsume(tokenizer)
                    tokenizer.state = .BeforeAttributeName
                }
            }

            // Character reference state
            case .CharacterReference: {
                // Set the temporary buffer to the empty string. Append a U+0026 AMPERSAND (&) character to the temporary buffer. Consume the next input character:
                fmt.sbprint(&tokenizer.temporary_buffer, '&')
                r, r_err := get_next_character(tokenizer)

                if codepoints.is_ascii_alphanumeric(r) { // ASCII alphanumeric
                    // Reconsume in the named character reference state.
                    reconsume(tokenizer)
                    tokenizer.state = .NamedCharacterReference
                }
                else if r == '#' { // U+0023 NUMBER SIGN (#)
                    // Append the current input character to the temporary buffer. Switch to the numeric character reference state.
                    fmt.sbprint(&tokenizer.temporary_buffer, r)
                    tokenizer.state = .NumericCharacterReference
                }
                else { // Anything else
                    // Flush code points consumed as a character reference. Reconsume in the return state.
                    flush_code_points(tokenizer)
                    reconsume(tokenizer)
                    tokenizer.state = tokenizer.return_state
                }
            }

            // Named character reference state
            case .NamedCharacterReference: {
                // Consume the maximum number of characters possible, where the consumed characters are one of the identifiers in the
                // first column of the named character references table. Append each character to the temporary buffer when it's consumed.
                entry, found := get_maximal_character_reference(tokenizer)

                if found { // If there is a match

                    // If the character reference was consumed as part of an attribute, and the last character matched is not a U+003B SEMICOLON
                    // character (;), and the next input character is either a U+003D EQUALS SIGN character (=) or an ASCII alphanumeric, then,
                    // for historical reasons, flush code points consumed as a character reference and switch to the return state.
                    last_in_name := entry.name[len(entry.name) - 1]
                    next, err := peek_next_character(tokenizer)
                    if last_in_name != ';' && (next == '=' || codepoints.is_ascii_alphanumeric(next)) {
                        flush_code_points(tokenizer)
                        tokenizer.state = tokenizer.return_state
                    }
                    else { // Otherwise:

                        // If the last character matched is not a U+003B SEMICOLON character (;), then this is a missing-semicolon-after-character-reference
                        // parse error.
                        if last_in_name != ';' do report_parse_error(.MissingSemicolonAfterCharacterReference)

                        // Set the temporary buffer to the empty string. Append one or two characters corresponding to the character reference name (as given
                        // by the second column of the named character references table) to the temporary buffer.
                        strings.builder_reset(&tokenizer.temporary_buffer)
                        for code in entry.codes {
                            fmt.sbprint(&tokenizer.temporary_buffer, code)
                        }
                        // Flush code points consumed as a character reference. Switch to the return state.
                        flush_code_points(tokenizer)
                        tokenizer.state = tokenizer.return_state
                    }
                }
                else { // Otherwise
                    // Flush code points consumed as a character reference. Switch to the ambiguous ampersand state.
                    flush_code_points(tokenizer)
                    tokenizer.state = .AmbiguousAmpersand
                }
            }

            // https://html.spec.whatwg.org/#rcdata-less-than-sign-state
            // RCDATA less-than sign state
            case .RCDataLessThanSign: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r == '/' { // U+002F SOLIDUS (/)
                    // Set the temporary buffer to the empty string. Switch to the RCDATA end tag open state.
                    strings.builder_reset(&tokenizer.temporary_buffer)
                    tokenizer.state = .RCDataEndTagOpen
                }
                else { // Anything else
                    // Emit a U+003C LESS-THAN SIGN character token. Reconsume in the RCDATA state.    
                    emit(tokenizer, Character_Token{'<'})
                    reconsume(tokenizer)
                    tokenizer.state = .RCData
                }
            }

            // https://html.spec.whatwg.org/#rcdata-end-tag-open-state
            // RCDATA end tag open state
            case .RCDataEndTagOpen: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if codepoints.is_ascii_alpha(r) { // ASCII alpha
                    // Create a new end tag token, set its tag name to the empty string. Reconsume in the RCDATA end tag name state. 
                    tokenizer.current_token = Tag_Token{is_start=false}
                    reconsume(tokenizer)
                    tokenizer.state = .RCDataEndTagName
                }
                else { // Anything else
                    // Emit a U+003C LESS-THAN SIGN character token and a U+002F SOLIDUS character token. Reconsume in the RCDATA state.
                    emit(tokenizer, Character_Token{'<'})
                    emit(tokenizer, Character_Token{'/'})
                    reconsume(tokenizer)
                    tokenizer.state = .RCData
                }
            }

            // https://html.spec.whatwg.org/#rcdata-end-tag-name-state
            // RCDATA end tag name state
            case .RCDataEndTagName: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)
                
                // U+0009 CHARACTER TABULATION (tab)
                // U+000A LINE FEED (LF)
                // U+000C FORM FEED (FF)
                // U+0020 SPACE
                if r == '\t' || r == '\n' || r == '\f' || r == ' ' {
                    // If the current end tag token is an appropriate end tag token, then switch to the before attribute name state. Otherwise,
                    // treat it as per the "anything else" entry below.
                    if is_appropriate_end_tag(tokenizer) do tokenizer.state = .BeforeAttributeName
                    else {
                        assert(false, "TODO")
                    }
                }
                else if r == '/' { // U+002F SOLIDUS (/)
                    // If the current end tag token is an appropriate end tag token, then switch to the self-closing start tag state. Otherwise,
                    // treat it as per the "anything else" entry below.
                    if is_appropriate_end_tag(tokenizer) do tokenizer.state = .SelfClosingStartTag
                    else {
                        emit(tokenizer, Character_Token{'<'})
                        emit(tokenizer, Character_Token{'/'})
                        for char in strings.to_string(tokenizer.temporary_buffer) {
                            emit(tokenizer, Character_Token{char})
                        }
                        reconsume(tokenizer)
                        tokenizer.state = .RCData
                    }
                }
                else if r == '>' { // U+003E GREATER-THAN SIGN (>)
                    // If the current end tag token is an appropriate end tag token, then switch to the data state and emit the current tag token.
                    // Otherwise, treat it as per the "anything else" entry below.
                    if is_appropriate_end_tag(tokenizer) {
                        tokenizer.state = .Data
                        emit(tokenizer, tokenizer.current_token)
                    }
                    else {
                        emit(tokenizer, Character_Token{'<'})
                        emit(tokenizer, Character_Token{'/'})
                        for char in strings.to_string(tokenizer.temporary_buffer) {
                            emit(tokenizer, Character_Token{char})
                        }
                        reconsume(tokenizer)
                        tokenizer.state = .RCData
                    }
                }
                else if codepoints.is_ascii_upper_alpha(r) { // ASCII upper alpha
                    // Append the lowercase version of the current input character (add 0x0020 to the character's code point) to the current tag token's tag
                    // name. Append the current input character to the temporary buffer.
                    current_token := &tokenizer.current_token.(Tag_Token)
                    fmt.sbprint(&current_token.name, r + cast(rune)0x0020)
                }
                else if codepoints.is_ascii_lower_alpha(r) { // ASCII lower alpha
                    // Append the current input character to the current tag token's tag name. Append the current input character to the temporary buffer.
                    current_token := &tokenizer.current_token.(Tag_Token)
                    fmt.sbprint(&current_token.name, r)
                    fmt.sbprint(&tokenizer.temporary_buffer, r)
                }
                else { // Anything else
                    // Emit a U+003C LESS-THAN SIGN character token, a U+002F SOLIDUS character token, and a character token for each of the characters
                    // in the temporary buffer (in the order they were added to the buffer). Reconsume in the RCDATA state.
                    emit(tokenizer, Character_Token{'<'})
                    emit(tokenizer, Character_Token{'/'})
                    for char in strings.to_string(tokenizer.temporary_buffer) {
                        emit(tokenizer, Character_Token{char})
                    }
                    reconsume(tokenizer)
                    tokenizer.state = .RCData
                }
            }

            // https://html.spec.whatwg.org/#rawtext-less-than-sign-state
            case .RawTextLessThanSign: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if r == '/' { // U+002F SOLIDUS (/)
                    // Set the temporary buffer to the empty string. Switch to the RAWTEXT end tag open state.
                    strings.builder_reset(&tokenizer.temporary_buffer)
                    tokenizer.state = .RawTextEndTagOpen
                }
                else { // Anything else
                    // Emit a U+003C LESS-THAN SIGN character token. Reconsume in the RAWTEXT state.
                    emit(tokenizer, Character_Token{'<'})
                    reconsume(tokenizer)
                    tokenizer.state = .RawText
                }
            }

            // https://html.spec.whatwg.org/#rawtext-end-tag-open-state
            case .RawTextEndTagOpen: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                if codepoints.is_ascii_alpha(r) { // ASCII alpha
                    // Create a new end tag token, set its tag name to the empty string. Reconsume in the RAWTEXT end tag name state. 
                    tokenizer.current_token = Tag_Token{is_start=false}
                    reconsume(tokenizer)
                    tokenizer.state = .RawTextEndTagName
                }
                else { // Anything else
                    // Emit a U+003C LESS-THAN SIGN character token and a U+002F SOLIDUS character token. Reconsume in the RAWTEXT state.
                    emit(tokenizer, Character_Token{'<'})
                    reconsume(tokenizer)
                    tokenizer.state = .RawText
                }
            }

            // https://html.spec.whatwg.org/#rawtext-end-tag-name-state
            case .RawTextEndTagName: {
                // Consume the next input character:
                r, r_err := get_next_character(tokenizer)

                // U+0009 CHARACTER TABULATION (tab)
                // U+000A LINE FEED (LF)
                // U+000C FORM FEED (FF)
                // U+0020 SPACE
                if r == '\t' || r == '\n' || r == '\f' || r == ' ' {
                    // If the current end tag token is an appropriate end tag token, then switch to the before attribute name state. Otherwise, treat it as per
                    // the "anything else" entry below.
                    if is_appropriate_end_tag(tokenizer) do tokenizer.state = .BeforeAttributeName
                    else {
                        emit(tokenizer, Character_Token{'<'})
                        emit(tokenizer, Character_Token{'/'})
                        for char in strings.to_string(tokenizer.temporary_buffer) {
                            emit(tokenizer, Character_Token{char})
                        }
                        reconsume(tokenizer)
                        tokenizer.state = .RawText
                    }
                }
                else if r == '/' { // U+002F SOLIDUS (/)
                    // If the current end tag token is an appropriate end tag token, then switch to the self-closing start tag state. Otherwise, treat it as per
                    // the "anything else" entry below.
                    if is_appropriate_end_tag(tokenizer) do tokenizer.state = .SelfClosingStartTag
                    else {
                        emit(tokenizer, Character_Token{'<'})
                        emit(tokenizer, Character_Token{'/'})
                        for char in strings.to_string(tokenizer.temporary_buffer) {
                            emit(tokenizer, Character_Token{char})
                        }
                        reconsume(tokenizer)
                        tokenizer.state = .RawText
                    }
                }
                else if r == '>' { // U+003E GREATER-THAN SIGN (>)
                    // If the current end tag token is an appropriate end tag token, then switch to the data state and emit the current tag token. Otherwise, treat it
                    // as per the "anything else" entry below.
                    if is_appropriate_end_tag(tokenizer) {
                        tokenizer.state = .Data
                        emit(tokenizer, tokenizer.current_token)
                    }
                    else {
                        emit(tokenizer, Character_Token{'<'})
                        emit(tokenizer, Character_Token{'/'})
                        for char in strings.to_string(tokenizer.temporary_buffer) {
                            emit(tokenizer, Character_Token{char})
                        }
                        reconsume(tokenizer)
                        tokenizer.state = .RawText
                    }
                }
                else if codepoints.is_ascii_upper_alpha(r) { // ASCII upper alpha
                    // Append the lowercase version of the current input character (add 0x0020 to the character's code point) to the current tag token's tag name.
                    // Append the current input character to the temporary buffer.
                    current_token := &tokenizer.current_token.(Tag_Token)
                    fmt.sbprint(&current_token.name, r + cast(rune)0x0020)
                    fmt.sbprint(&tokenizer.temporary_buffer, r)
                }
                else if codepoints.is_ascii_lower_alpha(r) { // ASCII lower alpha
                    // Append the current input character to the current tag token's tag name. Append the current input character to the temporary buffer.
                    current_token := &tokenizer.current_token.(Tag_Token)
                    fmt.sbprint(&current_token.name, r)
                    fmt.sbprint(&tokenizer.temporary_buffer, r)
                }
                else { // Anything else
                    // Emit a U+003C LESS-THAN SIGN character token, a U+002F SOLIDUS character token, and a character token for each of the characters in the
                    // temporary buffer (in the order they were added to the buffer). Reconsume in the RAWTEXT state.
                    emit(tokenizer, Character_Token{'<'})
                    emit(tokenizer, Character_Token{'/'})
                    for char in strings.to_string(tokenizer.temporary_buffer) {
                        emit(tokenizer, Character_Token{char})
                    }
                    reconsume(tokenizer)
                    tokenizer.state = .RawText
                }
            }

            case:
                fmt.assertf(false, "State %s not handled yet!", tokenizer.state)
        }
    }

    token := queue.pop_front(&tokenizer.to_emit)
    assert(token != nil)
    return token
}

Marker :: struct {}
Active_Formatting_Element :: union {Marker, ^Element}

Html_Parser :: struct { 
    tokenizer: ^Html_Tokenizer,

    // https://html.spec.whatwg.org/#the-insertion-mode
    insertion_mode: Insertion_Mode,
    original_insertion_mode: Insertion_Mode,

    // https://html.spec.whatwg.org/#stack-of-open-elements
    stack_of_open_elements: [dynamic]^Element,

    // https://html.spec.whatwg.org/#the-list-of-active-formatting-elements
    list_of_active_formatting_elements: [dynamic]Active_Formatting_Element,

    head_element_pointer: ^Element,
    form_element_pointer: ^Element,

    // https://html.spec.whatwg.org/#other-parsing-state-flags
    scripting_flag: bool,
    frameset_ok: bool,

    // https://html.spec.whatwg.org/#creating-and-inserting-nodes
    // While the parser is processing a token, it can enable or disable foster parenting.
    foster_parenting: bool,

    // Used for reprocessing
    last_token: Html_Token,
    should_reprocess: bool,

    // https://html.spec.whatwg.org/#concept-pending-table-char-tokens
    pending_table_character_tokens: [dynamic]Character_Token,
}

parser_init :: proc(parser: ^Html_Parser, tokenizer: ^Html_Tokenizer) {
    parser.tokenizer = tokenizer
    parser.insertion_mode = .Initial
    parser.stack_of_open_elements = make([dynamic]^Element)
    parser.list_of_active_formatting_elements = make([dynamic]Active_Formatting_Element)
}

stack_has_element_of_type :: proc(parser: ^Html_Parser, type: Element_Type) -> bool {
    for elem in parser.stack_of_open_elements {
        if elem.type == type do return true
    }
    return false
}

stack_has_element :: proc(parser: ^Html_Parser, element: ^Element) -> bool {
    for elem in parser.stack_of_open_elements {
        if elem == element do return true
    }
    return false
}

stack_has_element_that_is_not :: proc(parser: ^Html_Parser, types: bit_set[Element_Type]) -> bool {
    for elem in parser.stack_of_open_elements {
        if elem.type not_in types do return true
    }
    return false
}

remove_from_stack :: proc(parser: ^Html_Parser, element: ^Element) {
    for elem, index in parser.stack_of_open_elements {
        if elem == element {
            ordered_remove(&parser.stack_of_open_elements, index)
            break
        }
    }
}

// https://html.spec.whatwg.org/#has-an-element-in-the-specific-scope
// The stack of open elements is said to have an element target node in a specific scope consisting of a list of element types list when the following algorithm
// terminates in a match state:
stack_has_element_in_specific_scope :: proc(parser: ^Html_Parser, target_type: Element_Type, types: bit_set[Element_Type]) -> bool {
    // Initialize node to be the current node (the bottommost node of the stack).
    node, node_index := current_node_with_index(parser)
    for {
        // If node is the target node, terminate in a match state.
        if node.type == target_type do return true
        // Otherwise, if node is one of the element types in list, terminate in a failure state.
        if node.type in types do return false
        // Otherwise, set node to the previous entry in the stack of open elements and return to step 2.
        // (This will never fail, since the loop will always terminate in the previous step if the top of the stack — an html element — is reached.)
        node, node_index := set_to_previous_stack_entry(parser, node_index)
    }
}

// https://html.spec.whatwg.org/#has-an-element-in-scope
// The stack of open elements is said to have a particular element in scope when it has that element in the specific scope consisting of the following element types:
/*
    applet
    caption
    html
    table
    td
    th
    marquee
    object
    template
    MathML mi
    MathML mo
    MathML mn
    MathML ms
    MathML mtext
    MathML annotation-xml
    SVG foreignObject
    SVG desc
    SVG title
*/
stack_has_element_in_scope :: proc(parser: ^Html_Parser, target_type: Element_Type) -> bool {
    // @TODO: Expand this list
    return stack_has_element_in_specific_scope(parser, target_type, {.Applet, .Caption, .Html, .Table, .Td, .Th, .Marquee, .Object, .Template})
}

// https://html.spec.whatwg.org/#has-an-element-in-list-item-scope
// The stack of open elements is said to have a particular element in list item scope when it has that element in the specific scope consisting of the following element types:
/*
    All the element types listed above for the has an element in scope algorithm.
    ol in the HTML namespace
    ul in the HTML namespace
*/
stack_has_element_in_list_item_scope :: proc(parser: ^Html_Parser, target_type: Element_Type) -> bool {
    return stack_has_element_in_scope(parser, target_type) || stack_has_element_in_specific_scope(parser, target_type, {.Ol, .Ul})
}

// https://html.spec.whatwg.org/#has-an-element-in-button-scope
// The stack of open elements is said to have a particular element in button scope when it has that element in the specific scope consisting of the following element types:
/*
    All the element types listed above for the has an element in scope algorithm.
    button in the HTML namespace
*/
stack_has_element_in_button_scope :: proc(parser: ^Html_Parser, target_type: Element_Type) -> bool {
    return stack_has_element_in_scope(parser, target_type) || stack_has_element_in_specific_scope(parser, target_type, {.Button})
}

// https://html.spec.whatwg.org/#has-an-element-in-table-scope
// The stack of open elements is said to have a particular element in table scope when it has that element in the specific scope consisting of the following element types:
/*
    html in the HTML namespace
    table in the HTML namespace
    template in the HTML namespace
*/
stack_has_element_in_table_scope :: proc(parser: ^Html_Parser, target_type: Element_Type) -> bool {
    return stack_has_element_in_scope(parser, target_type) || stack_has_element_in_specific_scope(parser, target_type, {.Html, .Table, .Template})
}

// https://html.spec.whatwg.org/#has-an-element-in-select-scope
// The stack of open elements is said to have a particular element in select scope when it has that element in the specific scope consisting of all element types except the following:
/*
    optgroup in the HTML namespace
    option in the HTML namespace
*/
stack_has_element_in_select_scope :: proc(parser: ^Html_Parser, target_type: Element_Type) -> bool {
    return stack_has_element_in_scope(parser, target_type) || stack_has_element_in_specific_scope(parser, target_type, {.OptGroup, .Option})
}

// https://html.spec.whatwg.org/#clear-the-stack-back-to-a-table-body-context
// When the steps above require the UA to clear the stack back to a table body context, it means that the UA must, while the current node is not a tbody,
// tfoot, thead, template, or html element, pop elements from the stack of open elements.
clear_stack_to_table_body_context :: proc(parser: ^Html_Parser) {
    for (current_node(parser).type not_in bit_set[Element_Type]{.TBody, .TFoot, .THead, .Template, .Html}) {
        pop(&parser.stack_of_open_elements)
    }
}

// https://html.spec.whatwg.org/#clear-the-stack-back-to-a-table-context
// When the steps above require the UA to clear the stack back to a table context, it means that the UA must, while the current node is not a table, template,
// or html element, pop elements from the stack of open elements. 
clear_stack_to_table_context :: proc(parser: ^Html_Parser) {
    for (current_node(parser).type not_in bit_set[Element_Type]{.Table, .Template, .Html}) {
        pop(&parser.stack_of_open_elements)
    }
}

// https://html.spec.whatwg.org/#clear-the-stack-back-to-a-table-row-context
// When the steps above require the UA to clear the stack back to a table row context, it means that the UA must, while the current node is not a tr, template,
// or html element, pop elements from the stack of open elements.
clear_stack_to_table_row_context :: proc(parser: ^Html_Parser) {
    for (current_node(parser).type not_in bit_set[Element_Type]{.Tr, .Template, .Html}) {
        pop(&parser.stack_of_open_elements)
    }
}

find_index_in_list_of_active_formatting_elements :: proc(parser: ^Html_Parser, element: ^Element) -> (found: bool, index: int) {
    for elem, idx in parser.list_of_active_formatting_elements {
        switch e in elem {
            case Marker: continue
            case ^Element:
                if e == element {
                    return true, idx
                }
        }
    }
    return false, 0
}

in_list_of_active_formatting_elements :: proc(parser: ^Html_Parser, element: ^Element) -> bool {
    found, _ := find_index_in_list_of_active_formatting_elements(parser, element)
    return found
}

// https://html.spec.whatwg.org/#clear-the-list-of-active-formatting-elements-up-to-the-last-marker
clear_list_of_active_formatting_elements_up_to_marker :: proc(parser: ^Html_Parser) {
    #reverse for elem in parser.list_of_active_formatting_elements {
        switch e in elem {
            case Marker:
                pop(&parser.list_of_active_formatting_elements)
                return
            case ^Element:
                pop(&parser.list_of_active_formatting_elements)
        }
    }
}

// https://html.spec.whatwg.org/#reset-the-insertion-mode-appropriately
// When the steps below require the UA to reset the insertion mode appropriately, it means the UA must follow these steps:
reset_insertion_mode_appropriately :: proc(parser: ^Html_Parser) {
    // Let last be false.
    last := false
    // Let node be the last node in the stack of open elements.
    node, node_index := current_node_with_index(parser)
    // Loop: If node is the first node in the stack of open elements, then set last to true, and, if the parser was created as part of the HTML
    // fragment parsing algorithm (fragment case), set node to the context element passed to that algorithm.
    for {
        if node_index == 0 {
            last = true
            // @TODO: fragment parsing stuff
        }

        // If node is a select element, run these substeps:
        if node.type == .Select {
            // If last is true, jump to the step below labeled done.
            if last {
                parser.insertion_mode = .InSelect
                return
            }
            // Let ancestor be node.
            ancestor := node
            ancestor_index := node_index
            // Loop: If ancestor is the first node in the stack of open elements, jump to the step below labeled done.
            for {
                if ancestor_index == 0 {
                    // Done: Switch the insertion mode to "in select" and return.
                    parser.insertion_mode = .InSelect
                    return
                }
                // Let ancestor be the node before ancestor in the stack of open elements.
                ancestor, ancsetor_index := set_to_previous_stack_entry(parser, ancestor_index)

                // If ancestor is a template node, jump to the step below labeled done.
                if ancestor.type == .Template {
                    // Done: Switch the insertion mode to "in select" and return.
                    parser.insertion_mode = .InSelect
                    return
                }
                // If ancestor is a table node, switch the insertion mode to "in select in table" and return.
                if ancestor.type == .Table {
                    parser.insertion_mode = .InSelectInTable
                    return
                }
                // Jump back to the step labeled loop.
            }
        }
        else if (node.type == .Td || node.type == .Th) && !last {
        // If node is a td or th element and last is false, then switch the insertion mode to "in cell" and return.
            parser.insertion_mode = .InCell
            return
        }
        else if node.type == .Tr { // If node is a tr element, then switch the insertion mode to "in row" and return.
            parser.insertion_mode = .InRow
            return
        }
        else if (node.type in bit_set[Element_Type]{.TBody, .THead, .TFoot}) {
        // If node is a tbody, thead, or tfoot element, then switch the insertion mode to "in table body" and return.
            parser.insertion_mode = .InTableBody
            return
        }
        else if node.type == .Caption { // If node is a caption element, then switch the insertion mode to "in caption" and return.
            parser.insertion_mode = .InCaption
            return
        }
        else if node.type == .Colgroup { // If node is a colgroup element, then switch the insertion mode to "in column group" and return.
            parser.insertion_mode = .InColumnGroup
            return
        }
        else if node.type == .Table { // If node is a table element, then switch the insertion mode to "in table" and return.
            parser.insertion_mode = .InTable
            return
        }
        else if node.type == .Template { // If node is a template element, then switch the insertion mode to the current template insertion mode and return.
            panic("TODO")
        }
        else if node.type == .Head && !last { // If node is a head element and last is false, then switch the insertion mode to "in head" and return.
            parser.insertion_mode = .InHead
            return
        }
        else if node.type == .Body { // If node is a body element, then switch the insertion mode to "in body" and return.
            parser.insertion_mode = .InBody
            return
        }
        else if node.type == .Frameset { // If node is a frameset element, then switch the insertion mode to "in frameset" and return. (fragment case)
            parser.insertion_mode = .InFrameset
            return
        }
        else if node.type == .Html { // If node is an html element, run these substeps:
            // If the head element pointer is null, switch the insertion mode to "before head" and return. (fragment case)
            if parser.head_element_pointer == nil {
                parser.insertion_mode = .BeforeHead
                return
            }
            else { // Otherwise, the head element pointer is not null, switch the insertion mode to "after head" and return.
                parser.insertion_mode = .AfterHead
                return
            }
        }
        else if last { // If last is true, then switch the insertion mode to "in body" and return. (fragment case)
            parser.insertion_mode = .InBody
            return
        }

        // Let node now be the node before node in the stack of open elements.
        node, node_index = set_to_previous_stack_entry(parser, node_index)
        // Return to the step labeled loop.
    }
}

// https://html.spec.whatwg.org/#tree-construction-dispatcher
// As each token is emitted from the tokenizer, the user agent must follow the appropriate steps from the following list, known as the tree construction dispatcher:
dispatch_next_token :: proc(parser: ^Html_Parser, document: ^Document) -> (should_continue: bool) {
    token: Html_Token = ---
    if parser.should_reprocess {
        token = parser.last_token
        parser.should_reprocess = false
    }
    else do token = get_next_token(parser.tokenizer)
    parser.last_token = token
    // @TODO: Adjusted current node
    // If the stack of open elements is empty
    // If the adjusted current node is an element in the HTML namespace
    // If the adjusted current node is a MathML text integration point and the token is a start tag whose tag name is neither "mglyph" nor "malignmark"
    // If the adjusted current node is a MathML text integration point and the token is a character token
    // If the adjusted current node is a MathML annotation-xml element and the token is a start tag whose tag name is "svg"
    // If the adjusted current node is an HTML integration point and the token is a start tag
    // If the adjusted current node is an HTML integration point and the token is a character token
    // If the token is an end-of-file token
    if len(parser.stack_of_open_elements) == 0 || is_eof(token) || current_node(parser).namespace == HTML_NAMESPACE { 
        // Process the token according to the rules given in the section corresponding to the current insertion mode in HTML content.
        return process_token_as_html_content(parser, document, token)
    }
    else { // Otherwise
        assert(false, "TODO: Process the token according to the rules given in the section for parsing tokens in foreign content.")
    }

    return true
}

construct_tree :: proc(parser: ^Html_Parser, document: ^Document) {
    should_continue := true
    for should_continue{ // When do we stop?
        should_continue = dispatch_next_token(parser, document)
    }
}

is_start_tag :: proc(token: Html_Token) -> bool {
    tag, is_tag := token.(Tag_Token)
    return is_tag && tag.is_start
}

is_end_tag :: proc(token: Html_Token) -> bool {
    tag, is_tag := token.(Tag_Token)
    return is_tag && !tag.is_start
}

is_start_tag_named_one_of :: proc(token: Html_Token, names: ..string) -> bool {
    tag, is_tag := token.(Tag_Token)
    if !is_tag do return false
    if !tag.is_start do return false

    tag_name := strings.to_string(tag.name)
    for name in names {
        if tag_name == name do return true
    }
    return false
}

is_end_tag_named_one_of :: proc(token: Html_Token, names: ..string) -> bool {
    tag, is_tag := token.(Tag_Token)
    if !is_tag do return false
    if tag.is_start do return false

    tag_name := strings.to_string(tag.name)
    for name in names {
        if tag_name == name do return true
    }
    return false
}

tag_name_is_one_of :: proc(tag: Tag_Token, options: ..string) -> bool {
    name := strings.to_string(tag.name)
    for option in options {
        if name == option do return true
    }
    return false
}

// https://html.spec.whatwg.org/#insert-a-comment
// When the steps below require the user agent to insert a comment while processing a comment token, optionally with an explicitly insertion position
// position, the user agent must run the following steps:
insert_comment :: proc(parser: ^Html_Parser, comment: Comment_Token, insertion_parent: ^Node = nil, insertion_index := 0) {
    // Let data be the data given in the comment token being processed.
    data := strings.to_string(comment.data)
    // If position was specified, then let the adjusted insertion location be position. Otherwise, let adjusted insertion location be the appropriate place for inserting a node.
    insertion_elem := insertion_parent
    insertion_index := insertion_index
    if insertion_elem == nil do insertion_elem, insertion_index = get_appropriate_insertion_location(parser)
    // Create a Comment node whose data attribute is set to data and whose node document is the same as that of the node in which the adjusted insertion location finds itself.
    dom_comment := make_node(Comment, insertion_elem.document)
    dom_comment.data = data
    // Insert the newly created node at the adjusted insertion location.
    insert_node_at_location(dom_comment, insertion_elem, insertion_index)
}

// https://html.spec.whatwg.org/#insert-a-character
// When the steps below require the user agent to insert a character while processing a token, the user agent must run the following steps:
insert_character :: proc(parser: ^Html_Parser, document: ^Document, token: Character_Token) {
    // Let data be the characters passed to the algorithm, or, if no characters were explicitly specified, the character of the character token being processed.
    data := token.data
    // Let the adjusted insertion location be the appropriate place for inserting a node.
    insertion_elem, insertion_index := get_appropriate_insertion_location(parser)
    // If the adjusted insertion location is in a Document node, then return.
    if _, ok := insertion_elem.node_type.(^Document); ok do return
    // If there is a Text node immediately before the adjusted insertion location, then append data to that Text node's data.
    if insertion_index > 0 {
        text, ok := &insertion_elem.children[insertion_index - 1].node_type.(Text)
        if ok do fmt.sbprint(&text.data, data)
        return
    }

    // Otherwise, create a new Text node whose data is data and whose node document is the same as that of the element in which the adjusted insertion location finds
    // itself, and insert the newly created node at the adjusted insertion location.
    text := make_node(Text, document)
    fmt.sbprint(&text.data, data)
    insert_node_at_location(text, insertion_elem, insertion_index)
}

process_token_as_html_content :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    #partial switch parser.insertion_mode {
        case .Initial: return handle_initial_insertion_mode(parser, document, token)
        case .BeforeHtml: return handle_before_html_insertion_mode(parser, document, token)
        case .BeforeHead: return handle_before_head_insertion_mode(parser, document, token)
        case .InHead: return handle_in_head_insertion_mode(parser, document, token)
        case .AfterHead: return handle_after_head_insertion_mode(parser, document, token)
        case .InBody: return handle_in_body_insertion_mode(parser, document, token)
        case .Text: return handle_text_insertion_mode(parser, document, token)
        case .InTable: return handle_in_table_insertion_mode(parser, document, token)
        case .InTableText: return handle_in_table_text_insertion_mode(parser, document, token)
        case .InTableBody: return handle_in_table_body_insertion_mode(parser, document, token)
        case .InRow: return handle_in_row_insertion_mode(parser, document, token)
        case .InCell: return handle_in_cell_insertion_mode(parser, document, token)
        case .AfterBody: return handle_after_body_insertion_mode(parser, document, token)
        case .AfterAfterBody: return handle_after_after_body_insertion_mode(parser, document, token)

        case:
            fmt.println("So far:")
            print_document(document)
            fmt.assertf(false, "TODO: Insertion mode %s unhandled", parser.insertion_mode)
    }
    return false
}

// https://html.spec.whatwg.org/#the-initial-insertion-mode
// When the user agent is to apply the rules for the "initial" insertion mode, the user agent must handle the token as follows:
handle_initial_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    // A character token that is one of U+0009 CHARACTER TABULATION, U+000A LINE FEED (LF), U+000C FORM FEED (FF), U+000D CARRIAGE RETURN (CR), or U+0020 SPACE
    if is_character && (character.data in bit_set['\t'..=' ']{'\t', '\n', '\f', '\r', ' '}) {
        // Ignore the token.
    }
    else if is_comment { // A comment token
        // Insert a comment as the last child of the Document object.
        insert_comment(parser, comment, document, len(document.children))
    }
    else if is_doctype { // A DOCTYPE token
        // If the DOCTYPE token's name is not "html", or the token's public identifier is not missing, or the token's system identifier is neither missing nor
        // "about:legacy-compat", then there is a parse error.
        if (doctype.name_present && strings.to_string(doctype.name) != "html") || doctype.public_id_present || \
            (doctype.system_id_present && strings.to_string(doctype.system_id) != "about:legacy-compat") {
            report_parse_error(.ErrorInTreeConstruction)
        }

        // Append a DocumentType node to the Document node, with its name set to the name given in the DOCTYPE token, or the empty string if the name was
        // missing; its public ID set to the public identifier given in the DOCTYPE token, or the empty string if the public identifier was missing; and
        // its system ID set to the system identifier given in the DOCTYPE token, or the empty string if the system identifier was missing.
        dom_doctype := make_node(Document_Type, document)
        if doctype.name_present do dom_doctype.name = strings.to_string(doctype.name)
        if doctype.public_id_present do dom_doctype.public_id = strings.to_string(doctype.public_id)
        if doctype.system_id_present do dom_doctype.system_id = strings.to_string(doctype.system_id)
        append_child(document, dom_doctype)

        // @TODO: Then, if the document is not an iframe srcdoc document, and the parser cannot change the mode flag is false,
        // and the DOCTYPE token matches one of the conditions in the following list (see link), then set the Document to quirks mode:
        // @TODO: Otherwise, if the document is not an iframe srcdoc document, and the parser cannot change the mode flag is false, and the DOCTYPE
        // token matches one of the conditions in the following list (see link), then then set the Document to limited-quirks mode:
        // Then, switch the insertion mode to "before html".
        parser.insertion_mode = .BeforeHtml
    }
    else { // Anything else
        // @TODO: If the document is not an iframe srcdoc document, then this is a parse error; if the parser cannot change the mode flag is false,
        // set the Document to quirks mode.
        //In any case, switch the insertion mode to "before html", then reprocess the token.
        parser.insertion_mode = .BeforeHtml
    }

    return true
}

// https://html.spec.whatwg.org/#the-before-html-insertion-mode
// When the user agent is to apply the rules for the "before html" insertion mode, the user agent must handle the token as follows:
handle_before_html_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    if is_doctype { // A DOCTYPE token
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else if is_comment { // A comment token
        // Insert a comment as the last child of the Document object.
        insert_comment(parser, comment, document, len(document.children))
    }
    else if is_character && (character.data in bit_set['\t'..=' ']{'\t', '\n', '\f', '\r', ' '}) {
    // A character token that is one of U+0009 CHARACTER TABULATION, U+000A LINE FEED (LF), U+000C FORM FEED (FF), U+000D CARRIAGE RETURN (CR), or U+0020 SPACE
        // Ignore the token.
    }
    else if is_start_tag_named_one_of(token, "html") { // A start tag whose tag name is "html"
        tag := token.(Tag_Token)
        // Create an element for the token in the HTML namespace, with the Document as the intended parent. Append it to the Document object.
        // Put this element in the stack of open elements.
        element := create_element_for_token(tag, HTML_NAMESPACE, document)
        append_child(document, element)
        append(&parser.stack_of_open_elements, element)
        // Switch the insertion mode to "before head".
        parser.insertion_mode = .BeforeHead
    }
    else if is_end_tag_named_one_of(token, "head", "body", "html", "br") { // An end tag whose tag name is one of: "head", "body", "html", "br"
        // Act as described in the "anything else" entry below.
        element := make_node(Element, document)
        append_child(document, element)
        append(&parser.stack_of_open_elements, element)
        parser.insertion_mode = .BeforeHead
        parser.should_reprocess = true
    }
    else if is_end_tag(token) { // Any other end tag
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else { // Anything else
        // Create an html element whose node document is the Document object. Append it to the Document object. Put this element in the stack of open elements.
        element := make_node(Element, document)
        append_child(document, element)
        append(&parser.stack_of_open_elements, element)
        // Switch the insertion mode to "before head", then reprocess the token.
        parser.insertion_mode = .BeforeHead
        parser.should_reprocess = true
    }

    return true
}

// https://html.spec.whatwg.org/#the-before-head-insertion-mode
// When the user agent is to apply the rules for the "before head" insertion mode, the user agent must handle the token as follows:
handle_before_head_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    // A character token that is one of U+0009 CHARACTER TABULATION, U+000A LINE FEED (LF), U+000C FORM FEED (FF), U+000D CARRIAGE RETURN (CR), or U+0020 SPACE
    if is_character && (character.data in bit_set['\t'..=' ']{'\t', '\n', '\f', '\r', ' '}) {
        // Ignore the token.
    }
    else if is_comment { // A comment token
        // Insert a comment.
        insert_comment(parser, comment)
    }
    else if is_doctype { // A DOCTYPE token
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else if is_start_tag_named_one_of(token, "html") { // A start tag whose tag name is "html"
        // Process the token using the rules for the "in body" insertion mode.
        handle_in_body_insertion_mode(parser, document, token)
    }
    else if is_start_tag_named_one_of(token, "head") { // A start tag whose tag name is "head"
        tag := token.(Tag_Token)
        // Insert an HTML element for the token.
        element := insert_html_element(parser, tag)
        // Set the head element pointer to the newly created head element.
        parser.head_element_pointer = element
        // Switch the insertion mode to "in head".
        parser.insertion_mode = .InHead
    }
    else if is_end_tag_named_one_of(token, "head", "body", "html", "br") { // An end tag whose tag name is one of: "head", "body", "html", "br"
        tag := token.(Tag_Token)
        // Act as described in the "anything else" entry below.
        no_attr_head := Tag_Token{is_start=true}
        fmt.sbprint(&no_attr_head.name, "head")
        element := create_element_for_token(no_attr_head, HTML_NAMESPACE, document)
        parser.head_element_pointer = element 
        parser.insertion_mode = .InHead
        parser.should_reprocess = true
    }
    else if is_end_tag(token) { // Any other end tag
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else { // Anything else
        // Insert an HTML element for a "head" start tag token with no attributes.
        no_attr_head := Tag_Token{is_start=true}
        fmt.sbprint(&no_attr_head.name, "head")
        element := create_element_for_token(no_attr_head, HTML_NAMESPACE, document)
        // Set the head element pointer to the newly created head element.
        parser.head_element_pointer = element 
        // Switch the insertion mode to "in head".
        parser.insertion_mode = .InHead
        // Reprocess the current token.
        parser.should_reprocess = true
    }

    return true
} 

// https://html.spec.whatwg.org/#parsing-main-inhead
// When the user agent is to apply the rules for the "in head" insertion mode, the user agent must handle the token as follows:
handle_in_head_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    // A character token that is one of U+0009 CHARACTER TABULATION, U+000A LINE FEED (LF), U+000C FORM FEED (FF), U+000D CARRIAGE RETURN (CR), or U+0020 SPACE
    if is_character && (character.data in bit_set['\t'..=' ']{'\t', '\n', '\f', '\r', ' '}) {
        // Insert the character.
        insert_character(parser, document, character)
    }
    else if is_comment { // A comment token
        // Insert a comment.
        insert_comment(parser, comment)
    }
    else if is_doctype { // A DOCTYPE token
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else if is_start_tag_named_one_of(token, "html") { // A start tag whose tag name is "html"
        // Process the token using the rules for the "in body" insertion mode.
        handle_in_body_insertion_mode(parser, document, token)
    }
    else if is_start_tag_named_one_of(token, "base", "basefont", "bgsound", "link") { 
    // A start tag whose tag name is one of: "base", "basefont", "bgsound", "link"
        tag := token.(Tag_Token)
        // Insert an HTML element for the token. Immediately pop the current node off the stack of open elements.
        insert_html_element(parser, tag)
        pop(&parser.stack_of_open_elements)
        // @TODO: Acknowledge the token's self-closing flag, if it is set.
    }
    else if is_start_tag_named_one_of(token, "meta") { // A start tag whose tag name is "meta"
        tag := token.(Tag_Token)
        // Insert an HTML element for the token. Immediately pop the current node off the stack of open elements.
        insert_html_element(parser, tag)
        pop(&parser.stack_of_open_elements)
        // @TODO: Acknowledge the token's self-closing flag, if it is set.

        // @TODO:If the active speculative HTML parser is null, then:
        if true {
            // @TODO: If the element has a charset attribute, and getting an encoding from its value results in an encoding, and the confidence
            // is currently tentative, then change the encoding to the resulting encoding.

            // @TODO: Otherwise, if the element has an http-equiv attribute whose value is an ASCII case-insensitive match for the string "Content-Type", and the element has a content attribute, and applying the algorithm for extracting a character encoding from a meta element to that attribute's value returns an encoding, and the confidence is currently tentative, then change the encoding to the extracted encoding.
        }
    }
    else if is_start_tag_named_one_of(token, "title") { // A start tag whose tag name is "title"
        tag := token.(Tag_Token)
        // Follow the generic RCDATA element parsing algorithm.
        parse_generic_text(parser, tag, false)
    }
    else if (is_start_tag_named_one_of(token, "noscript") && parser.scripting_flag) || is_start_tag_named_one_of(token, "noframes", "style") {                 
    // A start tag whose tag name is "noscript", if the scripting flag is enabled
    // A start tag whose tag name is one of: "noframes", "style"
        tag := token.(Tag_Token)
        // Follow the generic raw text element parsing algorithm.
        parse_generic_text(parser, tag)
    }
    else if is_start_tag_named_one_of(token, "noscript") && !parser.scripting_flag {
    // A start tag whose tag name is "noscript", if the scripting flag is disabled
        tag := token.(Tag_Token)
        // Insert an HTML element for the token.
        insert_html_element(parser, tag)
        // Switch the insertion mode to "in head noscript".
        parser.insertion_mode = .InHeadNoscript
    }
    else if is_start_tag_named_one_of(token, "script") { // A start tag whose tag name is "script"
        assert(false, "TODO")
        /*
        Run these steps:
            Let the adjusted insertion location be the appropriate place for inserting a node.
 d           Create an element for the token in the HTML namespace, with the intended parent being the element in which the adjusted insertion location finds itself.
            Set the element's parser document to the Document, and set the element's force async to false.
            This ensures that, if the script is external, any document.write() calls in the script will execute in-line, instead of blowing the document away, as would happen in most other cases. It also prevents the script from executing until the end tag is seen.
            If the parser was created as part of the HTML fragment parsing algorithm, then set the script element's already started to true. (fragment case)
            If the parser was invoked via the document.write() or document.writeln() methods, then optionally set the script element's already started to true. (For example, the user agent might use this clause to prevent execution of cross-origin scripts inserted via document.write() under slow network conditions, or when the page has already taken a long time to load.)
            Insert the newly created element at the adjusted insertion location.
            Push the element onto the stack of open elements so that it is the new current node.
            Switch the tokenizer to the script data state.
            Let the original insertion mode be the current insertion mode.
            Switch the insertion mode to "text".
        */
    }
    else if is_end_tag_named_one_of(token, "head") { // An end tag whose tag name is "head"
        tag := token.(Tag_Token)
        // Pop the current node (which will be the head element) off the stack of open elements.
        pop(&parser.stack_of_open_elements)
        // Switch the insertion mode to "after head".
        parser.insertion_mode = .AfterHead
    }
    else if is_end_tag_named_one_of(token, "body", "html", "br") { // An end tag whose tag name is one of: "body", "html", "br"
        tag := token.(Tag_Token)
        // Act as described in the "anything else" entry below.
        pop(&parser.stack_of_open_elements)
        parser.insertion_mode = .AfterHead
        parser.should_reprocess = true
    }
    else if is_start_tag_named_one_of(token, "template") { // A start tag whose tag name is "template"
        assert(false, "TODO")
        /*
        Let template start tag be the start tag.
        Insert a marker at the end of the list of active formatting elements.
        Set the frameset-ok flag to "not ok".
        Switch the insertion mode to "in template".
        Push "in template" onto the stack of template insertion modes so that it is the new current template insertion mode.
        Let the adjusted insertion location be the appropriate place for inserting a node.
        Let intended parent be the element in which the adjusted insertion location finds itself.
        Let document be intended parent's node document.
        If any of the following are false:
            template start tag's shadowrootmode is not in the none state;
            Document's allow declarative shadow roots is true; or
            the adjusted current node is not the topmost element in the stack of open elements,
        then insert an HTML element for the token.
        Otherwise:
            Let declarative shadow host element be adjusted current node.
            Let template be the result of insert a foreign element for template start tag, with HTML namespace and true.
            Let mode be template start tag's shadowrootmode attribute's value.
            Let clonable be true if template start tag has a shadowrootclonable attribute; otherwise false.
            Let serializable be true if template start tag has a shadowrootserializable attribute; otherwise false.
            Let delegatesFocus be true if template start tag has a shadowrootdelegatesfocus attribute; otherwise false.
            If declarative shadow host element is a shadow host, then insert an element at the adjusted insertion location with template.
            Otherwise:
                Attach a shadow root with declarative shadow host element, mode, clonable, serializable, delegatesFocus, and "named". If an exception is thrown, then catch it, report the exception, insert an element at the adjusted insertion location with template, and return.
                Let shadow be declarative shadow host element's shadow root.
                Set shadow's declarative to true.
                Set template's template contents property to shadow.
                Set shadow's available to element internals to true.
        */
    }
    else if is_end_tag_named_one_of(token, "template") { // An end tag whose tag name is "template"
        assert(false, "TODO")
        /*
        If there is no template element on the stack of open elements, then this is a parse error; ignore the token.
        Otherwise, run these steps:
            Generate all implied end tags thoroughly.
            If the current node is not a template element, then this is a parse error.
            Pop elements from the stack of open elements until a template element has been popped from the stack.
            Clear the list of active formatting elements up to the last marker.
            Pop the current template insertion mode off the stack of template insertion modes.
            Reset the insertion mode appropriately.
        */
    }
    else if is_start_tag_named_one_of(token, "head") || is_end_tag(token) {
    // A start tag whose tag name is "head"
    // Any other end tag
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else { // Anything else
        // Pop the current node (which will be the head element) off the stack of open elements.
        pop(&parser.stack_of_open_elements)
        // Switch the insertion mode to "after head".
        parser.insertion_mode = .AfterHead
        // Reprocess the token.
        parser.should_reprocess = true
    }

    return true
}

// https://html.spec.whatwg.org/#the-after-head-insertion-mode
// When the user agent is to apply the rules for the "after head" insertion mode, the user agent must handle the token as follows:
handle_after_head_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    // A character token that is one of U+0009 CHARACTER TABULATION, U+000A LINE FEED (LF), U+000C FORM FEED (FF), U+000D CARRIAGE RETURN (CR), or U+0020 SPACE
    if is_character && (character.data in bit_set['\t'..=' ']{'\t', '\n', '\f', '\r', ' '}) {
        // Insert the character.
        insert_character(parser, document, character)
    }
    else if is_comment { // A comment token
        // Insert a comment.
        insert_comment(parser, comment)
    }
    else if is_doctype { // A DOCTYPE token
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else if is_start_tag_named_one_of(token, "html") { // A start tag whose tag name is "html"
        // Process the token using the rules for the "in body" insertion mode.
        handle_in_body_insertion_mode(parser, document, token)
    }
    else if is_start_tag_named_one_of(token, "body") { // A start tag whose tag name is "body"
        tag := token.(Tag_Token)
        // Insert an HTML element for the token.
        insert_html_element(parser, tag)
        // Set the frameset-ok flag to "not ok".
        parser.frameset_ok = false
        // Switch the insertion mode to "in body".
        parser.insertion_mode = .InBody
    }
    else if is_start_tag_named_one_of(token, "frameset") { // A start tag whose tag name is "frameset"
        tag := token.(Tag_Token)
        // Insert an HTML element for the token.
        insert_html_element(parser, tag)
        // Switch the insertion mode to "in frameset".
        parser.insertion_mode = .InFrameset
    }
    else if is_start_tag_named_one_of(token, "base", "basefont", "bgsound", "link", "meta", "noframes", "script", "style", "template", "title") { 
    // A start tag whose tag name is one of: "base", "basefont", "bgsound", "link", "meta", "noframes", "script", "style", "template", "title"
        // Parse error.
        report_parse_error(.ErrorInTreeConstruction)
        // Push the node pointed to by the head element pointer onto the stack of open elements.
        append(&parser.stack_of_open_elements, parser.head_element_pointer)
        // Process the token using the rules for the "in head" insertion mode.
        handle_in_head_insertion_mode(parser, document, token)
        // Remove the node pointed to by the head element pointer from the stack of open elements. (It might not be the current node at this point.)
        remove_from_stack(parser, parser.head_element_pointer)
    }
    else if is_end_tag_named_one_of(token, "template") { // An end tag whose tag name is "template"
        // Process the token using the rules for the "in head" insertion mode.
        handle_in_head_insertion_mode(parser, document, token)
    }
    else if is_end_tag_named_one_of(token, "body", "html", "br") { // An end tag whose tag name is one of: "body", "html", "br"
        no_attr_body := Tag_Token{is_start=true}
        fmt.sbprint(&no_attr_body.name, "body")
        insert_html_element(parser, no_attr_body)
        parser.insertion_mode = .InBody
        parser.should_reprocess = true
    }
    else if is_start_tag_named_one_of(token, "head") || is_end_tag(token) {
    // A start tag whose tag name is "head"
    // Any other end tag
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else { // Anything else
        // Insert an HTML element for a "body" start tag token with no attributes.
        no_attr_body := Tag_Token{is_start=true}
        fmt.sbprint(&no_attr_body.name, "body")
        insert_html_element(parser, no_attr_body)
        // Switch the insertion mode to "in body".
        parser.insertion_mode = .InBody
        // Reprocess the current token.
        parser.should_reprocess = true
    }

    return true
}

// https://html.spec.whatwg.org/#parsing-main-inbody
// When the user agent is to apply the rules for the "in body" insertion mode, the user agent must handle the token as follows:
handle_in_body_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    _, is_eof := token.(Eof_Token)
    if is_character && character.data == '\u0000' { // A character token that is U+0000 NULL
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else if is_character && (character.data in bit_set['\t'..=' ']{'\t', '\n', '\f', '\r', ' '}) {
    // A character token that is one of U+0009 CHARACTER TABULATION, U+000A LINE FEED (LF), U+000C FORM FEED (FF), U+000D CARRIAGE RETURN (CR), or U+0020 SPACE
        // @TODO: Reconstruct the active formatting elements, if any.
        // Insert the token's character.
        insert_character(parser, document, character)
    }
    else if is_character { // Any other character token
        //@TODO: Reconstruct the active formatting elements, if any.
        // Insert the token's character.
        insert_character(parser, document, character)
        // Set the frameset-ok flag to "not ok".
        parser.frameset_ok = false
    }
    else if is_comment { // A comment token
        // Insert a comment.
        insert_comment(parser, comment)
    }
    else if is_doctype { // A DOCTYPE token
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else if is_start_tag_named_one_of(token, "html") { // A start tag whose tag name is "html"
        // Parse error.
        report_parse_error(.ErrorInTreeConstruction)
        // If there is a template element on the stack of open elements, then ignore the token.
        template_on_stack := false
        for elem in parser.stack_of_open_elements {
            if elem.type == .Template {
                template_on_stack = true
                break
            }
        }

        if template_on_stack {
            // Ignore the token
        }
        else {
        // @TODO: Otherwise, for each attribute on the token, check to see if the attribute is already present on the top element of the stack of open elements.
        // If it is not, add the attribute and its corresponding value to that element.
        }
    }
    else if is_start_tag_named_one_of(token, "base", "basefont", "bgsound", "link", "meta", "noframes", "script", "style", "template", "title") || \
        is_end_tag_named_one_of(token, "template") {
    // A start tag whose tag name is one of: "base", "basefont", "bgsound", "link", "meta", "noframes", "script", "style", "template", "title"
    // An end tag whose tag name is "template"
        // Process the token using the rules for the "in head" insertion mode.
        handle_in_head_insertion_mode(parser, document, token)
    }
    else if is_start_tag_named_one_of(token, "body") { // A start tag whose tag name is "body"
        // Parse error.
        report_parse_error(.ErrorInTreeConstruction)

        // If the stack of open elements has only one node on it, if the second element on the stack of open elements is not a body element, or if
        // there is a template element on the stack of open elements, then ignore the token. (fragment case or there is a template element on the stack)
        if len(parser.stack_of_open_elements) == 1 || parser.stack_of_open_elements[1].type != .Body || stack_has_element_of_type(parser, .Template) {
            // Ignore
        }
        else {
        // Otherwise, set the frameset-ok flag to "not ok"; then, @TODO: for each attribute on the token, check to see if the attribute is already present on the
        // body element (the second element) on the stack of open elements, and if it is not, add the attribute and its corresponding value to that element.
            parser.frameset_ok = false
        }
    }
    else if is_start_tag_named_one_of(token, "frameset") { // A start tag whose tag name is "frameset"
        tag := token.(Tag_Token)
        // Parse error.
        report_parse_error(.ErrorInTreeConstruction)
        // If the stack of open elements has only one node on it, or if the second element on the stack of open elements is not a body element, then ignore the token.
        // (fragment case or there is a template element on the stack)
        if len(parser.stack_of_open_elements) == 1 || parser.stack_of_open_elements[1].type != .Body {
            // Ignore the token
        }
        else if !parser.frameset_ok {
        // If the frameset-ok flag is set to "not ok", ignore the token.
            // Ignore the token
        }
        else {
        // Otherwise, run the following steps:
            // Remove the second element on the stack of open elements from its parent node, if it has one.
            if len(parser.stack_of_open_elements) >= 2 do remove_from_parent(parser.stack_of_open_elements[1])
            // Pop all the nodes from the bottom of the stack of open elements, from the current node up to, but not including, the root html element.
            for current_node(parser).type != .Html do pop(&parser.stack_of_open_elements)
            // Insert an HTML element for the token.
            insert_html_element(parser, tag)
            // Switch the insertion mode to "in frameset".
            parser.insertion_mode = .InFrameset
        }
    }
    else if is_eof { // An end-of-file token
        // @TODO: If the stack of template insertion modes is not empty, then process the token using the rules for the "in template" insertion mode.
        if false {
        }
        else {
        // Otherwise, follow these steps:
            // If there is a node in the stack of open elements that is not either a dd element, a dt element, an li element, an optgroup element, an option
            // element, a p element, an rb element, an rp element, an rt element, an rtc element, a tbody element, a td element, a tfoot element, a th element,
            // a thead element, a tr element, the body element, or the html element, then this is a parse error.
            if stack_has_element_that_is_not(parser, \
                {.Dd, .Dt, .Li, .OptGroup, .Option, .P, .Rb, .Rp, .Rt, .Rtc, .TBody, .Td, .TFoot, .Th, .THead, .Tr, .Body, .Html}) {
                report_parse_error(.ErrorInTreeConstruction)
            }

            return false
        }
    }
    else if is_end_tag_named_one_of(token, "body") { // An end tag whose tag name is "body"
        // If the stack of open elements does not have a body element in scope, this is a parse error; ignore the token.
        if !stack_has_element_in_scope(parser, .Body) {
            report_parse_error(.ErrorInTreeConstruction)
        }
        else if stack_has_element_that_is_not(parser, \
            {.Dd, .Dt, .Li, .OptGroup, .Option, .P, .Rb, .Rp, .Rt, .Rtc, .TBody, .Td, .TFoot, .Th, .THead, .Tr, .Body, .Html}) {
        // Otherwise, if there is a node in the stack of open elements that is not either a dd element, a dt element, an li element, an optgroup element, an option element,
        // a p element, an rb element, an rp element, an rt element, an rtc element, a tbody element, a td element, a tfoot element, a th element, a thead element, a tr element,
        // the body element, or the html element, then this is a parse error.
            report_parse_error(.ErrorInTreeConstruction)
        }
        // Switch the insertion mode to "after body".
        parser.insertion_mode = .AfterBody
    }
    else if is_end_tag_named_one_of(token, "html") { // An end tag whose tag name is "html"
        // If the stack of open elements does not have a body element in scope, this is a parse error; ignore the token.
        if !stack_has_element_of_type(parser, .Body) {
            report_parse_error(.ErrorInTreeConstruction)
        }
        else if stack_has_element_that_is_not(parser, \
            {.Dd, .Dt, .Li, .OptGroup, .Option, .P, .Rb, .Rp, .Rt, .Rtc, .TBody, .Td, .TFoot, .Th, .THead, .Tr, .Body, .Html}) {
        // Otherwise, if there is a node in the stack of open elements that is not either a dd element, a dt element, an li element, an optgroup element, an option element,
        // a p element, an rb element, an rp element, an rt element, an rtc element, a tbody element, a td element, a tfoot element, a th element, a thead element, a tr element,
        // the body element, or the html element, then this is a parse error.
            report_parse_error(.ErrorInTreeConstruction)
            // Switch the insertion mode to "after body".
            parser.insertion_mode = .AfterBody
            // Reprocess the token.
            parser.should_reprocess = true
        }
    }
    else if is_start_tag_named_one_of(token, "address", "article", "aside", "blockquote", "center", "details", "dialog", "dir", "div", \
        "dl", "fieldset", "figcaption", "figure", "footer", "header", "hgroup", "main", "menu", "nav", "ol", "p", "search", "section", "summary", "ul") { 
    // A start tag whose tag name is one of: "address", "article", "aside", "blockquote", "center", "details", "dialog", "dir", "div",
    // "dl", "fieldset", "figcaption", "figure", "footer", "header", "hgroup", "main", "menu", "nav", "ol", "p", "search", "section", "summary", "ul"
        tag := token.(Tag_Token)
        // @TODO: If the stack of open elements has a p element in button scope, then close a p element.
        // Insert an HTML element for the token.
        insert_html_element(parser, tag)
    }
    else if is_start_tag_named_one_of(token, "h1", "h2", "h3", "h4", "h5", "h6") { // A start tag whose tag name is one of: "h1", "h2", "h3", "h4", "h5", "h6"
        tag := token.(Tag_Token)
        // @TODO: If the stack of open elements has a p element in button scope, then close a p element.
        if elem, is_elem := current_node(parser).node_type.(^Element); is_elem && string_is_any_of(elem.local_name, "h1", "h2", "h3", "h4", "h5", "h6") { 
        // If the current node is an HTML element whose tag name is one of "h1", "h2", "h3", "h4", "h5", or "h6", then this is a parse error; pop the current
        // node off the stack of open elements.
            report_parse_error(.ErrorInTreeConstruction)
            pop(&parser.stack_of_open_elements)
        }
        // Insert an HTML element for the token.
        insert_html_element(parser, tag)
    }
    else if is_start_tag_named_one_of(token, "pre", "listing") { // A start tag whose tag name is one of: "pre", "listing"
    tag := token.(Tag_Token)
        // @TODO: If the stack of open elements has a p element in button scope, then close a p element.
        // Insert an HTML element for the token.
        insert_html_element(parser, tag)
        // If the next token is a U+000A LINE FEED (LF) character token, then ignore that token and move on to the next one. (Newlines at the start of pre blocks
        // are ignored as an authoring convenience.)
        assert(false, "TODO: Peek at tokens")
        // Set the frameset-ok flag to "not ok".
        parser.frameset_ok = false
    }
    else if is_start_tag_named_one_of(token, "form") { // A start tag whose tag name is "form"
        tag := token.(Tag_Token)
        // If the form element pointer is not null, and there is no template element on the stack of open elements, then this is a parse error; ignore the token.
        if parser.form_element_pointer != nil && !stack_has_element_of_type(parser, .Template) {
            report_parse_error(.ErrorInTreeConstruction)
        }
        else { // Otherwise:
            // @TODO: If the stack of open elements has a p element in button scope, then close a p element.
            // Insert an HTML element for the token, and, if there is no template element on the stack of open elements, set the form element pointer to point to
            // the element created.
            element := insert_html_element(parser, tag)
            if !stack_has_element_of_type(parser, .Template) {
                parser.form_element_pointer = element
            }
        }
    }
    else if is_start_tag_named_one_of(token, "li") { // A start tag whose tag name is "li"
        tag := token.(Tag_Token)
        // Set the frameset-ok flag to "not ok".
        parser.frameset_ok = false
        // Initialize node to be the current node (the bottommost node of the stack).
        node, node_index := current_node_with_index(parser)

        // Loop: If node is an li element, then run these substeps:
        for {
            if node.type == .Li {
                // Generate implied end tags, except for li elements.
                generate_implied_end_tags(parser, {.Li})
                // If the current node is not an li element, then this is a parse error.
                if current_node(parser).type != .Li do report_parse_error(.ErrorInTreeConstruction)
                // Pop elements from the stack of open elements until an li element has been popped from the stack.
                for current_node(parser).type != .Li {
                    pop(&parser.stack_of_open_elements)
                }
                pop(&parser.stack_of_open_elements)
                // Jump to the step labeled done below.
                break
            }
            // If node is in the special category, but is not an address, div, or p element, then jump to the step labeled done below.
            if (node.type in special_category) && (node.type not_in bit_set[Element_Type]{.Div, .P}) do break
            // Otherwise, set node to the previous entry in the stack of open elements and return to the step labeled loop.
            node, node_index = set_to_previous_stack_entry(parser, node_index)
        }

        // Done: @TODO: If the stack of open elements has a p element in button scope, then close a p element.
        // Finally, insert an HTML element for the token.
        insert_html_element(parser, tag)
    }
    else if is_start_tag_named_one_of(token, "dd", "dt") { // A start tag whose tag name is one of: "dd", "dt"
        tag := token.(Tag_Token)
        // Set the frameset-ok flag to "not ok".
        parser.frameset_ok = false
        // Initialize node to be the current node (the bottommost node of the stack).
        node, node_index := current_node_with_index(parser)

        // Loop: If node is a dd element, then run these substeps:
        for {
            if node.type == .Dd {
                // Generate implied end tags, except for dd elements.
                generate_implied_end_tags(parser, {.Dd})
                // If the current node is not a dd element, then this is a parse error.
                if current_node(parser).type != .Dd do report_parse_error(.ErrorInTreeConstruction)
                // Pop elements from the stack of open elements until a dd element has been popped from the stack.
                for current_node(parser).type != .Dd {
                    pop(&parser.stack_of_open_elements)
                }
                pop(&parser.stack_of_open_elements)
                // Jump to the step labeled done below.
                break
            }
            if node.type == .Dt {
            // If node is a dt element, then run these substeps:
                // Generate implied end tags, except for dt elements.
                generate_implied_end_tags(parser, {.Dt})
                // If the current node is not a dt element, then this is a parse error.
                if current_node(parser).type != .Dt do report_parse_error(.ErrorInTreeConstruction)
                // Pop elements from the stack of open elements until a dt element has been popped from the stack.
                for current_node(parser).type != .Dt {
                    pop(&parser.stack_of_open_elements)
                }
                pop(&parser.stack_of_open_elements)
                // Jump to the step labeled done below.
                break
            }
            if node.type in (special_category - bit_set[Element_Type]{.Address, .Div, .P}) {
            // If node is in the special category, but is not an address, div, or p element, then jump to the step labeled done below.
                break
            }
            // Otherwise, set node to the previous entry in the stack of open elements and return to the step labeled loop.
            node, node_index := set_to_previous_stack_entry(parser, node_index)
        }

        // Done: @TODO: If the stack of open elements has a p element in button scope, then close a p element.
        // Finally, insert an HTML element for the token.
        insert_html_element(parser, tag)
    }
    else if is_start_tag_named_one_of(token, "plaintext") { // A start tag whose tag name is "plaintext"
        tag := token.(Tag_Token)
        // @TODO: If the stack of open elements has a p element in button scope, then close a p element.
        // Insert an HTML element for the token.
        insert_html_element(parser, tag)
        // Switch the tokenizer to the PLAINTEXT state.
        parser.tokenizer.state = .Plaintext
    }
    else if is_start_tag_named_one_of(token, "button") { // A start tag whose tag name is "button"
        tag := token.(Tag_Token)
        /* @TODO:
        If the stack of open elements has a button element in scope, then run these substeps:
            Parse error.
            Generate implied end tags.
            Pop elements from the stack of open elements until a button element has been popped from the stack.
        */
        // @TODO: Reconstruct the active formatting elements, if any.
        // Insert an HTML element for the token.
        insert_html_element(parser, tag)
        // Set the frameset-ok flag to "not ok".
        parser.frameset_ok = false
    }
    else if is_end_tag_named_one_of(token, "address", "article", "aside", "blockquote", "button", "center", "details", "dialog", "dir", "div", "dl", \
        "fieldset", "figcaption", "figure", "footer", "header", "hgroup", "listing", "main", "menu", "nav", "ol", "pre", "search", "section", "summary", "ul") {
        tag := token.(Tag_Token)
    // An end tag whose tag name is one of: "address", "article", "aside", "blockquote", "button", "center", "details", "dialog", "dir", "div", "dl",
    // "fieldset", "figcaption", "figure", "footer", "header", "hgroup", "listing", "main", "menu", "nav", "ol", "pre", "search", "section", "summary", "ul"
        // @TODO: If the stack of open elements does not have an element in scope that is an HTML element with the same tag name as that of the token, then this is 
        // a parse error; ignore the token.
        if false {
        }
        else { // Otherwise, run these steps:
            // Generate implied end tags.
            generate_implied_end_tags(parser)
            // If the current node is not an HTML element with the same tag name as that of the token, then this is a parse error.
            if current_node(parser).local_name != strings.to_string(tag.name) {
                report_parse_error(.ErrorInTreeConstruction)
            }
            // Pop elements from the stack of open elements until an HTML element with the same tag name as the token has been popped from the stack.
            for current_node(parser).local_name != strings.to_string(tag.name) {
                pop(&parser.stack_of_open_elements)
            }
            pop(&parser.stack_of_open_elements)
        }
    }
    else if is_end_tag_named_one_of(token, "form") { // An end tag whose tag name is "form"
        // If there is no template element on the stack of open elements, then run these substeps:
        if !stack_has_element_of_type(parser, .Template) {
            // Let node be the element that the form element pointer is set to, or null if it is not set to an element.
            node := parser.form_element_pointer
            // Set the form element pointer to null.
            parser.form_element_pointer = nil
            // @TODO: If node is null or if the stack of open elements does not have node in scope, then this is a parse error; return and ignore the token.
            // Generate implied end tags.
            generate_implied_end_tags(parser)
            // If the current node is not node, then this is a parse error.
            if current_node(parser) != node do report_parse_error(.ErrorInTreeConstruction)
            // Remove node from the stack of open elements.
            remove_from_stack(parser, node)
        }
        else { // If there is a template element on the stack of open elements, then run these substeps instead:
            // @TODO: If the stack of open elements does not have a form element in scope, then this is a parse error; return and ignore the token.
            // Generate implied end tags.
            generate_implied_end_tags(parser)
            // If the current node is not a form element, then this is a parse error.
            if current_node(parser).type != .Form do report_parse_error(.ErrorInTreeConstruction)
            // Pop elements from the stack of open elements until a form element has been popped from the stack.
            for current_node(parser).type != .Form {
                pop(&parser.stack_of_open_elements)
            }
            pop(&parser.stack_of_open_elements)
        }
    }
    else if is_end_tag_named_one_of(token, "p") { // An end tag whose tag name is "p"
        // @TODO: If the stack of open elements does not have a p element in button scope, then this is a parse error; insert an HTML element for a "p" start tag token with no attributes.
        // Close a p element.
        close_p_element(parser)
    }
    else if is_end_tag_named_one_of(token, "li") { // An end tag whose tag name is "li"
        // @TODO: If the stack of open elements does not have an li element in list item scope, then this is a parse error; ignore the token.
        if false {}
        else { // Otherwise, run these steps:
            // Generate implied end tags, except for li elements.
            generate_implied_end_tags(parser, {.Li})
            // If the current node is not an li element, then this is a parse error.
            if current_node(parser).type != .Li do report_parse_error(.ErrorInTreeConstruction)
            // Pop elements from the stack of open elements until an li element has been popped from the stack.
            for current_node(parser).type != .Li {
                pop(&parser.stack_of_open_elements)
            }
            pop(&parser.stack_of_open_elements)
        }
    }
    else if is_end_tag_named_one_of(token, "dd", "dt") { // An end tag whose tag name is one of: "dd", "dt"
        tag := token.(Tag_Token)
        // @TODO: If the stack of open elements does not have an element in scope that is an HTML element with the same tag name as that of the token, then this is a parse error; ignore the token.
        if false {}
        else { // Otherwise, run these steps:
            // Generate implied end tags, except for HTML elements with the same tag name as the token.
            if strings.to_string(tag.name) == "dd" do generate_implied_end_tags(parser, {.Dd})
            else do generate_implied_end_tags(parser, {.Dt})
            // If the current node is not an HTML element with the same tag name as that of the token, then this is a parse error.
            if current_node(parser).local_name != strings.to_string(tag.name) do report_parse_error(.ErrorInTreeConstruction)
            // Pop elements from the stack of open elements until an HTML element with the same tag name as the token has been popped from the stack.
            for current_node(parser).local_name != strings.to_string(tag.name) {
                pop(&parser.stack_of_open_elements)
            }
            pop(&parser.stack_of_open_elements)
        }
    }
    else if is_end_tag_named_one_of(token, "h1", "h2", "h3", "h4", "h5", "h6") { // An end tag whose tag name is one of: "h1", "h2", "h3", "h4", "h5", "h6"
        tag := token.(Tag_Token)
        // @TODO: If the stack of open elements does not have an element in scope that is an HTML element and whose tag name is one of "h1", "h2", "h3", "h4", "h5", or "h6", then this is a parse error; ignore the token.
        if false {}
        else { // Otherwise, run these steps:
            // Generate implied end tags.
            generate_implied_end_tags(parser)
            // If the current node is not an HTML element with the same tag name as that of the token, then this is a parse error.
            if current_node(parser).local_name != strings.to_string(tag.name) do report_parse_error(.ErrorInTreeConstruction)
            // Pop elements from the stack of open elements until an HTML element with the same tag name as the token has been popped from the stack.
            for current_node(parser).local_name != strings.to_string(tag.name) {
                pop(&parser.stack_of_open_elements)
            }
            pop(&parser.stack_of_open_elements)
        }
    }
    else if is_end_tag_named_one_of(token, "sarcasm") { // An end tag whose tag name is "sarcasm"
        assert(false, "TODO")
        // Take a deep breath, then act as described in the "any other end tag" entry below.
    }
    else if is_start_tag_named_one_of(token, "a") { // A start tag whose tag name is "a"
        tag := token.(Tag_Token)
        // @TODO: If the list of active formatting elements contains an a element between the end of the list and the last marker on the list (or the start of the list if there is no marker on the list), then this is a parse error; run the adoption agency algorithm for the token, then remove that element from the list of active formatting elements and the stack of open elements if the adoption agency algorithm didn't already remove it (it might not have if the element is not in table scope).
        // @TODO: Reconstruct the active formatting elements, if any.
        // Insert an HTML element for the token. Push onto the list of active formatting elements that element.
        element := insert_html_element(parser, tag)
        append(&parser.list_of_active_formatting_elements, element)
    }
    else if is_start_tag_named_one_of(token, "b", "big", "code", "em", "font", "i", "s", "small", "strike", "strong", "tt", "u") {
    //A start tag whose tag name is one of: "b", "big", "code", "em", "font", "i", "s", "small", "strike", "strong", "tt", "u"
        tag := token.(Tag_Token)
        // @TODO: Reconstruct the active formatting elements, if any.
        // Insert an HTML element for the token. Push onto the list of active formatting elements that element.
        element := insert_html_element(parser, tag)
        append(&parser.list_of_active_formatting_elements, element)
    }
    else if is_start_tag_named_one_of(token, "nobr") { // A start tag whose tag name is "nobr"
        tag := token.(Tag_Token)
        // @TODO: Reconstruct the active formatting elements, if any.
        // @TODO: If the stack of open elements has a nobr element in scope, then this is a parse error; run the adoption agency algorithm for the token, then once again reconstruct the active formatting elements, if any.
        // Insert an HTML element for the token. Push onto the list of active formatting elements that element.
        element := insert_html_element(parser, tag)
        append(&parser.list_of_active_formatting_elements, element)
    }
    else if is_end_tag_named_one_of(token, "a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small", "strike", "strong", "tt", "u") {
    // An end tag whose tag name is one of: "a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small", "strike", "strong", "tt", "u"
        tag := token.(Tag_Token)
        // Run the adoption agency algorithm for the token.
        do_adoption_agency(parser, tag)
    }
    else if is_start_tag_named_one_of(token, "applet", "marquee", "object") { // A start tag whose tag name is one of: "applet", "marquee", "object"
        tag := token.(Tag_Token)
        // @TODO: Reconstruct the active formatting elements, if any.
        // Insert an HTML element for the token.
        insert_html_element(parser, tag)
        // Insert a marker at the end of the list of active formatting elements.
        append(&parser.list_of_active_formatting_elements, Marker{})
        // Set the frameset-ok flag to "not ok".
        parser.frameset_ok = false
    }
    else if is_end_tag_named_one_of(token, "applet", "marquee", "object") { // An end tag whose tag name is one of: "applet", "marquee", "object"
        tag := token.(Tag_Token)
        // @TODO: If the stack of open elements does not have an element in scope that is an HTML element with the same tag name as that of the token, then this is a parse error; ignore the token.
        if false {}
        else { // Otherwise, run these steps:
            // Generate implied end tags.
            generate_implied_end_tags(parser)
            // If the current node is not an HTML element with the same tag name as that of the token, then this is a parse error.
            if current_node(parser).local_name != strings.to_string(tag.name) do report_parse_error(.ErrorInTreeConstruction)
            // Pop elements from the stack of open elements until an HTML element with the same tag name as the token has been popped from the stack.
            for current_node(parser).local_name != strings.to_string(tag.name) {
                pop(&parser.stack_of_open_elements)
            }
            pop(&parser.stack_of_open_elements)
            // @TODO: Clear the list of active formatting elements up to the last marker.
        }
    }
    else if is_start_tag_named_one_of(token, "table") { // A start tag whose tag name is "table"
        tag := token.(Tag_Token)
        // @TODO: If the Document is not set to quirks mode, and the stack of open elements has a p element in button scope, then close a p element.
        // Insert an HTML element for the token.
        insert_html_element(parser, tag)
        // Set the frameset-ok flag to "not ok".
        parser.frameset_ok = false
        // Switch the insertion mode to "in table".
        parser.insertion_mode = .InTable
    }
    /*
    An end tag whose tag name is "br"

        Parse error. Drop the attributes from the token, and act as described in the next entry; i.e. act as if this was a "br" start tag token with no attributes, rather than the end tag token that it actually is.
    A start tag whose tag name is one of: "area", "br", "embed", "img", "keygen", "wbr"

        Reconstruct the active formatting elements, if any.

        Insert an HTML element for the token. Immediately pop the current node off the stack of open elements.

        Acknowledge the token's self-closing flag, if it is set.

        Set the frameset-ok flag to "not ok".
    A start tag whose tag name is "input"

        Reconstruct the active formatting elements, if any.

        Insert an HTML element for the token. Immediately pop the current node off the stack of open elements.

        Acknowledge the token's self-closing flag, if it is set.

        If the token does not have an attribute with the name "type", or if it does, but that attribute's value is not an ASCII case-insensitive match for the string "hidden", then: set the frameset-ok flag to "not ok".
    A start tag whose tag name is one of: "param", "source", "track"

        Insert an HTML element for the token. Immediately pop the current node off the stack of open elements.

        Acknowledge the token's self-closing flag, if it is set.
    A start tag whose tag name is "hr"

        If the stack of open elements has a p element in button scope, then close a p element.

        Insert an HTML element for the token. Immediately pop the current node off the stack of open elements.

        Acknowledge the token's self-closing flag, if it is set.

        Set the frameset-ok flag to "not ok".
    A start tag whose tag name is "image"

        Parse error. Change the token's tag name to "img" and reprocess it. (Don't ask.)
    A start tag whose tag name is "textarea"

        Run these steps:

            Insert an HTML element for the token.

            If the next token is a U+000A LINE FEED (LF) character token, then ignore that token and move on to the next one. (Newlines at the start of textarea elements are ignored as an authoring convenience.)

            Switch the tokenizer to the RCDATA state.

            Let the original insertion mode be the current insertion mode.

            Set the frameset-ok flag to "not ok".

            Switch the insertion mode to "text".

    A start tag whose tag name is "xmp"

        If the stack of open elements has a p element in button scope, then close a p element.

        Reconstruct the active formatting elements, if any.

        Set the frameset-ok flag to "not ok".

        Follow the generic raw text element parsing algorithm.
    A start tag whose tag name is "iframe"

        Set the frameset-ok flag to "not ok".

        Follow the generic raw text element parsing algorithm.
    A start tag whose tag name is "noembed"
    A start tag whose tag name is "noscript", if the scripting flag is enabled

        Follow the generic raw text element parsing algorithm.
    A start tag whose tag name is "select"

        Reconstruct the active formatting elements, if any.

        Insert an HTML element for the token.

        Set the frameset-ok flag to "not ok".

        If the insertion mode is one of "in table", "in caption", "in table body", "in row", or "in cell", then switch the insertion mode to "in select in table". Otherwise, switch the insertion mode to "in select".
    A start tag whose tag name is one of: "optgroup", "option"

        If the current node is an option element, then pop the current node off the stack of open elements.

        Reconstruct the active formatting elements, if any.

        Insert an HTML element for the token.
    A start tag whose tag name is one of: "rb", "rtc"

        If the stack of open elements has a ruby element in scope, then generate implied end tags. If the current node is not now a ruby element, this is a parse error.

        Insert an HTML element for the token.
    A start tag whose tag name is one of: "rp", "rt"

        If the stack of open elements has a ruby element in scope, then generate implied end tags, except for rtc elements. If the current node is not now a rtc element or a ruby element, this is a parse error.

        Insert an HTML element for the token.
    A start tag whose tag name is "math"

        Reconstruct the active formatting elements, if any.

        Adjust MathML attributes for the token. (This fixes the case of MathML attributes that are not all lowercase.)

        Adjust foreign attributes for the token. (This fixes the use of namespaced attributes, in particular XLink.)

        Insert a foreign element for the token, with MathML namespace and false.

        If the token has its self-closing flag set, pop the current node off the stack of open elements and acknowledge the token's self-closing flag.
    A start tag whose tag name is "svg"

        Reconstruct the active formatting elements, if any.

        Adjust SVG attributes for the token. (This fixes the case of SVG attributes that are not all lowercase.)

        Adjust foreign attributes for the token. (This fixes the use of namespaced attributes, in particular XLink in SVG.)

        Insert a foreign element for the token, with SVG namespace and false.

        If the token has its self-closing flag set, pop the current node off the stack of open elements and acknowledge the token's self-closing flag.
    A start tag whose tag name is one of: "caption", "col", "colgroup", "frame", "head", "tbody", "td", "tfoot", "th", "thead", "tr"

        Parse error. Ignore the token.
    Any other start tag

        Reconstruct the active formatting elements, if any.

        Insert an HTML element for the token.

        This element will be an ordinary element. With one exception: if the scripting flag is disabled, it can also be a noscript element.
    Any other end tag

        Run these steps:

            Initialize node to be the current node (the bottommost node of the stack).

            Loop: If node is an HTML element with the same tag name as the token, then:

                Generate implied end tags, except for HTML elements with the same tag name as the token.

                If node is not the current node, then this is a parse error.

                Pop all the nodes from the current node up to node, including node, then stop these steps.

            Otherwise, if node is in the special category, then this is a parse error; ignore the token, and return.

            Set node to the previous entry in the stack of open elements.

            Return to the step labeled loop.
        */
    return true
}

handle_in_body_any_other_end_tag :: proc(parser: ^Html_Parser, token: Tag_Token) {
    // Initialize node to be the current node (the bottommost node of the stack).
    node, node_index := current_node_with_index(parser)
    // Loop: If node is an HTML element with the same tag name as the token, then:
    for {
        if node.local_name == strings.to_string(token.name) {
            // Generate implied end tags, except for HTML elements with the same tag name as the token.
            generate_implied_end_tags(parser, {node.type})
            // If node is not the current node, then this is a parse error.
            if node != current_node(parser) do report_parse_error(.ErrorInTreeConstruction)
            // Pop all the nodes from the current node up to node, including node, then stop these steps.
            for node != current_node(parser) {
                pop(&parser.stack_of_open_elements)
            }
            pop(&parser.stack_of_open_elements)
            break
        }
        else { // Otherwise, if node is in the special category, then this is a parse error; ignore the token, and return.
            if (node.type in special_category) {
                report_parse_error(.ErrorInTreeConstruction)
                return
            }
        }

        // Set node to the previous entry in the stack of open elements.
        node, node_index = set_to_previous_stack_entry(parser, node_index)
        // Return to the step labeled loop.
    }
}

// https://dom.spec.whatwg.org/#concept-create-element
// To create an element, given a document, localName, namespace, and optional prefix, is, and synchronous custom elements flag, run these steps:
create_element :: proc(document: ^Document, local_name: string, namespace: string, prefix := "", is := "", synchronous_custom_elements := false) -> ^Element {
    // If prefix was not given, let prefix be null.
    // If is was not given, let is be null.
    // Let result be null.
    result: ^Element = nil

    if false {
    /* @TODO
    Let definition be the result of looking up a custom element definition given document, namespace, localName, and is.
    If definition is non-null, and definition’s name is not equal to its local name (i.e., definition represents a customized built-in element), then:
        Let interface be the element interface for localName and the HTML namespace.
        Set result to a new element that implements interface, with no attributes, namespace set to the HTML namespace, namespace prefix set to prefix, local name set to localName, custom element state set to "undefined", custom element definition set to null, is value set to is, and node document set to document.
        If the synchronous custom elements flag is set, then run this step while catching any exceptions:
            Upgrade element using definition.
        If this step threw an exception, then:
            Report the exception.
            Set result’s custom element state to "failed".
        Otherwise, enqueue a custom element upgrade reaction given result and definition.
    Otherwise, if definition is non-null, then:
        If the synchronous custom elements flag is set, then run these steps while catching any exceptions:
            Let C be definition’s constructor.
            Set result to the result of constructing C, with no arguments.
            Assert: result’s custom element state and custom element definition are initialized.
            Assert: result’s namespace is the HTML namespace.
            IDL enforces that result is an HTMLElement object, which all use the HTML namespace.
            If result’s attribute list is not empty, then throw a "NotSupportedError" DOMException.
            If result has children, then throw a "NotSupportedError" DOMException.
            If result’s parent is not null, then throw a "NotSupportedError" DOMException.
            If result’s node document is not document, then throw a "NotSupportedError" DOMException.
            If result’s local name is not equal to localName, then throw a "NotSupportedError" DOMException.
            Set result’s namespace prefix to prefix.
            Set result’s is value to null.
        If any of these steps threw an exception, then:
            Report the exception.
            Set result to a new element that implements the HTMLUnknownElement interface, with no attributes, namespace set to the HTML namespace, namespace prefix set to prefix, local name set to localName, custom element state set to "failed", custom element definition set to null, is value set to null, and node document set to document.
        Otherwise:
            Set result to a new element that implements the HTMLElement interface, with no attributes, namespace set to the HTML namespace, namespace prefix set to prefix, local name set to localName, custom element state set to "undefined", custom element definition set to null, is value set to null, and node document set to document.
            Enqueue a custom element upgrade reaction given result and definition.
    */
    }
    else { // Otherwise:
        // @TODO: Let interface be the element interface for localName and namespace.
        // Set result to a new element that implements interface, with no attributes, namespace set to namespace, namespace prefix set to prefix, local name set
        // to localName, custom element state set to "uncustomized", custom element definition set to null, is value set to is, and node document set to document.
        result = make_node(Element, document)
        result.namespace = namespace
        result.prefix = prefix
        result.local_name = local_name
        /* @TODO
        result.custom_element_state = "uncustomized"
        result.custom_element_definition = nil
        result.is_value = is
        */
        result.document = document

        // @TODO: If namespace is the HTML namespace, and either localName is a valid custom element name or is is non-null, then set result’s custom element state to "undefined".
    }
    // Return result.
    return result
}

// https://html.spec.whatwg.org/#create-an-element-for-the-token
// When the steps below require the UA to create an element for a token in a particular given namespace and with a particular intended parent, the UA must run the following steps:
create_element_for_token :: proc(token: Tag_Token, given_namespace: string, intended_parent: ^Node) -> ^Element {
    // @TODO: If the active speculative HTML parser is not null, then return the result of creating a speculative mock element given given namespace, the tag name of the given token, and the attributes of the given token.
    // @TODO: Otherwise, optionally create a speculative mock element given given namespace, the tag name of the given token, and the attributes of the given token.
    // The result is not used. This step allows for a speculative fetch to be initiated from non-speculative parsing. The fetch is still speculative at this point,
    // because, for example, by the time the element is inserted, intended parent might have been removed from the document.

    // Let document be intended parent's node document.
    document := intended_parent.document
    // Let local name be the tag name of the token.
    local_name := strings.to_string(token.name)
    // @TODO: Let is be the value of the "is" attribute in the given token, if such an attribute exists, or null otherwise.
    // @TODO: Let definition be the result of looking up a custom element definition given document, given namespace, local name, and is.
    // @TODO: If definition is non-null and the parser was not created as part of the HTML fragment parsing algorithm, then let will execute script be true. Otherwise, let it be false.
    /* @TODO
    If will execute script is true, then:
        Increment document's throw-on-dynamic-markup-insertion counter.
        If the JavaScript execution context stack is empty, then perform a microtask checkpoint.
        Push a new element queue onto document's relevant agent's custom element reactions stack.
    */
    // Let element be the result of creating an element given document, localName, given namespace, null, and is. If will execute script is true, set the synchronous custom elements flag; otherwise, leave it unset.
    //@TODO: Handle "is"
    //@TODO: Handle synchronous custom elements flag
    element := create_element(document, local_name, given_namespace)
    set_element_type_from_tag_name(element, strings.to_string(token.name))
    // @TODO: This will cause custom element constructors to run, if will execute script is true. However, since we incremented the throw-on-dynamic-markup-insertion counter, this cannot cause new characters to be inserted into the tokenizer, or the document to be blown away.
    // Append each attribute in the given token to element.
    for attr in token.attributes {
        dom_attr := make_node(Attr, document) 
        dom_attr.namespace_uri = given_namespace
        dom_attr.name = strings.to_string(attr.name)
        dom_attr.value = strings.to_string(attr.value)
        append_child(element, dom_attr)
    }
    //@TODO: This can enqueue a custom element callback reaction for the attributeChangedCallback, which might run immediately (in the next step).
    //@NOTE: Even though the is attribute governs the creation of a customized built-in element, it is not present during the execution of the relevant custom
    // element constructor; it is appended in this step, along with all other attributes.
    /* TODO
    If will execute script is true, then:
        Let queue be the result of popping from document's relevant agent's custom element reactions stack. (This will be the same element queue as was pushed above.)
        Invoke custom element reactions in queue.
        Decrement document's throw-on-dynamic-markup-insertion counter.
    */
    // @TODO: If element has an xmlns attribute in the XMLNS namespace whose value is not exactly the same as the element's namespace, that is a parse error. Similarly,
    // if element has an xmlns:xlink attribute in the XMLNS namespace whose value is not the XLink Namespace, that is a parse error.
    // @TODO: If element is a resettable element, invoke its reset algorithm. (This initializes the element's value and checkedness based on the element's attributes.)
    // @TODO: If element is a form-associated element and not a form-associated custom element, the form element pointer is not null, there is no template element on the
    // stack of open elements, element is either not listed or doesn't have a form attribute, and the intended parent is in the same tree as the element pointed to by the
    // form element pointer, then associate element with the form element pointed to by the form element pointer and set element's parser inserted flag.

    // Keep track of the token that created this element. This is needed for the adoption agency algorithm
    element.generating_token = token
    // Return element.   
    return element
}

// https://html.spec.whatwg.org/#parsing-main-incdata
// When the user agent is to apply the rules for the "text" insertion mode, the user agent must handle the token as follows:
handle_text_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    _, is_eof := token.(Eof_Token)
    if is_character { // A character token
        // Insert the token's character.
        insert_character(parser, document, character)
    }
    else if is_eof { // An end-of-file token
        // Parse error.
        report_parse_error(.ErrorInTreeConstruction)
        // @TODO: If the current node is a script element, then set its already started to true.
        // Pop the current node off the stack of open elements.
        pop(&parser.stack_of_open_elements)
        // Switch the insertion mode to the original insertion mode and reprocess the token.
        parser.insertion_mode = parser.original_insertion_mode
        parser.should_reprocess = true
    }
    else if is_end_tag_named_one_of(token, "script") { // An end tag whose tag name is "script"
        // @TODO: If the active speculative HTML parser is null and the JavaScript execution context stack is empty, then perform a microtask checkpoint.
        // Let script be the current node (which will be a script element).
        script := current_node(parser)
        // Pop the current node off the stack of open elements.
        pop(&parser.stack_of_open_elements)
        // Switch the insertion mode to the original insertion mode.
        parser.insertion_mode = parser.original_insertion_mode
        assert(false, "TODO") 
        /*
        Let the old insertion point have the same value as the current insertion point. Let the insertion point be just before the next input character.
        Increment the parser's script nesting level by one.
        If the active speculative HTML parser is null, then prepare the script element script. This might cause some script to execute, which might cause new characters to be inserted into the tokenizer, and might cause the tokenizer to output more tokens, resulting in a reentrant invocation of the parser.
        Decrement the parser's script nesting level by one. If the parser's script nesting level is zero, then set the parser pause flag to false.
        Let the insertion point have the value of the old insertion point. (In other words, restore the insertion point to its previous value. This value might be the "undefined" value.)
        At this stage, if the pending parsing-blocking script is not null, then:
        If the script nesting level is not zero:
            Set the parser pause flag to true, and abort the processing of any nested invocations of the tokenizer, yielding control back to the caller. (Tokenization will resume when the caller returns to the "outer" tree construction stage.)
            The tree construction stage of this particular parser is being called reentrantly, say from a call to document.write().
        Otherwise:
            While the pending parsing-blocking script is not null:
                Let the script be the pending parsing-blocking script.
                Set the pending parsing-blocking script to null.
                Start the speculative HTML parser for this instance of the HTML parser.
                Block the tokenizer for this instance of the HTML parser, such that the event loop will not run tasks that invoke the tokenizer.
                If the parser's Document has a style sheet that is blocking scripts or the script's ready to be parser-executed is false: spin the event loop until the parser's Document has no style sheet that is blocking scripts and the script's ready to be parser-executed becomes true.
                If this parser has been aborted in the meantime, return.
                This could happen if, e.g., while the spin the event loop algorithm is running, the Document gets destroyed, or the document.open() method gets invoked on the Document.
                Stop the speculative HTML parser for this instance of the HTML parser.
                Unblock the tokenizer for this instance of the HTML parser, such that tasks that invoke the tokenizer can again be run.
                Let the insertion point be just before the next input character.
                Increment the parser's script nesting level by one (it should be zero before this step, so this sets it to one).
                Execute the script element the script.
                Decrement the parser's script nesting level by one. If the parser's script nesting level is zero (which it always should be at this point), then set the parser pause flag to false.
                Let the insertion point be undefined again.
        */
    }
    else if is_end_tag(token) { // Any other end tag
        // Pop the current node off the stack of open elements.
        pop(&parser.stack_of_open_elements)
        // Switch the insertion mode to the original insertion mode.
        parser.insertion_mode = parser.original_insertion_mode
    }    return true
}

// https://html.spec.whatwg.org/#parsing-main-intable
// When the user agent is to apply the rules for the "in table" insertion mode, the user agent must handle the token as follows:
handle_in_table_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    _, is_eof := token.(Eof_Token)

    if is_character && (current_node(parser).type in bit_set[Element_Type]{.Table, .TBody, .Template, .TFoot, .THead, .Tr}) {
    // A character token, if the current node is table, tbody, template, tfoot, thead, or tr element
        // Let the pending table character tokens be an empty list of tokens.
        clear(&parser.pending_table_character_tokens)
        // Let the original insertion mode be the current insertion mode.
        parser.original_insertion_mode = parser.insertion_mode
        // Switch the insertion mode to "in table text" and reprocess the token.
        parser.insertion_mode = .InTableText
        parser.should_reprocess = true
    }
    else if is_comment { // A comment token
        // Insert a comment.
        insert_comment(parser, comment)
    }
    else if is_doctype { // A DOCTYPE token
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else if is_start_tag_named_one_of(token, "caption") { // A start tag whose tag name is "caption"
        tag := token.(Tag_Token)
        // Clear the stack back to a table context. (See below.)
        clear_stack_to_table_context(parser)
        // Insert a marker at the end of the list of active formatting elements.
        append(&parser.list_of_active_formatting_elements, Marker{})
        // Insert an HTML element for the token, then switch the insertion mode to "in caption".
        insert_html_element(parser, tag)
        parser.insertion_mode = .InCaption
    }
    else if is_start_tag_named_one_of(token, "colgroup") { // A start tag whose tag name is "colgroup"
        tag := token.(Tag_Token)
        // Clear the stack back to a table context. (See below.)
        clear_stack_to_table_context(parser)
        // Insert an HTML element for the token, then switch the insertion mode to "in column group".
        insert_html_element(parser, tag)
        parser.insertion_mode = .InColumnGroup
    }
    else if is_start_tag_named_one_of(token, "col") { // A start tag whose tag name is "col"
        // Clear the stack back to a table context. (See below.)
        clear_stack_to_table_context(parser)
        // Insert an HTML element for a "colgroup" start tag token with no attributes, then switch the insertion mode to "in column group".
        colgroup_no_attrs := Tag_Token{is_start=true}
        fmt.sbprint(&colgroup_no_attrs.name, "colgroup")
        insert_html_element(parser, colgroup_no_attrs)
        // Reprocess the current token.
        parser.should_reprocess = true
    }
    else if is_start_tag_named_one_of(token, "tbody", "tfoot", "thead") { // A start tag whose tag name is one of: "tbody", "tfoot", "thead"
        tag := token.(Tag_Token)
        // Clear the stack back to a table context. (See below.)
        clear_stack_to_table_context(parser)
        // Insert an HTML element for the token, then switch the insertion mode to "in table body".
        insert_html_element(parser, tag)
        parser.insertion_mode = .InTableBody
    }
    else if is_start_tag_named_one_of(token, "td", "th", "tr") { // A start tag whose tag name is one of: "td", "th", "tr"
        // Clear the stack back to a table context. (See below.)
        clear_stack_to_table_context(parser)
        // Insert an HTML element for a "tbody" start tag token with no attributes, then switch the insertion mode to "in table body".
        tbody_no_attrs := Tag_Token{is_start=true}
        fmt.sbprint(&tbody_no_attrs.name, "tbody")
        insert_html_element(parser, tbody_no_attrs)
        parser.insertion_mode = .InTableBody
        // Reprocess the current token.
        parser.should_reprocess = true
    }
    else if is_start_tag_named_one_of(token, "table") { // A start tag whose tag name is "table"
        // Parse error.
        report_parse_error(.ErrorInTreeConstruction)
        // If the stack of open elements does not have a table element in table scope, ignore the token.
        if !stack_has_element_in_table_scope(parser, .Table) {
            // Ignore the token
        }
        else { // Otherwise:
            // Pop elements from this stack until a table element has been popped from the stack.
            for current_node(parser).type != .Table {
                pop(&parser.stack_of_open_elements)
            }
            pop(&parser.stack_of_open_elements)
            // Reset the insertion mode appropriately.
            reset_insertion_mode_appropriately(parser)
            // Reprocess the token.
            parser.should_reprocess = true
        }
    }
    else if is_end_tag_named_one_of(token, "table") { // An end tag whose tag name is "table"
        // If the stack of open elements does not have a table element in table scope, this is a parse error; ignore the token.
        if !stack_has_element_in_table_scope(parser, .Table) {
            report_parse_error(.ErrorInTreeConstruction)
        }
        else { // Otherwise:
            // Pop elements from this stack until a table element has been popped from the stack.
            for current_node(parser).type != .Table {
                pop(&parser.stack_of_open_elements)
            }
            pop(&parser.stack_of_open_elements)
            // Reset the insertion mode appropriately.
            reset_insertion_mode_appropriately(parser)
        }
    }
    else if is_end_tag_named_one_of(token, "body", "caption", "col", "colgroup", "html", "tbody", "td", "tfoot", "th", "thead", "tr") {
    // An end tag whose tag name is one of: "body", "caption", "col", "colgroup", "html", "tbody", "td", "tfoot", "th", "thead", "tr"
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else if is_start_tag_named_one_of(token, "style", "script", "template") || is_end_tag_named_one_of(token, "template") { 
    // A start tag whose tag name is one of: "style", "script", "template"
    // An end tag whose tag name is "template"
        // Process the token using the rules for the "in head" insertion mode.
        handle_in_head_insertion_mode(parser, document, token)
    }
    else if is_start_tag_named_one_of(token, "input") { // A start tag whose tag name is "input"
        tag := token.(Tag_Token)
        // @TODO: If the token does not have an attribute with the name "type", or if it does, but that attribute's value is not an ASCII case-insensitive match for the string
        // "hidden", then: act as described in the "anything else" entry below.
        if false {}
        else { // Otherwise:
            // Parse error.
            report_parse_error(.ErrorInTreeConstruction)
            // Insert an HTML element for the token.
            insert_html_element(parser, tag)
            // Pop that input element off the stack of open elements.
            pop(&parser.stack_of_open_elements)
            // @TODO: Acknowledge the token's self-closing flag, if it is set.
        }
    }
    else if is_start_tag_named_one_of(token, "form") { // A start tag whose tag name is "form"
        tag := token.(Tag_Token)
        // Parse error.
        report_parse_error(.ErrorInTreeConstruction)
        // If there is a template element on the stack of open elements, or if the form element pointer is not null, ignore the token.
        if stack_has_element_of_type(parser, .Template) || parser.form_element_pointer != nil {
            // Ignore the token
        }
        else { // Otherwise:
            // Insert an HTML element for the token, and set the form element pointer to point to the element created.
            insert_html_element(parser, tag)
            // Pop that form element off the stack of open elements.
            pop(&parser.stack_of_open_elements)
        }
    }
    else if is_eof { // An end-of-file token
        // Process the token using the rules for the "in body" insertion mode.
        handle_in_body_insertion_mode(parser, document, token)
    }
    else { // Anything else
        // Parse error. Enable foster parenting, process the token using the rules for the "in body" insertion mode, and then disable foster parenting.
        parser.foster_parenting = true
        handle_in_body_insertion_mode(parser, document, token)
        parser.foster_parenting = false
    }

    return true
}

// https://html.spec.whatwg.org/#parsing-main-intabletext
// When the user agent is to apply the rules for the "in table text" insertion mode, the user agent must handle the token as follows:
handle_in_table_text_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    _, is_eof := token.(Eof_Token)

    if is_character && character.data == '\u0000' { // A character token that is U+0000 NULL
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else if is_character { // Any other character token
        // Append the character token to the pending table character tokens list.
        append(&parser.pending_table_character_tokens, character)
    }
    else { // Anything else
        // If any of the tokens in the pending table character tokens list are character tokens that are not ASCII whitespace, then this is a parse error:
        // reprocess the character tokens in the pending table character tokens list using the rules given in the "anything else" entry in the "in table" insertion mode.
        for char in parser.pending_table_character_tokens {
            if !codepoints.is_ascii_whitespace(char.data) {
                report_parse_error(.ErrorInTreeConstruction)
                parser.foster_parenting = true
                handle_in_body_insertion_mode(parser, document, token)
                parser.foster_parenting = false
                return
            }
        }

        // Otherwise, insert the characters given by the pending table character tokens list.
        for char in parser.pending_table_character_tokens {
            insert_character(parser, document, char)
        }

        // Switch the insertion mode to the original insertion mode and reprocess the token.
        parser.insertion_mode = parser.original_insertion_mode
        parser.should_reprocess = true
    }

    return true
}

// https://html.spec.whatwg.org/#parsing-main-intbody
// When the user agent is to apply the rules for the "in table body" insertion mode, the user agent must handle the token as follows:
handle_in_table_body_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    _, is_eof := token.(Eof_Token)

    if is_start_tag_named_one_of(token, "tr") { // A start tag whose tag name is "tr"
        tag := token.(Tag_Token)
        // Clear the stack back to a table body context. (See below.)
        clear_stack_to_table_body_context(parser)
        // Insert an HTML element for the token, then switch the insertion mode to "in row".
        insert_html_element(parser, tag)
        parser.insertion_mode = .InRow
    }
    else if is_start_tag_named_one_of(token, "th", "td") { // A start tag whose tag name is one of: "th", "td"
        // Parse error.
        report_parse_error(.ErrorInTreeConstruction)
        // Clear the stack back to a table body context. (See below.)
        clear_stack_to_table_body_context(parser)
        // Insert an HTML element for a "tr" start tag token with no attributes, then switch the insertion mode to "in row".
        tr_no_attr := Tag_Token{is_start=true}
        fmt.sbprint(&tr_no_attr.name, "tr")
        insert_html_element(parser, tr_no_attr)
        parser.insertion_mode = .InRow
        // Reprocess the current token.
        parser.should_reprocess = true
    }
    else if is_end_tag_named_one_of(token, "tbody", "tfoot", "thead") { // An end tag whose tag name is one of: "tbody", "tfoot", "thead"
        // If the stack of open elements does not have an element in table scope that is an HTML element with the same tag name as the token, this is a
        // parse error; ignore the token.
        if !stack_has_element_in_table_scope(parser, get_element_type_from_tag_name(strings.to_string(token.(Tag_Token).name))) {
            report_parse_error(.ErrorInTreeConstruction)
        }
        else { // Otherwise:
            // Clear the stack back to a table body context. (See below.)
            clear_stack_to_table_body_context(parser)
            // Pop the current node from the stack of open elements. Switch the insertion mode to "in table".
            pop(&parser.stack_of_open_elements)
            parser.insertion_mode = .InTable
        }
    }
    else if is_start_tag_named_one_of(token, "caption", "col", "colgroup", "tbody", "tfoot", "thead") || is_end_tag_named_one_of(token, "table") {
    // A start tag whose tag name is one of: "caption", "col", "colgroup", "tbody", "tfoot", "thead"
    // An end tag whose tag name is "table"
        // If the stack of open elements does not have a tbody, thead, or tfoot element in table scope, this is a parse error; ignore the token.
        if !stack_has_element_in_table_scope(parser, .TBody) && \
            !stack_has_element_in_table_scope(parser, .THead) && \
            !stack_has_element_in_table_scope(parser, .TFoot) {
            report_parse_error(.ErrorInTreeConstruction)
        } 
        else { // Otherwise:
            // Clear the stack back to a table body context. (See below.)
            clear_stack_to_table_body_context(parser)
            // Pop the current node from the stack of open elements. Switch the insertion mode to "in table".
            pop(&parser.stack_of_open_elements)
            parser.insertion_mode = .InTable
            // Reprocess the token.
            parser.should_reprocess = true
        }
    }
    else if is_end_tag_named_one_of(token, "body", "caption", "col", "colgroup", "html", "td", "th", "tr") {
    // An end tag whose tag name is one of: "body", "caption", "col", "colgroup", "html", "td", "th", "tr"
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else { // Anything else
        // Process the token using the rules for the "in table" insertion mode.
        handle_in_table_insertion_mode(parser, document, token)
    }

    return true
}

// https://html.spec.whatwg.org/#parsing-main-intr
// When the user agent is to apply the rules for the "in row" insertion mode, the user agent must handle the token as follows:
handle_in_row_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    _, is_eof := token.(Eof_Token)

    if is_start_tag_named_one_of(token, "th", "td") { // A start tag whose tag name is one of: "th", "td"
        tag := token.(Tag_Token)
        // Clear the stack back to a table row context. (See below.)
        clear_stack_to_table_row_context(parser)
        // Insert an HTML element for the token, then switch the insertion mode to "in cell".
        insert_html_element(parser, tag)
        parser.insertion_mode = .InCell
        // Insert a marker at the end of the list of active formatting elements.
        append(&parser.list_of_active_formatting_elements, Marker{})
    }
    else if is_end_tag_named_one_of(token, "tr") { // An end tag whose tag name is "tr"
        // If the stack of open elements does not have a tr element in table scope, this is a parse error; ignore the token.
        if !stack_has_element_in_table_scope(parser, .Tr) {
            report_parse_error(.ErrorInTreeConstruction)
        }
        else { // Otherwise:
            // Clear the stack back to a table row context. (See below.)
            clear_stack_to_table_row_context(parser)
            // Pop the current node (which will be a tr element) from the stack of open elements. Switch the insertion mode to "in table body".
            pop(&parser.stack_of_open_elements)
            parser.insertion_mode = .InTableBody
        }
    }
    else if is_start_tag_named_one_of(token, "caption", "col", "colgroup", "tbody", "tfoot", "thead", "tr") || is_end_tag_named_one_of(token, "table") {
    // A start tag whose tag name is one of: "caption", "col", "colgroup", "tbody", "tfoot", "thead", "tr"
    // An end tag whose tag name is "table"
        // If the stack of open elements does not have a tr element in table scope, this is a parse error; ignore the token.
        if !stack_has_element_in_table_scope(parser, .Tr) {
            report_parse_error(.ErrorInTreeConstruction)
        }
        else { // Otherwise:
            // Clear the stack back to a table row context. (See below.)
            clear_stack_to_table_row_context(parser)
            // Pop the current node (which will be a tr element) from the stack of open elements. Switch the insertion mode to "in table body".
            pop(&parser.stack_of_open_elements)
            parser.insertion_mode = .InTableBody
            // Reprocess the token.
            parser.should_reprocess = true
        }
    }
    else if is_end_tag_named_one_of(token, "tbody", "tfoot", "thead") { //An end tag whose tag name is one of: "tbody", "tfoot", "thead"
        // If the stack of open elements does not have an element in table scope that is an HTML element with the same tag name as the token, this is a parse error; ignore the token.
        if !stack_has_element_in_table_scope(parser, get_element_type_from_tag_name(strings.to_string(token.(Tag_Token).name))) {
            report_parse_error(.ErrorInTreeConstruction)
        }
        else if !stack_has_element_in_table_scope(parser, .Tr) {
            // If the stack of open elements does not have a tr element in table scope, ignore the token.
        }
        else { // Otherwise:
            // Clear the stack back to a table row context. (See below.)
            clear_stack_to_table_row_context(parser)
            // Pop the current node (which will be a tr element) from the stack of open elements. Switch the insertion mode to "in table body".
            pop(&parser.stack_of_open_elements)
            parser.insertion_mode = .InTableBody
            // Reprocess the token.
            parser.should_reprocess = true
        }
    }
    else if is_end_tag_named_one_of(token, "body", "caption", "col", "colgroup", "html", "td", "th") {
    // An end tag whose tag name is one of: "body", "caption", "col", "colgroup", "html", "td", "th"
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else { // Anything else
        // Process the token using the rules for the "in table" insertion mode.
        handle_in_table_insertion_mode(parser, document, token)
    }

    return true
}

// https://html.spec.whatwg.org/#parsing-main-intd
// When the user agent is to apply the rules for the "in cell" insertion mode, the user agent must handle the token as follows:
handle_in_cell_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    _, is_eof := token.(Eof_Token)

    if is_end_tag_named_one_of(token, "td", "th") { // An end tag whose tag name is one of: "td", "th"
        tag := token.(Tag_Token)
        // If the stack of open elements does not have an element in table scope that is an HTML element with the same tag name as that of the token, then this is a parse error; ignore the token.
        if !stack_has_element_in_table_scope(parser, get_element_type_from_tag_name(strings.to_string(token.(Tag_Token).name))) {
            report_parse_error(.ErrorInTreeConstruction)
        }
        else { // Otherwise:
            // Generate implied end tags.
            generate_implied_end_tags(parser)
            // Now, if the current node is not an HTML element with the same tag name as the token, then this is a parse error.
            if current_node(parser).local_name != strings.to_string(tag.name) do report_parse_error(.ErrorInTreeConstruction)
            // Pop elements from the stack of open elements until an HTML element with the same tag name as the token has been popped from the stack.
            for current_node(parser).local_name != strings.to_string(tag.name) {
                pop(&parser.stack_of_open_elements)
            }
            pop(&parser.stack_of_open_elements)
            // Clear the list of active formatting elements up to the last marker.
            clear_list_of_active_formatting_elements_up_to_marker(parser)
            // Switch the insertion mode to "in row".
            parser.insertion_mode = .InRow
        }
    }
    else if is_start_tag_named_one_of(token, "caption", "col", "colgroup", "tbody", "td", "tfoot", "th", "thead", "tr") {
    // A start tag whose tag name is one of: "caption", "col", "colgroup", "tbody", "td", "tfoot", "th", "thead", "tr"
        // Assert: The stack of open elements has a td or th element in table scope.
        assert(stack_has_element_in_table_scope(parser, .Td) || stack_has_element_in_table_scope(parser, .Th))
        // Close the cell (see below) and reprocess the token.
        close_cell(parser)
    }
    else if is_end_tag_named_one_of(token, "body", "caption", "col", "colgroup", "html") {
    // An end tag whose tag name is one of: "body", "caption", "col", "colgroup", "html"
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else if is_end_tag_named_one_of(token, "table", "tbody", "tfoot", "thead", "tr") {
    // An end tag whose tag name is one of: "table", "tbody", "tfoot", "thead", "tr"
        // If the stack of open elements does not have an element in table scope that is an HTML element with the same tag name as that of the token, then this is a parse error; ignore the token.
        if !stack_has_element_in_table_scope(parser, get_element_type_from_tag_name(strings.to_string(token.(Tag_Token).name))) {
            report_parse_error(.ErrorInTreeConstruction)
        }
        else { // Otherwise, close the cell (see below) and reprocess the token.
            panic("TODO")
        }
    }
    else { // Anything else
        // Process the token using the rules for the "in body" insertion mode.
        handle_in_body_insertion_mode(parser, document, token)
    }

    return true
}

// https://html.spec.whatwg.org/#parsing-main-afterbody
// When the user agent is to apply the rules for the "after body" insertion mode, the user agent must handle the token as follows:
handle_after_body_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    _, is_eof := token.(Eof_Token)

    // A character token that is one of U+0009 CHARACTER TABULATION, U+000A LINE FEED (LF), U+000C FORM FEED (FF), U+000D CARRIAGE RETURN (CR), or U+0020 SPACE
    if is_character && (character.data == '\t' || character.data == '\n' || character.data == '\f' || character.data == '\r' || character.data == ' ') {
        // Process the token using the rules for the "in body" insertion mode.
        handle_in_body_insertion_mode(parser, document, token)
    }
    else if is_comment { // A comment token
        // Insert a comment as the last child of the first element in the stack of open elements (the html element).
        insert_comment(parser, comment, parser.stack_of_open_elements[0], len(parser.stack_of_open_elements[0].children))
    }
    else if is_doctype { // A DOCTYPE token
        // Parse error. Ignore the token.
        report_parse_error(.ErrorInTreeConstruction)
    }
    else if is_start_tag_named_one_of(token, "html") { // A start tag whose tag name is "html"
        // Process the token using the rules for the "in body" insertion mode.
        handle_in_body_insertion_mode(parser, document, token)
    }
    else if is_end_tag_named_one_of(token, "html") { // An end tag whose tag name is "html"
        // @TODO: If the parser was created as part of the HTML fragment parsing algorithm, this is a parse error; ignore the token. (fragment case)
        if false {}
        else { // Otherwise, switch the insertion mode to "after after body".
            parser.insertion_mode = .AfterAfterBody
        }
    }
    else if is_eof { // An end-of-file token
        // Stop parsing.
        return false 
    }
    else { // Anything else
        // Parse error. Switch the insertion mode to "in body" and reprocess the token.
        report_parse_error(.ErrorInTreeConstruction)
        parser.insertion_mode = .InBody
        parser.should_reprocess = true
    }

    return true
}

// https://html.spec.whatwg.org/#the-after-after-body-insertion-mode
// When the user agent is to apply the rules for the "after after body" insertion mode, the user agent must handle the token as follows:
handle_after_after_body_insertion_mode :: proc(parser: ^Html_Parser, document: ^Document, token: Html_Token) -> (should_continue: bool) {
    character, is_character := token.(Character_Token)
    comment, is_comment := token.(Comment_Token)
    doctype, is_doctype := token.(Doctype_Token)
    _, is_eof := token.(Eof_Token)

    if is_comment { // A comment token
        // Insert a comment as the last child of the Document object.
        insert_comment(parser, comment, document, len(document.children))
    }
    else if is_doctype || \
        (is_character && (character.data == '\t' || character.data == '\n' || character.data == '\f' || character.data == '\r' || character.data == ' ')) || \
        is_start_tag_named_one_of(token, "html") {
    // A DOCTYPE token
    // A character token that is one of U+0009 CHARACTER TABULATION, U+000A LINE FEED (LF), U+000C FORM FEED (FF), U+000D CARRIAGE RETURN (CR), or U+0020 SPACE
    // A start tag whose tag name is "html"
        // Process the token using the rules for the "in body" insertion mode.
        handle_in_body_insertion_mode(parser, document, token)
    }
    else if is_eof { // An end-of-file token
        // Stop parsing.
        return false
    }
    else { // Anything else
        // Parse error. Switch the insertion mode to "in body" and reprocess the token.
        report_parse_error(.ErrorInTreeConstruction)
        parser.insertion_mode = .InBody
        parser.should_reprocess = true
    }

    return true
}

current_node :: proc(parser: ^Html_Parser) -> ^Element {
    assert(len(parser.stack_of_open_elements) > 0)
    return slice.last(parser.stack_of_open_elements[:])
}

current_node_with_index :: proc(parser: ^Html_Parser) -> (element: ^Element, index: int) {
    return current_node(parser), len(parser.stack_of_open_elements) - 1
}

set_to_previous_stack_entry :: proc(parser: ^Html_Parser, index: int) -> (element: ^Element, previous_index: int) {
    assert(index > 0)
    previous_index = index - 1
    element = parser.stack_of_open_elements[previous_index]
    return element, previous_index
}

// https://html.spec.whatwg.org/#adoption-agency-algorithm
// The adoption agency algorithm, which takes as its only argument a token token for which the algorithm is being run, consists of the following steps:
do_adoption_agency :: proc(parser: ^Html_Parser, tag: Tag_Token) {
    // Let subject be token's tag name.
    subject_type := get_element_type_from_tag_name(strings.to_string(tag.name))
    // If the current node is an HTML element whose tag name is subject, and the current node is not in the list of active formatting elements, then pop
    // the current node off the stack of open elements and return.
    curr_node := current_node(parser)
    if curr_node.type != subject_type && !in_list_of_active_formatting_elements(parser, curr_node) {
        pop(&parser.stack_of_open_elements)
        return
    }

    // Let outerLoopCounter be 0.
    outer_loop_counter := 0
    // While true:
    for {
        // If outerLoopCounter is greater than or equal to 8, then return.
        if outer_loop_counter >= 8 do return
        // Increment outerLoopCounter by 1.
        outer_loop_counter += 1

        // Let formattingElement be the last element in the list of active formatting elements that:
        //     is between the end of the list and the last marker in the list, if any, or the start of the list otherwise, and
        //     has the tag name subject.
        formatting_element: ^Element = nil
        formatting_element_list_index := 0
        find: #reverse for elem, index in parser.list_of_active_formatting_elements {
            switch e in elem {
                case Marker: break find
                case ^Element:
                    if e.type == .Subject {
                        formatting_element = e
                        formatting_element_list_index = index
                        break find
                    }
            }
        }

        // If there is no such element, then return and instead act as described in the "any other end tag" entry above.
        if formatting_element == nil {
            handle_in_body_any_other_end_tag(parser, tag)
            return
        }
        // If formattingElement is not in the stack of open elements, then this is a parse error; remove the element from the list, and return.
        if !stack_has_element(parser, formatting_element) {
            report_parse_error(.ErrorInTreeConstruction)
            ordered_remove(&parser.list_of_active_formatting_elements, formatting_element_list_index)
            return
        }
        //@TODO: If formattingElement is in the stack of open elements, but the element is not in scope, then this is a parse error; return.
        // If formattingElement is not the current node, this is a parse error. (But do not return.)
        if formatting_element != current_node(parser) do report_parse_error(.ErrorInTreeConstruction)

        // Let furthestBlock be the topmost node in the stack of open elements that is lower in the stack than formattingElement, and is an element in the
        // special category. There might not be one.
        furthest_block: ^Element = nil
        furthest_block_index := 0
        found_formatting_element := false
        formatting_element_stack_index := 0
        for elem, index in parser.stack_of_open_elements {
            if found_formatting_element && (elem.type in special_category) {
                furthest_block = elem
                furthest_block_index = index
                break
            }
            if elem == formatting_element {
                found_formatting_element = true
                formatting_element_stack_index = index
            }
        }

        // If there is no furthestBlock, then the UA must first pop all the nodes from the bottom of the stack of open elements, from the current node up to
        // and including formattingElement, then remove formattingElement from the list of active formatting elements, and finally return.
        if furthest_block == nil {
            for current_node(parser) != formatting_element {
                pop(&parser.stack_of_open_elements)
            }
            ordered_remove(&parser.list_of_active_formatting_elements, formatting_element_list_index)
            return
        }

        // Let commonAncestor be the element immediately above formattingElement in the stack of open elements.
        common_ancestor := parser.stack_of_open_elements[formatting_element_stack_index - 1]
        // Let a bookmark note the position of formattingElement in the list of active formatting elements relative to the elements on either side of it in the list.
        bookmark := formatting_element_list_index
        // Let node and lastNode be furthestBlock.
        node := furthest_block
        node_index := furthest_block_index
        last_node := furthest_block
        // Let innerLoopCounter be 0.
        inner_loop_counter := 0

        //While true:
        for {
            // Increment innerLoopCounter by 1.
            inner_loop_counter += 1
            // Let node be the element immediately above node in the stack of open elements, or if node is no longer in the stack of open elements
            // (e.g. because it got removed by this algorithm), the element that was immediately above node in the stack of open elements before node was removed.
            node, node_index = set_to_previous_stack_entry(parser, node_index)
            // If node is formattingElement, then break.
            if node == formatting_element do break
            // If innerLoopCounter is greater than 3 and node is in the list of active formatting elements, then remove node from the list of active formatting elements.
            found, index := find_index_in_list_of_active_formatting_elements(parser, node);
            if inner_loop_counter > 3 && found {
                ordered_remove(&parser.list_of_active_formatting_elements, index)
            }
            // If node is not in the list of active formatting elements, then remove node from the stack of open elements and continue.
            if !found {
                ordered_remove(&parser.stack_of_open_elements, node_index)
                continue
            }

            // Create an element for the token for which the element node was created, in the HTML namespace, with commonAncestor as the intended parent; replace
            // the entry for node in the list of active formatting elements with an entry for the new element, replace the entry for node in the stack of open elements
            // with an entry for the new element, and let node be the new element.
            element := create_element_for_token(node.generating_token, HTML_NAMESPACE, common_ancestor)
            parser.stack_of_open_elements[node_index] = element
            node = element
            // If last node is furthestBlock, then move the aforementioned bookmark to be immediately after the new node in the list of active formatting elements.
            found, index = find_index_in_list_of_active_formatting_elements(parser, node)
            if last_node == furthest_block do bookmark = index + 1 
            // Append lastNode to node.
            append_child(node, last_node)
            // Set lastNode to node.
            last_node = node
        }

        // Insert whatever lastNode ended up being in the previous step at the appropriate place for inserting a node, but using commonAncestor as the override target.
        insertion_elem, insertion_index := get_appropriate_insertion_location(parser, common_ancestor)
        insert_node_at_location(last_node, insertion_elem, insertion_index)
        // Create an element for the token for which formattingElement was created, in the HTML namespace, with furthestBlock as the intended parent.
        element := create_element_for_token(formatting_element.generating_token, HTML_NAMESPACE, furthest_block)
        // Take all of the child nodes of furthestBlock and append them to the element created in the last step.
        for child in furthest_block.children {
            append_child(element, child)
        }
        // Append that new element to furthestBlock.
        append_child(furthest_block, element)
        // Remove formattingElement from the list of active formatting elements, and insert the new element into the list of active formatting elements at the position
        // of the aforementioned bookmark.
        ordered_remove(&parser.list_of_active_formatting_elements, formatting_element_list_index)
        inject_at(&parser.list_of_active_formatting_elements, bookmark)
        // Remove formattingElement from the stack of open elements, and insert the new element into the stack of open elements immediately below the position of
        // furthestBlock in that stack.
        ordered_remove(&parser.stack_of_open_elements, formatting_element_stack_index)
        inject_at(&parser.stack_of_open_elements, furthest_block_index + 1)
    }
}

// https://html.spec.whatwg.org/#close-the-cell
// Where the steps above say to close the cell, they mean to run the following algorithm:
close_cell :: proc(parser: ^Html_Parser) {
    // Generate implied end tags.
    generate_implied_end_tags(parser)
    // If the current node is not now a td element or a th element, then this is a parse error.
    if current_node(parser).type != .Td && current_node(parser).type != .Th {
        report_parse_error(.ErrorInTreeConstruction)
    }
    // Pop elements from the stack of open elements stack until a td element or a th element has been popped from the stack.
    for current_node(parser).type != .Td && current_node(parser).type != .Th {
        pop(&parser.stack_of_open_elements)
    }
    pop(&parser.stack_of_open_elements)
    // Clear the list of active formatting elements up to the last marker.
    clear_list_of_active_formatting_elements_up_to_marker(parser)
    // Switch the insertion mode to "in row".
    parser.insertion_mode = .InRow
}


// https://html.spec.whatwg.org/#close-a-p-element
// When the steps above say the user agent is to close a p element, it means that the user agent must run the following steps:
close_p_element :: proc(parser: ^Html_Parser) {
    // Generate implied end tags, except for p elements.
    generate_implied_end_tags(parser, {.P})
    // If the current node is not a p element, then this is a parse error.
    if current_node(parser).type != .P do report_parse_error(.ErrorInTreeConstruction)
    // Pop elements from the stack of open elements until a p element has been popped from the stack.
    for current_node(parser).type != .P {
        pop(&parser.stack_of_open_elements)
    }
    pop(&parser.stack_of_open_elements)
}

// https://html.spec.whatwg.org/#generate-implied-end-tags
// When the steps below require the UA to generate implied end tags, then, while the current node is a dd element, a dt element, an li element,
// an optgroup element, an option element, a p element, an rb element, an rp element, an rt element, or an rtc element, the UA must pop the current
// node off the stack of open elements.
generate_implied_end_tags :: proc(parser: ^Html_Parser, except: bit_set[Element_Type] = nil) {
    types := bit_set[Element_Type]{.Dd, .Dt, .Li, .OptGroup, .Option, .P, .Rb, .Rp, .Rt, .Rtc} - except
    for (current_node(parser).type in types) {
        pop(&parser.stack_of_open_elements)
    }
}

// https://html.spec.whatwg.org/#generic-rcdata-element-parsing-algorithm
// The generic raw text element parsing algorithm and the generic RCDATA element parsing algorithm consist of the following steps. These algorithms are
// always invoked in response to a start tag token.
parse_generic_text :: proc(parser: ^Html_Parser, tag: Tag_Token, is_rawtext := true) {
    // Insert an HTML element for the token.
    insert_html_element(parser, tag)
    // If the algorithm that was invoked is the generic raw text element parsing algorithm, switch the tokenizer to the RAWTEXT state; otherwise the algorithm
    // invoked was the generic RCDATA element parsing algorithm, switch the tokenizer to the RCDATA state.
    if is_rawtext do parser.tokenizer.state = .RawText
    else do parser.tokenizer.state = .RCData
    // Let the original insertion mode be the current insertion mode.
    parser.original_insertion_mode = parser.insertion_mode
    // Then, switch the insertion mode to "text".
    parser.insertion_mode = .Text
}

// https://html.spec.whatwg.org/#appropriate-place-for-inserting-a-node
get_appropriate_insertion_location :: proc(parser: ^Html_Parser, override_target: ^Node = nil) -> (parent: ^Node, child_index: int) {
    // If there was an override target specified, then let target be the override target.
    target := override_target

    // Otherwise, let target be the current node.
    if target == nil do target = current_node(parser)

    // Determine the adjusted insertion location using the first matching steps from the following list:
    // If foster parenting is enabled and target is a table, tbody, tfoot, thead, or tr element
    if element, is_element := target.node_type.(^Element); \
        parser.foster_parenting && is_element && (element.type in bit_set[Element_Type]{.Table, .TBody, .TFoot, .THead, .Tr}) {
        assert(false, "TODO")
    /* @TODO
        Foster parenting happens when content is misnested in tables.
        Run these substeps:
            Let last template be the last template element in the stack of open elements, if any.
            Let last table be the last table element in the stack of open elements, if any.
            If there is a last template and either there is no last table, or there is one, but last template is lower (more recently added) than last table in the stack of open elements, then: let adjusted insertion location be inside last template's template contents, after its last child (if any), and abort these steps.
            If there is no last table, then let adjusted insertion location be inside the first element in the stack of open elements (the html element), after its last child (if any), and abort these steps. (fragment case)
            If last table has a parent node, then let adjusted insertion location be inside last table's parent node, immediately before last table, and abort these steps.
            Let previous element be the element immediately above last table in the stack of open elements.
            Let adjusted insertion location be inside previous element, after its last child (if any).
        These steps are involved in part because it's possible for elements, the table element in this case in particular, to have been moved by a script around in the DOM, or indeed removed from the DOM entirely, after the element was inserted by the parser.
    */
    }
    else { // Otherwise
        // Let adjusted insertion location be inside target, after its last child (if any).
        parent = target
        child_index = len(target.children)
    }
    // @TODO: If the adjusted insertion location is inside a template element, let it instead be inside the template element's template contents, after its last child (if any).
    // Return the adjusted insertion location.
    return parent, child_index
}

insert_node_at_location :: proc(child: ^Node, insertion_elem: ^Node, insertion_index: int) {
    inject_at(&insertion_elem.children, insertion_index, child)
}

// https://html.spec.whatwg.org/#insert-an-element-at-the-adjusted-insertion-location
// To insert an element at the adjusted insertion location with an element element:
insert_element_at_adjusted_insertion_location :: proc(parser: ^Html_Parser, element: ^Element) {
    // Let the adjusted insertion location be the appropriate place for inserting a node.
    insertion_elem, insertion_index := get_appropriate_insertion_location(parser)
    // @TODO: If it is not possible to insert element at the adjusted insertion location, abort these steps.
    // @TODO: If the parser was not created as part of the HTML fragment parsing algorithm, then push a new element queue onto element's relevant agent's custom element reactions stack.
    // Insert element at the adjusted insertion location.
    insert_node_at_location(element, insertion_elem, insertion_index)
    // @TODO: If the parser was not created as part of the HTML fragment parsing algorithm, then pop the element queue from element's relevant agent's custom element reactions stack, and invoke custom element reactions in that queue.
}

// https://html.spec.whatwg.org/#insert-a-foreign-element
// When the steps below require the user agent to insert a foreign element for a token in a given namespace and with a boolean onlyAddToElementStack, the user agent
// must run these steps:
insert_foreign_element :: proc(parser: ^Html_Parser, token: Tag_Token, namespace: string, only_add_to_element_stack: bool) -> ^Element {
    // Let the adjusted insertion location be the appropriate place for inserting a node.
    insertion_elem, insertion_index := get_appropriate_insertion_location(parser)
    // Let element be the result of creating an element for the token in the given namespace, with the intended parent being the element in which the adjusted
    // insertion location finds itself.
    element := create_element_for_token(token, namespace, insertion_elem)
    // If onlyAddToElementStack is false, then run insert an element at the adjusted insertion location with element.
    if !only_add_to_element_stack do insert_element_at_adjusted_insertion_location(parser, element)
    // Push element onto the stack of open elements so that it is the new current node.
    append(&parser.stack_of_open_elements, element)
    // Return element.
    return element
}

// https://html.spec.whatwg.org/#insert-an-html-element
// When the steps below require the user agent to insert an HTML element for a token, the user agent must insert a foreign element for the token, with the
// HTML namespace and false.
insert_html_element :: proc(parser: ^Html_Parser, token: Tag_Token) -> ^Element {
    return insert_foreign_element(parser, token, HTML_NAMESPACE, false)
}

