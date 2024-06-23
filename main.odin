package browser

import "core:os"
import "core:strings"
import "core:fmt"

import "css"
import "html"

parse_and_print_html :: proc(file_name: string) {
    data, ok := os.read_entire_file(file_name)
    if !ok {
        fmt.eprintfln("Could not open %v", file_name)
    }

    reader: strings.Reader
    input_stream := strings.to_reader(&reader, string(data[:]))

    tokenizer: html.Html_Tokenizer
    html.tokenizer_init(&tokenizer, input_stream)

    parser: html.Html_Parser
    html.parser_init(&parser, &tokenizer)

    document := html.Document{}
    document.document = &document
    html.construct_tree(&parser, &document)
    html.print_document(&document)
}

parse_and_print_css :: proc(file_name: string) {
    data, ok := os.read_entire_file(file_name)
    if !ok {
        fmt.eprintfln("Could not open %v", file_name)
    }

    reader: strings.Reader
    input_stream := strings.to_reader(&reader, string(data[:]))

    tokenizer: css.Css_Tokenizer
    css.tokenizer_init(&tokenizer, input_stream)
    
    for {
        token := css.get_next_token(&tokenizer)
        if _, is_eof := token.(css.Eof_Token); is_eof do return 
        fmt.println(token)
    }
}

main :: proc() {
    if len(os.args) != 3 {
        fmt.eprintln("Invalid arguments")
    }
    if os.args[1] == "-html" do parse_and_print_html(os.args[2])
    else if os.args[1] == "-css" do parse_and_print_css(os.args[2])
    /*
    init_success := sdl2.Init(sdl2.INIT_VIDEO)
    if init_success < 0 {
        fmt.eprintln("Could not initialize sdl2")
        return
    }

    init_success = ttf.Init()
    if init_success < 0 {
        fmt.eprintln("Could not initialize sdl2_ttf")
        return
    }

    window := sdl2.CreateWindow("Painter", 100, 100, WINDOW_WIDTH, WINDOW_HEIGHT, {.SHOWN, .RESIZABLE})
    if window == nil {
        fmt.eprintln("Could not create a window")
        return
    }

    renderer := sdl2.CreateRenderer(window, -1, sdl2.RENDERER_ACCELERATED)
    if renderer == nil {
        fmt.eprintln("Could not create renderer")
        return
    }

    set_painter_font("Times_Regular.ttf")

    running := true
    for running {
        painter_y = 0
        event: sdl2.Event
        event_found := sdl2.PollEvent(&event)

        if event_found {
            #partial switch event.type {
                case .QUIT: running = false
            }
        }

        paint_document(&document, window, renderer)
        sdl2.RenderPresent(renderer)
        sdl2.SetRenderDrawColor(renderer, 0xff, 0xff, 0xff, 0xff)
        sdl2.RenderClear(renderer)
    }

    sdl2.DestroyRenderer(renderer)
    sdl2.DestroyWindow(window)
    */
}
