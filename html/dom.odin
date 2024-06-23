package html

import "core:fmt"
import "core:strings"

Node :: struct {
    parent: ^Node,
    children: [dynamic]^Node,
    document: ^Document,

    node_type: any,
}

Element_Type :: enum {
    Em,
    Subject,
    Html,
    Table,
    TBody,
    TFoot,
    THead,
    Tr,
    Th, 
    Td, 
    Head,
    Meta,
    Body,
    Dd,
    Dt,
    Li,
    Template,
    Option,
    OptGroup,
    P,
    Rb,
    Rt,
    Rtc,
    Rp,
    Link,
    Div,
    Section,
    Header,
    Nav,
    Ul,
    Img,
    Input,
    Iframe,
    Keygen,
    Listing,
    Main,
    Marquee,
    NoEmbed,
    NoFrames,
    Menu,
    Object,
    NoScript,
    Param,
    Plaintext,
    Pre,
    Script,
    Search,
    Select,
    Source,
    Style,
    Summary,
    TextArea,
    Title,
    Track,
    Wbr,
    Xmp,
    Ol,
    Hr,
    H1,
    H2,
    H3,
    H4,
    H5,
    H6,
    Frame,
    Frameset,
    HGroup,
    Form,
    Footer,
    Figure,
    FigCaption,
    Fieldset,
    Embed,
    Dl,
    Dir,
    Details,
    Colgroup,
    Col,
    Center,
    Caption,
    Button,
    Br,
    BlockQuote,
    BgSound,
    BaseFont,
    Base,
    Aside,
    Article,
    Area,
    Address,
    Applet,
    A,
}

special_category := bit_set[Element_Type]{
    .Address,
    .Applet,
    .Area,
    .Article,
    .Aside,
    .Base,
    .BaseFont,
    .BgSound,
    .BlockQuote,
    .Body,
    .Br,
    .Button,
    .Caption,
    .Center,
    .Col,
    .Colgroup,
    .Dd,
    .Details,
    .Dir,
    .Div,
    .Dl,
    .Dt,
    .Embed,
    .Fieldset,
    .FigCaption,
    .Figure,
    .Footer,
    .Form,
    .Frame,
    .Frameset,
    .H1,
    .H2,
    .H3,
    .H4,
    .H5,
    .H6,
    .Head,
    .Header,
    .HGroup,
    .Hr,
    .Html,
    .Iframe,
    .Img,
    .Input,
    .Keygen,
    .Li,
    .Link,
    .Listing,
    .Main,
    .Marquee,
    .Menu,
    .Meta,
    .Nav,
    .NoEmbed,
    .NoFrames,
    .NoScript,
    .Object,
    .Ol,
    .P,
    .Param,
    .Plaintext,
    .Pre,
    .Script,
    .Search,
    .Section,
    .Select,
    .Source,
    .Style,
    .Summary,
    .Table,
    .TBody,
    .Td,
    .Template,
    .TextArea,
    .TFoot,
    .Th,
    .THead,
    .Title,
    .Tr,
    .Track,
    .Ul,
    .Wbr,
    .Xmp,
}

Element :: struct {
    using n: Node,
    type: Element_Type,
    namespace: Maybe(string),
    prefix: Maybe(string),
    local_name: string,
    // @TODO: Eventually we will want to compare tag names, but for now we just compare local names
    // tag_name: string,

    // We need to save the token that generated this element for the adoption agency algorithm
    generating_token: Tag_Token,
}

Document :: struct {
    using n: Node,
    document_uri: string,
}

Document_Type :: struct {
    using n: Node,
    name: string,
    public_id: string,
    system_id: string,
}

Comment :: struct {
    using n: Node,
    data: string,
}

Attr :: struct {
    using n: Node,
    namespace_uri: string,
    name: string,
    value: string,
}

Text :: struct {
    using n: Node,
    data: strings.Builder,
}

make_node :: proc($T: typeid, document: ^Document) -> ^T {
    node := new(T)
    node.node_type = node^
    node.document = document
    return node
}

append_child :: proc(parent: ^Node, child: ^Node) {
    append(&parent.children, child)
    child.parent = parent
}

remove_from_parent :: proc(element: ^Element) {
    parent := element.parent
    assert(parent != nil)
    for elem, index in parent.children {
        if elem == element {
            ordered_remove(&parent.children, index)
            break
        }
    }
}

print_indent :: proc(indent: int) {
    for i in 0..<indent {
        fmt.print("  ")
    }
}

print_node :: proc(node: ^Node, indent := 0) {
    switch &n in node.node_type {
        case Element:
            print_element(&n, indent)
        case Attr:
            print_indent(indent)
            fmt.printfln("Attr(name=%s, value=%s)", n.name, n.value)
        case Text:
            print_indent(indent)
            fmt.printfln("Text(%q)", strings.to_string(n.data))
        /*
        case CData_Section:
        case Processing_Instruction:
        */
        case Comment:
            fmt.printfln("Comment(data=%s)", n.data)
        case Document:
            print_document(&n, indent)
        case Document_Type:
            print_document_type(&n, indent)
        // case DocumentFragment:
        case:
            fmt.assertf(false, "Unsupported node type: %s", node.node_type)
    }
}

set_element_type_from_tag_name :: proc(element: ^Element, tag_name: string) {
    element.type = get_element_type_from_tag_name(tag_name)
}

get_element_type_from_tag_name :: proc(tag_name: string) -> Element_Type {
    switch tag_name {
        case "html": return .Html
        case "table": return .Table
        case "tbody": return .TBody
        case "tfoot": return .TFoot
        case "thead": return .THead
        case "tr": return .Tr
        case "head": return .Head
        case "meta": return .Meta
        case "body": return .Body
        case "link": return .Link
        case "div": return .Div
        case "section": return .Section
        case "header": return .Header
        case "nav": return .Nav
        case "ul": return .Ul
        case "li": return .Li
        case "p": return .P
        case "h2": return .H2
        case "h1": return .H1
        case "h4": return .H4
        case "h3": return .H3
        case "h5": return .H5
        case "footer": return .Footer
        case "title": return .Title
        case "a": return .A
        case "th": return .Th
        case "td": return .Td
        case "em": return .Em
        case "style": return .Style
        case: fmt.assertf(false, "TODO: Tag name %s not handled yet!", tag_name)
    }
    return {}
}

print_element :: proc(element: ^Element, indent := 0) {
    print_indent(indent)
    fmt.printf("%s(namespace=%q, prefix=%q, local_name=%q", element.type, element.namespace, element.prefix, element.local_name)
    print_all_children(element, indent)
}

print_all_children :: proc(node: ^Node, indent := 0) {
    if len(node.children) > 0 {
        fmt.println(", children=(")
        for child in node.children {
            print_node(child, indent + 1)
        }
        print_indent(indent)
        fmt.println("))")
    }
    else {
        fmt.println(")")
    }
}

print_document :: proc(document: ^Document, indent := 0) {
    print_indent(indent)
    fmt.printf("Document(uri=%q", document.document_uri)
    print_all_children(document, indent)
}

print_document_type :: proc(doctype: ^Document_Type, indent := 0) {
    print_indent(indent)
    fmt.printf("Document_Type(name=%q, system_id=%q, public_id=%q", doctype.name, doctype.public_id, doctype.system_id)
    print_all_children(doctype, indent)
}
