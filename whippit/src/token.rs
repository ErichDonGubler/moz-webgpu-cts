use std::{cmp::Ordering, io, iter, str::Lines};

use chumsky::{
    extra,
    input::Stream,
    prelude::{EmptyErr, Input, Rich},
    primitive::{any, choice, custom, just},
    span::SimpleSpan,
    text::{ascii, inline_whitespace, newline},
    IterParser, Parser,
};

#[derive(Clone, Debug)]
enum Event<'a> {
    SingleLineComment {
        span: SimpleSpan,
        contents: &'a str,
        contents_span: SimpleSpan,
    },
    // Property {
    //     name: &'a str,
    //     name_span: SimpleSpan,
    //     value: &'a str,
    //     value_span: SimpleSpan,
    // },
    EnterSection {
        header_span: SimpleSpan,
        name: UnescapedSectionHeader<'a>,
        name_span: SimpleSpan,
    },
    ExitSection {
        end_point_span: SimpleSpan,
    },
}

// enum PropertyValue<'a> {
//     Unconditional(&'a str),
//     Conditional(ConditionalPropertyTokenizer<'a>),
// }
//
// struct ConditionalPropertyTokenizer<'a> {}

#[derive(Clone, Debug)]
struct UnescapedSectionHeader<'a> {
    name: &'a str,
}

#[derive(Clone, Debug)]
struct Tokenizer<'a> {
    input: &'a str,
    current_idx: usize,
    current_indent_level: u8,
}

#[derive(Clone, Debug)]
enum TokenizationError {
    MisalignedIndent { span: SimpleSpan },
    UnexpectedIndent { indent_span: SimpleSpan },
    // TODO: populate
    MalformedItem { skipped_span: SimpleSpan },
}

fn lines<'a>(input: &'a str) -> impl Clone + Iterator<Item = (&'a str, SimpleSpan)> + 'a {
    let parser = any::<_, extra::Err<EmptyErr>>()
        .and_is(newline().not())
        .repeated()
        .to_slice()
        .then_ignore(newline().or_not())
        .map_with(|line, e| (e.span(), line))
        .lazy();

    let mut idx = 0;
    iter::from_fn(move || loop {
        if idx == input.len() {
            return None;
        }
        let (span, line) = parser.parse(&input[idx..]).into_result().unwrap();
        idx += span.end;
        if !line.trim().is_empty() {
            break Some((line.trim_end(), span));
        }
    })
}

fn tokens<'a>(input: &'a str) -> impl Iterator<Item = Result<Event<'a>, TokenizationError>> + 'a {
    const INDENT_SIZE: usize = 2;

    let mut remaining_lines = Some(lines(input));

    iter::from_fn(move || {
        let lines = remaining_lines.as_mut()?;

        let (first_line, first_line_span) = lines.next()?;
        let first_line = first_line.map_span(move |span| {
            SimpleSpan::new(
                span.start + first_line_span.start,
                span.end + first_line_span.start,
            )
        });

        let (indent_len, (unindented_span, unindented)) =
            just::<'_, _, _, extra::Err<EmptyErr>>(" ")
                .repeated()
                .count()
                .map_with(|indent, e| (e.span(), indent))
                .then(
                    any()
                        .repeated()
                        .to_slice()
                        .map_with(|line, e| (e.span(), line)),
                )
                .parse(first_line)
                .into_result()
                .unwrap();
        let unindented = unindented.map_span(move |span| {
            SimpleSpan::new(
                span.start + unindented_span.start,
                span.end + unindented_span.start,
            )
        });

        if let Ok(comment) = just::<'_, _, _, extra::Err<EmptyErr>>('#')
            .ignore_then(just(' ').or_not())
            .ignore_then(
                any()
                    .repeated()
                    .to_slice()
                    .map_with(|contents, e| (e.span(), contents)),
            )
            .map_with(|parsed, e| (e.span(), parsed))
            .parse(unindented.clone())
            .into_result()
        {
            let (span, (contents_span, contents)) = comment;
            return Some(Ok(Event::SingleLineComment {
                span,
                contents,
                contents_span,
            }));
        }

        let parsed_indent_level = {
            let (span, indent_len) = indent_len;
            if indent_len % INDENT_SIZE != 0 {
                remaining_lines.take();
                return Some(Err(TokenizationError::MisalignedIndent { span }));
            }
            indent_len / INDENT_SIZE
        };

        enum Parsed<'a> {
            SectionHeader {
                span: &'a str,
                unescaped_name: &'a str,
                unescaped_name_span: SimpleSpan,
            },
        }


        .map_err(|_e| TokenizationError::MalformedItem {
            skipped_span: first_line_span,
        })
        .and_then(|res| res)
        .map(Some)
        .transpose()
    })
    // let parser = custom(|input| {
    //     let indent_len = input.next().unwrap();
    //
    //     let comment = inline_whitespace()
    //         .ignore_then(just('#'))
    //         .ignore_then(any());
    //     input.check(parser);
    //
    //     choice((comment, section_header))
    // })
    // .lazy();

    // let mut current_indent_level = 0;
    // iter::from_fn(move || {
    //     const INDENT_SIZE: usize = 2;
    //
    //     let fuse = |current_idx: &mut _, input: &str| {
    //         *current_idx = input.len();
    //     };
    //
    //     let mut next_nonempty_line = || loop {
    //         let (line, line_span) = lines.as_mut()?.next()?;
    //
    //         let unindented = line.trim_start_matches(' ');
    //         if unindented.is_empty() {
    //             continue;
    //         }
    //
    //         let indent_len = line.len() - unindented.len();
    //
    //         break Some((line_span, indent_len, unindented));
    //     };
    //     let (parsed_indent_level, unindented) = {
    //         let (line_span, indent_len, unindented) = next_nonempty_line()?;
    //
    //         if unindented.starts_with('#') {
    //             return Some(Ok(Event::SingleLineComment {
    //                 contents: fully_trimmed,
    //                 contents_span: todo!(),
    //             }));
    //         }
    //
    //         if indent_len % INDENT_SIZE != 0 {
    //             fuse(current_idx, input);
    //             return Some(Err(TokenizationError::MisalignedIndent {
    //                 span: SimpleSpan::new(*current_idx, *current_idx + indent_len),
    //             }));
    //         }
    //         (indent_len / INDENT_SIZE, unindented)
    //     };
    //
    //     match parsed_indent_level.cmp(&usize::from(*current_indent_level)) {
    //         Ordering::Equal => (),
    //         Ordering::Less => {
    //             *current_indent_level = *current_indent_level - 1;
    //             // Deliberate: don't update `current_idx`. We'll emit another event for the next
    //             // level of indentation.
    //             return Some(Ok(Event::ExitSection {
    //                 end_point_span: todo!(),
    //             }));
    //         }
    //         Ordering::Greater => {
    //             return Some(Err(TokenizationError::UnexpectedIndent {
    //                 indent_span: todo!(),
    //             }))
    //         }
    //     };
    //
    //     // TODO: check for a property or section
    //     if let Some(rest) = unindented.strip_prefix('[') {
    //         // TODO: escaping
    //     } else if let Ok(property_ident) = ascii::ident::<_, _, extra::Err<EmptyErr>>()
    //         .lazy()
    //         .parse(*input)
    //         .into_result()
    //     {
    //         if let Some(property_val_on_line) = input[property_ident.len()..].strip_prefix(':') {
    //             let property_val_on_line = property_val_on_line.trim_start();
    //             if property_val_on_line.is_empty() {
    //                 while let Some((indent_len, unindented)) = next_nonempty_line() {
    //                     if indent_len / INDENT_SIZE <= *current_indent_level {
    //                         break;
    //                     }
    //                 }
    //
    //                 // TODO: slurp up indented
    //             }
    //         }
    //     }
    //
    //     // TODO: recover by skipping indented items, probably relevant to this malformed
    //     // whatever-it-is
    //     Some(Err(TokenizationError::MalformedItem {
    //         skipped_span: todo!(),
    //     }))
    // })
}

fn main() {
    dbg!(tokens(
        r#"
# hay sup
[thing]
  [thang]
    stuff: things

[blarg] "#,
    )
    .collect::<Vec<_>>());

    //     dbg!(Tokenizer::new(
    //         r#"
    // [thing]
    //   [thang]
    //
    // stuff: things
    //
    // [blarg] "#
    //     )
    //     .collect::<Vec<_>>());
}
