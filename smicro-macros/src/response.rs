use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::quote;
use syn::{
    parse, parse::Parser, punctuated::Punctuated, spanned::Spanned, Expr, ExprPath, ItemStruct,
    Meta, Token,
};

struct PacketArgs {
    ty: ExprPath,
}

fn parse_packet_args(input: TokenStream) -> Result<PacketArgs, Diagnostic> {
    let mut ty = None;

    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let attribute_args = match parser.parse(input.clone()) {
        Ok(x) => x,
        Err(_) => return Err(Span::call_site().error("Couldn't parse the fields of the macro")),
    };

    for arg in attribute_args.iter() {
        if let Meta::NameValue(namevalue) = arg {
            let key = namevalue
                .path
                .get_ident()
                .expect("the macro parameter is not an ident?")
                .to_string();
            match key.as_str() {
                "packet_type" => {
                    if let Expr::Path(ty_path) = &namevalue.value {
                        ty = Some(ty_path);
                    } else {
                        return Err(Span::call_site()
                            .error(format!("Invalid parameter for the value {}", key)));
                    }
                }
                _ => return Err(arg.span().error("Unsupported macro parameter")),
            }
        } else {
            return Err(arg.span().error("Unrecognized argument"));
        }
    }

    if ty.is_none() {
        return Err(attribute_args.span().error("Missing type argument"));
    }

    Ok(PacketArgs {
        ty: ty.unwrap().clone(),
    })
}

pub(crate) fn declare_response_packet_inner(
    attrs: TokenStream,
    item: TokenStream,
) -> Result<TokenStream, Diagnostic> {
    let ast: ItemStruct = parse(item.clone()).expect("Not a structure?");
    let name = &ast.ident;
    let generics = &ast.generics;

    let args = parse_packet_args(attrs)?;

    let ty = args.ty;

    Ok(quote! {
        #[derive(Debug)]
        #[smicro_macros::gen_serialize_impl]
        #ast

        impl #generics crate::response::ResponsePacket for #name #generics {
            fn get_type(&self) -> ResponseType {
                #ty
            }
        }
    }
    .into())
}
