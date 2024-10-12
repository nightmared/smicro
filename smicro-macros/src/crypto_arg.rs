use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::quote;
use syn::{
    parse, parse::Parser, punctuated::Punctuated, spanned::Spanned, token::Comma, Expr, ExprPath,
    ItemConst, ItemStruct, LitStr, Meta, Path, Token,
};

pub(crate) fn declare_crypto_arg_inner(
    attrs: TokenStream,
    item: TokenStream,
) -> Result<TokenStream, Diagnostic> {
    let ast: ItemStruct = parse(item)?;
    let alg_name: LitStr = parse(attrs)?;

    let struct_name = &ast.ident;

    Ok(quote! {
        #[derive(Clone)]
        #ast

        impl crate::crypto::CryptoAlgName for #struct_name {
            const NAME: &'static str = #alg_name;

            fn name(&self) -> &'static str {
                Self::NAME
            }
        }
    }
    .into())
}

fn parse_crypto_list_args(input: TokenStream) -> Result<(Path, Path), Diagnostic> {
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let attribute_args = parser.parse(input.clone())?;

    let mut wrapper_name = None;
    let mut error_value = None;

    for arg in attribute_args.iter() {
        if let Meta::NameValue(namevalue) = arg {
            let key = namevalue
                .path
                .get_ident()
                .expect("the macro parameter is not an ident?")
                .to_string();
            if let Expr::Path(ExprPath { path, .. }) = &namevalue.value {
                match key.as_str() {
                    "wrapper_name" => {
                        wrapper_name = Some(path);
                    }
                    "error_value" => {
                        error_value = Some(path);
                    }
                    _ => return Err(arg.span().error("Unsupported macro parameter")),
                }
            } else {
                return Err(
                    Span::call_site().error(format!("Invalid parameter for the value {}", key))
                );
            }
        } else {
            return Err(arg.span().error("Unrecognized argument"));
        }
    }

    if wrapper_name.is_none() {
        return Err(attribute_args
            .span()
            .error("Missing 'wrapper_name' argument"));
    }
    if error_value.is_none() {
        return Err(attribute_args
            .span()
            .error("Missing 'error_value' argument"));
    }

    Ok((wrapper_name.unwrap().clone(), error_value.unwrap().clone()))
}

pub(crate) fn declare_crypto_algs_list_inner(
    attrs: TokenStream,
    item: TokenStream,
) -> Result<TokenStream, Diagnostic> {
    let ast: ItemConst = parse(item.clone())?;
    let (wrapper_name, error_value) = parse_crypto_list_args(attrs)?;

    let elems = if let Expr::Array(ref expr_arr) = *ast.expr {
        &expr_arr.elems
    } else {
        return Err(ast.expr.span().error("Not a list of entries"));
    };
    let entries_len = elems.len();
    let name_list_ident = syn::Ident::new(&format!("{}_NAMES", ast.ident), ast.ident.span());
    let mut name_list_values: Punctuated<_, Comma> = Punctuated::new();
    for e in elems {
        name_list_values.push(quote! { <#e>::NAME });
    }

    let negotiation_type = ast.ident.to_string().to_lowercase();

    let negotiate_alg_ident = syn::Ident::new(
        &format!("negotiate_alg_{}", negotiation_type),
        ast.ident.span(),
    );

    let mut match_list = Vec::new();
    for e in elems {
        if let Expr::Path(ExprPath { path, .. }) = e {
            let ident = path.segments.last().unwrap();
            match_list.push(quote! {
                if <#e>::NAME == client_alg.as_ref() {
                    return Ok(#wrapper_name::#ident(<#e>::new()));
                }
            });
        } else {
            return Err(e.span().error("Invalid value"));
        }
    }

    Ok(quote! {
        const #name_list_ident: [&'static str; #entries_len] = {
            use crate::crypto::CryptoAlgName;
            [#name_list_values]
        };

        pub fn #negotiate_alg_ident<T: AsRef<str>>(choices: &[T]) -> Result<#wrapper_name, crate::error::Error> {
            use crate::crypto::CryptoAlgName;
            for client_alg in choices {
                #(#match_list)*
            }

            return Err(#error_value);
        }
    }
    .into())
}
