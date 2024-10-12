use proc_macro::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::quote;
use syn::{
    parse, parse::Parser, punctuated::Punctuated, spanned::Spanned, AngleBracketedGenericArguments,
    Expr, ExprLit, ExprPath, FnArg, GenericArgument, Ident, ItemTrait, Lit, Meta, MetaList, Pat,
    PatType, Path, PathArguments, Token, TraitItem, Type, TypePath,
};

struct WrapperDeclarationArgs {
    name: Ident,
    serializable: bool,
    deserializable: bool,
}

fn parse_wrapper_declaration_args(
    input: TokenStream,
) -> Result<WrapperDeclarationArgs, Diagnostic> {
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let attribute_args = parser.parse(input.clone())?;

    let mut name = None;
    let mut serializable = false;
    let mut deserializable = false;

    for arg in attribute_args.iter() {
        if let Meta::NameValue(namevalue) = arg {
            let key = namevalue
                .path
                .get_ident()
                .expect("the macro parameter is not an ident?")
                .to_string();
            match key.as_str() {
                "name" => {
                    if let Expr::Path(ExprPath { path, .. }) = &namevalue.value {
                        name = Some(
                            path.get_ident()
                                .expect("Got a complex path, expected a single ident"),
                        );
                    } else {
                        return Err(namevalue
                            .value
                            .span()
                            .error(format!("Invalid type for the key {}", key)));
                    }
                }
                "serializable" => {
                    if let Expr::Lit(ExprLit {
                        lit: Lit::Bool(boolean),
                        ..
                    }) = &namevalue.value
                    {
                        serializable = boolean.value;
                    } else {
                        return Err(namevalue.span().error("Expected a boolean"));
                    }
                }
                "deserializable" => {
                    if let Expr::Lit(ExprLit {
                        lit: Lit::Bool(boolean),
                        ..
                    }) = &namevalue.value
                    {
                        deserializable = boolean.value;
                    } else {
                        return Err(namevalue.span().error("Expected a boolean"));
                    }
                }
                _ => return Err(arg.span().error("Unsupported macro parameter")),
            }
        } else {
            return Err(arg.span().error("Unrecognized argument"));
        }
    }

    if name.is_none() {
        return Err(attribute_args.span().error("Missing 'name' argument"));
    }

    Ok(WrapperDeclarationArgs {
        name: name.unwrap().clone(),
        serializable,
        deserializable,
    })
}

pub(crate) fn create_wrapper_enum_implementing_trait_inner(
    attrs: TokenStream,
    item: TokenStream,
) -> Result<TokenStream, Diagnostic> {
    let mut ast: ItemTrait = parse(item)?;
    let args = parse_wrapper_declaration_args(attrs)?;

    let mut implementors = Vec::new();
    let mut attrs = Vec::new();
    for attr in &ast.attrs {
        if let Meta::List(MetaList { path, tokens, .. }) = &attr.meta {
            if path.segments.last().map(|s| s.ident.to_string())
                == Some(String::from("implementors"))
            {
                let res = match (<Punctuated<Path, Token![,]>>::parse_terminated)
                    .parse2(tokens.clone())
                {
                    Ok(res) => res,
                    Err(_) => return Err(tokens.span().error("Invalid list of paths")),
                };
                for v in res {
                    implementors.push(v);
                }
                break;
            }
        }
        attrs.push(attr.clone());
    }
    if implementors.is_empty() {
        return Err(ast
            .span()
            .error("Missing implementors attribute or no implementors"));
    }

    let implementors_ident: Vec<Ident> = implementors
        .iter()
        .map(|x| {
            let last = x.segments.last().unwrap();

            let mut name = last.ident.to_string();

            fn recurse_path(name: &mut String, arguments: &PathArguments) {
                if let PathArguments::AngleBracketed(AngleBracketedGenericArguments {
                    args, ..
                }) = arguments
                {
                    for arg in args {
                        if let GenericArgument::Type(Type::Path(TypePath { path, .. })) = arg {
                            let last = path.segments.last().unwrap();
                            name.push_str(&last.ident.to_string());
                            recurse_path(name, &last.arguments);
                        }
                    }
                }
            }
            recurse_path(&mut name, &last.arguments);

            Ident::new(&name, last.span())
        })
        .collect();

    let mut new_items = Vec::new();
    for item in &ast.items {
        let f = match item {
            TraitItem::Fn(f) => f,
            _ => {
                return Err(item
                    .span()
                    .error("Invalid type of items, only methods are supported"))
            }
        };
        let attrs = f.attrs.clone();
        let sig = f.sig.clone();
        let f_name = sig.ident.clone();
        let mut arg_names = Vec::new();
        for input in &sig.inputs {
            match input {
                FnArg::Receiver(_) => {}
                FnArg::Typed(PatType { pat, .. }) => match **pat {
                    Pat::Ident(ref i) => arg_names.push(i),
                    _ => return Err(pat.span().error("Invalid object for typed function input")),
                },
            }
        }
        let call_part = quote! {
            v.#f_name(#(#arg_names),*)
        };
        new_items.push(quote! {
            #(#attrs)* #sig {
                match self {
                    #(
                        Self::#implementors_ident(v) => #call_part
                    ),*
                }
            }
        });
    }

    let trait_name = &ast.ident;
    let enum_name = &args.name;

    let name_impl = quote!(
        impl #enum_name {
            pub fn name(&self) -> &'static str {
                use crate::crypto::CryptoAlgName;
                match self {
                    #(Self::#implementors_ident(v) => v.name()),*
                }
            }
        }
    );

    let deserialize_impl = if args.deserializable {
        quote!(
            impl<'a> smicro_types::deserialize::DeserializePacket<'a> for #enum_name {
                fn deserialize(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, smicro_types::error::ParsingError> {
                    use smicro_types::deserialize::DeserializePacket;
                    use crate::crypto::CryptoAlgName;
                    log::trace!("Deserializing {}", std::any::type_name::<Self>());
                    let (input, name) = smicro_types::sftp::deserialize::parse_slice(input)?;

                    #(
                        if name == <#implementors>::NAME.as_bytes() {
                            return #implementors::deserialize(input).map(|(input, v)| (input, Self::#implementors_ident(v)));
                        }
                    )*

                    Err(nom::Err::Failure(smicro_types::error::ParsingError::InvalidEnumVariant))
                }
            }
        )
    } else {
        quote!()
    };

    let serialize_impl = if args.serializable {
        quote!(
            impl smicro_types::serialize::SerializePacket for #enum_name {
                fn get_size(&self) -> usize {
                    use smicro_types::serialize::SerializePacket;
                    self.name().get_size() +
                    match self {
                        #(Self::#implementors_ident(e) => e.get_size()),*
                    }
                }

                fn serialize<W: std::io::Write>(&self, mut writer: W) -> Result<(), std::io::Error> {
                    use smicro_types::serialize::SerializePacket;
                    self.name().serialize(&mut writer)?;
                    match self {
                        #(Self::#implementors_ident(e) => e.serialize(&mut writer)),*
                    }
                }
            }
        )
    } else {
        quote!()
    };

    ast.attrs = attrs;

    Ok(quote! {
        #ast

        #[derive(Clone, Debug)]
        pub enum #enum_name {
            #(#implementors_ident(#implementors)),*
        }

        #name_impl

        #deserialize_impl

        #serialize_impl

        impl #trait_name for #enum_name {
            #(#new_items)*
        }
    }
    .into())
}
