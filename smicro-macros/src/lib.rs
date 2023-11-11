use proc_macro::{Span, TokenStream};
use proc_macro2::Ident;
use proc_macro_error::{abort, proc_macro_error};
use quote::{quote, quote_spanned, ToTokens};

use syn::{
    parse, parse::Parser, punctuated::Punctuated, spanned::Spanned, Attribute, Expr, ExprLit,
    ExprPath, Fields, GenericParam, ItemEnum, ItemStruct, LifetimeParam, Lit, Meta, Token, Type,
};

struct PacketArgs {
    ty: ExprPath,
}

fn parse_packet_args(input: TokenStream) -> PacketArgs {
    let mut ty = None;

    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let attribute_args = match parser.parse(input.clone()) {
        Ok(x) => x,
        Err(_) => abort!(Span::call_site(), "Couldn't parse the fields of the macro"),
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
                        abort!(Span::call_site(), "Invalid parameter for the value {}", key);
                    }
                }
                _ => abort!(arg.span(), "Unsupported macro parameter"),
            }
        } else {
            abort!(arg.span(), "Unrecognized argument");
        }
    }

    if ty.is_none() {
        abort!(attribute_args.span(), "Missing type argument");
    }

    PacketArgs {
        ty: ty.unwrap().clone(),
    }
}

#[proc_macro_attribute]
pub fn gen_serialize_impl(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemStruct = parse(item.clone()).unwrap();
    let name = ast.ident;

    let mut fields = Vec::with_capacity(ast.fields.len());

    for field in ast.fields.iter() {
        fields.push(field.ident.as_ref().expect("Should be a names struct"));
    }

    let write_entries = fields.iter().map(|field| {
        quote!(
            self.#field.serialize(&mut output)?;
        )
    });
    let size_entries = fields.iter().map(|field| {
        quote!(
            size += &self.#field.get_size();
        )
    });
    let serialize_impl = quote!(
        impl SerializeForSftp for #name {
            fn get_size(&self) -> usize {
                let mut size = 0;
                #(#size_entries)*
                size
            }

            fn serialize<W: std::io::Write>(&self, mut output: W) -> Result<(), std::io::Error> {
                #(#write_entries) *
                Ok(())
            }
        }
    );

    let mut output = item.into();
    quote! {
        #serialize_impl
    }
    .to_tokens(&mut output);

    output.into()
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn declare_response_packet(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemStruct = parse(item.clone()).unwrap();
    let name = &ast.ident;

    let args = parse_packet_args(attrs);

    let ty = args.ty;

    quote! {
        #[derive(Debug)]
        #[smicro_macros::gen_serialize_impl]
        #ast

        impl crate::response::ResponsePacket for #name {
            fn get_type(&self) -> ResponseType {
                #ty
            }
        }
    }
    .into()
}

struct Field<'a> {
    name: &'a Ident,
    ty: &'a Type,
    args: FieldArgs,
    attrs: Vec<&'a Attribute>,
}

struct FieldArgs {
    optional: bool,
    vec: bool,
    parser: Expr,
}

fn parse_field_args(input: TokenStream) -> syn::Result<FieldArgs> {
    let mut optional = false;
    let mut vec = false;
    let mut parser = None;
    let attribute_args = Punctuated::<Meta, Token![,]>::parse_terminated.parse(input)?;
    for arg in attribute_args.iter() {
        match arg {
            Meta::NameValue(namevalue) => {
                let key = namevalue
                    .path
                    .get_ident()
                    .expect("the macro parameter is not an ident?")
                    .to_string();
                match key.as_str() {
                    "optional" => {
                        if let Expr::Lit(ExprLit {
                            lit: Lit::Bool(boolean),
                            ..
                        }) = &namevalue.value
                        {
                            optional = boolean.value;
                        } else {
                            abort!(&namevalue.span(), "Expected a boolean");
                        }
                    }
                    "vec" => {
                        if let Expr::Lit(ExprLit {
                            lit: Lit::Bool(boolean),
                            ..
                        }) = &namevalue.value
                        {
                            vec = boolean.value;
                        } else {
                            abort!(&namevalue.span(), "Expected a boolean");
                        }
                    }
                    "parser" => {
                        parser = Some(namevalue.value.clone());
                    }
                    _ => abort!(arg.span(), "Unsupported macro parameter"),
                }
            }
            _ => abort!(arg.span(), "Unrecognized argument"),
        }
    }

    if parser.is_none() {
        abort!(attribute_args.span(), "A parser must be provided");
    }

    Ok(FieldArgs {
        optional,
        vec,
        parser: parser.unwrap(),
    })
}

fn get_fields(fields: &Fields) -> Vec<Field> {
    let mut res = Vec::with_capacity(fields.len());

    for field in fields.iter() {
        let mut args = None;
        let mut additional_attributes = Vec::new();
        for attr in field.attrs.iter() {
            match &attr.meta {
                Meta::Path(path) if path.get_ident().is_some() => {
                    if path.get_ident().unwrap() == "field" {
                        abort!(path.span(), "Please supply required arguments");
                    }
                }
                Meta::List(list) if list.path.get_ident().is_some() => {
                    if list.path.get_ident().unwrap() == "field" {
                        args = match parse_field_args(list.tokens.clone().into()) {
                            Ok(x) => Some(x),
                            Err(_) => {
                                abort!(list.tokens.span(), "Could not parse the field attributes")
                            }
                        };

                        continue;
                    }
                }
                _ => {}
            };
            additional_attributes.push(attr);
        }

        if args.is_none() {
            abort!(field.span(), "Missing a required #[field] argument");
        }

        res.push(Field {
            name: field.ident.as_ref().expect("Should be a names struct"),
            ty: &field.ty,
            args: args.unwrap(),
            attrs: additional_attributes,
        });
    }

    res
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn declare_deserializable_struct(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemStruct = parse(item.clone()).unwrap();
    let name = &ast.ident;
    let generics = &ast.generics;

    let fields = get_fields(&ast.fields);

    let new_field_idents: Vec<Ident> = fields
        .iter()
        .map(|field| {
            Ident::new(
                &format!("__internal_field_{}", field.name),
                field.name.span(),
            )
        })
        .collect();
    let deserialize_and_assign_fields: Vec<_> = fields
        .iter()
        .zip(new_field_idents)
        .map(|(field, new_field_ident)| {
            let field_name = &field.name;
            let parser = &field.args.parser;

            let mut parsing_code = quote!(
                let (next_data, new_field_value) = #parser.parse(remaining_data)?;
                remaining_data = next_data;
            );

            if field.args.vec {
                parsing_code = quote!(
                    let mut iter = nom::combinator::iterator(remaining_data, #parser);
                    let new_field_value = iter.collect::<Vec<_>>();
                    let (next_data, _) = iter.finish()?;
                    remaining_data = next_data;
                );
            }
            parsing_code = if field.args.optional {
                quote!(
                    #[allow(non_snake_case)]
                    let mut #new_field_ident = None;
                    if remaining_data.len() > 0 {
                        #parsing_code
                        #new_field_ident = Some(new_field_value);
                    }
                )
            } else {
                quote!(
                    #parsing_code
                    #[allow(non_snake_case)]
                    let #new_field_ident = new_field_value;
                )
            };

            let assignment_code = quote!( #field_name: #new_field_ident );

            (parsing_code, assignment_code)
        })
        .collect();

    let deserialize_fields = deserialize_and_assign_fields
        .iter()
        .map(|(parsing_code, _)| parsing_code);
    let assign_fields = deserialize_and_assign_fields
        .iter()
        .map(|(_, assignment_code)| assignment_code);

    let mut fake_lifetime = quote!();
    let mut lifetime_constraint = quote!();
    for param in &generics.params {
        if let GenericParam::Lifetime(LifetimeParam { .. }) = param {
            fake_lifetime = quote!( 'fakelif );
            lifetime_constraint = quote!( , 'a: 'fakelif );
        }
    }
    let deserialize_impl = quote!(
        impl<'a  , #fake_lifetime> DeserializeSftp<'a> for #name<#fake_lifetime> where Self: Sized  #lifetime_constraint {
            fn deserialize(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, crate::error::ParsingError>  {
                let mut remaining_data = input;
                #(#deserialize_fields) *

                Ok((remaining_data, Self {
                    #(#assign_fields),*
                }))
            }
        }
    );

    let vis = &ast.vis;
    let attrs = ast.attrs;
    let new_fields = fields.iter().map(|field| {
        let name = field.name;
        let ty = field.ty;
        let ty = if field.args.optional {
            quote!( Option<#ty> )
        } else {
            quote!( #ty )
        };
        let attrs = &field.attrs;
        quote_spanned!(name.span() => #(#attrs) * pub #name: #ty, )
    });

    quote! {
        #[derive(Debug)]
        #(#attrs) * #vis struct #name #generics {
            #(#new_fields)*
        }

        #deserialize_impl
    }
    .into()
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn serialize_variants_in_enum(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemEnum = parse(item.clone()).unwrap();
    let name = ast.ident;

    let mut variants = Vec::with_capacity(ast.variants.len());

    for variant in ast.variants.iter() {
        if let syn::Fields::Unnamed(inner) = &variant.fields {
            if inner.unnamed.len() != 1 {
                abort!(
                    inner.unnamed,
                    "Invalid number of fields in this variant: should be 1"
                );
            }
            variants.push(&variant.ident);
        } else {
            abort!(variant.fields, "Invalid content for the variant");
        }
    }

    let mut output = item.into();
    quote! {
        impl SerializeForSftp for #name {
            fn get_size(&self) -> usize {
                match self {
                    #(#name::#variants(val) => val.get_size()),*
                }
            }

            fn serialize<W: std::io::Write>(&self, mut output: W) -> Result<(), std::io::Error> {
                match self {
                    #(#name::#variants(val) => val.serialize(output)),*
                }
            }
        }
    }
    .to_tokens(&mut output);

    output.into()
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn implement_responsepacket_on_enum(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemEnum = parse(item.clone()).unwrap();
    let name = &ast.ident;

    let mut variants = Vec::with_capacity(ast.variants.len());

    for variant in ast.variants.iter() {
        if let syn::Fields::Unnamed(inner) = &variant.fields {
            if inner.unnamed.len() != 1 {
                abort!(
                    inner.unnamed,
                    "Invalid number of fields in this variant: should be 1"
                );
            }
            variants.push(&variant.ident);
        } else {
            abort!(variant.fields, "Invalid content for the variant");
        }
    }

    quote! {
        #ast

        impl ResponsePacket for #name {
            fn get_type(&self) -> crate::response::ResponseType {
                match self {
                    #(#name::#variants(val) => val.get_type()),*
                }
            }
        }
    }
    .into()
}
