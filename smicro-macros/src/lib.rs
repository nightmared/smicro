use proc_macro::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::{quote, ToTokens};

use syn::{parse, Ident};
use syn::{spanned::Spanned, GenericParam, ItemEnum, ItemStruct, LifetimeParam};

mod crypto_arg;
mod deserialize;
mod response;
mod session_states;
mod wrapper_enum;

#[proc_macro_attribute]
pub fn gen_serialize_impl(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemStruct = parse(item.clone()).unwrap();
    let name = ast.ident;

    let mut fields = Vec::with_capacity(ast.fields.len());

    for field in ast.fields.iter() {
        fields.push(field.ident.as_ref().expect("Should be a named struct"));
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
    let generics = ast.generics;
    let serialize_impl = quote!(
        impl #generics SerializePacket for #name #generics {
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

#[proc_macro_attribute]
pub fn declare_response_packet(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match response::declare_response_packet_inner(attrs, item) {
        Ok(tokens) => tokens.into(),
        Err(diag) => diag.emit_as_item_tokens().into(),
    }
}

#[proc_macro_attribute]
pub fn declare_deserializable_struct(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    match deserialize::declare_deserializable_struct_inner(item) {
        Ok(tokens) => tokens.into(),
        Err(diag) => diag.emit_as_item_tokens().into(),
    }
}

fn get_variants_in_enum(ast: &ItemEnum) -> Result<Vec<&Ident>, Diagnostic> {
    let mut variants = Vec::with_capacity(ast.variants.len());

    for variant in ast.variants.iter() {
        if let syn::Fields::Unnamed(inner) = &variant.fields {
            if inner.unnamed.len() != 1 {
                return Err(inner
                    .unnamed
                    .span()
                    .error("Invalid number of fields in this variant: should be 1"));
            }
            variants.push(&variant.ident);
        } else {
            return Err(variant
                .fields
                .span()
                .error("Invalid content for the variant"));
        }
    }

    Ok(variants)
}

#[proc_macro_attribute]
pub fn serialize_variants_in_enum(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemEnum = parse(item.clone()).unwrap();
    let name = &ast.ident;
    let generics = &ast.generics;

    let variants = match get_variants_in_enum(&ast) {
        Ok(v) => v,
        Err(e) => return e.emit_as_item_tokens().into(),
    };

    let mut output = item.into();
    quote! {
        impl #generics SerializePacket for #name #generics {
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

#[proc_macro_attribute]
pub fn implement_responsepacket_on_enum(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemEnum = parse(item.clone()).unwrap();
    let name = &ast.ident;
    let generics = &ast.generics;

    let variants = match get_variants_in_enum(&ast) {
        Ok(v) => v,
        Err(e) => return e.emit_as_item_tokens().into(),
    };

    quote! {
        #ast

        impl #generics ResponsePacket for #name #generics {
            fn get_type(&self) -> crate::response::ResponseType {
                match self {
                    #(#name::#variants(val) => val.get_type()),*
                }
            }
        }
    }
    .into()
}

#[proc_macro_attribute]
pub fn declare_message(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemStruct = parse(item).expect("Not a function");
    let message_type: Ident = parse(attrs).expect("Not an identifier");
    let name = &ast.ident;

    let mut lifetime = quote!();
    for param in &ast.generics.params {
        if let GenericParam::Lifetime(LifetimeParam { .. }) = param {
            lifetime = quote!( 'a );
        }
    }

    quote! {
        #[derive(Debug)]
        #[::smicro_macros::gen_serialize_impl]
        #ast

        impl<'a> crate::messages::Message<'a> for #name<#lifetime> {
            fn get_message_type() -> MessageType {
                ::smicro_types::ssh::types::MessageType::#message_type
            }
        }
    }
    .into()
}

#[proc_macro_attribute]
pub fn declare_session_state(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match session_states::declare_session_state_inner(attrs, item) {
        Ok(tokens) => tokens.into(),
        Err(diag) => diag.emit_as_item_tokens().into(),
    }
}

#[proc_macro_attribute]
pub fn create_wrapper_enum_implementing_trait(
    attrs: TokenStream,
    item: TokenStream,
) -> TokenStream {
    match wrapper_enum::create_wrapper_enum_implementing_trait_inner(attrs, item) {
        Ok(tokens) => tokens.into(),
        Err(diag) => diag.emit_as_item_tokens().into(),
    }
}

#[proc_macro_attribute]
pub fn declare_crypto_arg(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match crypto_arg::declare_crypto_arg_inner(attrs, item) {
        Ok(tokens) => tokens.into(),
        Err(diag) => diag.emit_as_item_tokens().into(),
    }
}

#[proc_macro_attribute]
pub fn declare_crypto_algs_list(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match crypto_arg::declare_crypto_algs_list_inner(attrs, item) {
        Ok(tokens) => tokens.into(),
        Err(diag) => diag.emit_as_item_tokens().into(),
    }
}
