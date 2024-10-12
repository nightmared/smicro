use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::quote;
use syn::{
    parse, parse::Parser, punctuated::Punctuated, spanned::Spanned, token::Comma, Expr, ExprLit,
    Fields, ItemStruct, Lit, LitBool, MetaNameValue, Token,
};

pub(crate) fn declare_session_state_inner(
    attrs: TokenStream,
    item: TokenStream,
) -> Result<TokenStream, Diagnostic> {
    let ast: ItemStruct = parse(item).expect("Not a structure");

    let parser = Punctuated::<MetaNameValue, Token![,]>::parse_terminated;
    let attribute_args = match parser.parse(attrs) {
        Ok(x) => x,
        Err(e) => {
            return Err(
                Span::call_site().error(format!("Couldn't parse the fields of the macro: {}", e))
            )
        }
    };

    let mut msg_type = None;
    let mut strict_kex = false;
    for arg in attribute_args.iter() {
        let MetaNameValue { path, value, .. } = arg;
        if path.get_ident().is_none() {
            return Err(path.span().error("Not an identifier?"));
        }
        let key = path.get_ident().unwrap().to_string();
        match key.as_str() {
            "msg_type" => {
                msg_type = Some(if let Expr::Array(_) = value {
                    quote!( #value )
                } else {
                    quote!( [#value] )
                });
            }
            "strict_kex" => {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Bool(LitBool { value, .. }),
                    ..
                }) = value
                {
                    strict_kex = *value;
                } else {
                    return Err(value.span().error("Not a boolean"));
                };
            }
            _ => return Err(arg.span().error("Unsupported macro parameter")),
        }
    }

    if msg_type.is_none() {
        return Err(attribute_args
            .span()
            .error("Missing the 'msg_type' argument"));
    }

    let struct_name = ast.ident;
    let struct_vis = ast.vis;
    let struct_attrs = ast.attrs;
    let struct_fields = match ast.fields {
        Fields::Unit => <Punctuated<syn::Field, Comma>>::new(),
        Fields::Unnamed(_) => {
            return Err(ast
                .fields
                .span()
                .error("Unnamed structures are not supported"))
        }
        Fields::Named(named_fields) => named_fields.named,
    };

    let allowed_types = msg_type.unwrap();

    let allowed_renegotiation = struct_name == "ExpectsServiceRequest"
        || struct_name == "ExpectsUserAuthRequest"
        || struct_name == "ExpectsChannelOpen"
        || struct_name == "AcceptsChannelMessages";

    let renegotiation_part = if allowed_renegotiation {
        quote!(if message_type == MessageType::KexInit {
            log::info!("Renegotiating a new key");
            let kex_sent = crate::session::KexSent {
                my_kex_message: crate::session::kex::renegotiate_kex(state, writer)?,
                next_state: crate::session::kex::SessionStateAllowedAfterKex::#struct_name(self.clone()),
            };
            return Ok((
                next,
                kex_sent.inner_process(
                    state,
                    writer,
                    message_type,
                    message_data,
                )?.into(),
            ));
        })
    } else {
        quote!()
    };

    let handle_messages_part = if !strict_kex {
        quote! (
            if message_type == MessageType::Ignore || message_type == MessageType::Debug || message_type == MessageType::Unimplemented {
                return Ok((next, SessionStateEstablished::#struct_name(self.clone()).into()));
            }

            #renegotiation_part
        )
    } else {
        quote!()
    };

    Ok(quote! {
        #(#struct_attrs)*
        #[derive(Debug, Clone)]
        #struct_vis struct #struct_name {
            #struct_fields
        }

        impl crate::session::SessionState for #struct_name {
            fn process<'a, const SIZE: usize, W: ::smicro_common::LoopingBufferWriter<SIZE>>(
                &mut self,
                state: &mut crate::state::State,
                writer: &mut W,
                input: &'a mut [u8],
            ) -> Result<(&'a [u8], crate::session::PacketProcessingDecision), crate::error::Error> {
                use ::smicro_types::{
                    deserialize::DeserializePacket,
                    ssh::types::MessageType
                };
                use crate::session::{SessionStates, SessionStateEstablished};
                let (next, packet_payload) = crate::packet::parse_packet(input, state)?;

                let (message_data, message_type) = match crate::parse_message_type(packet_payload) {
                    Ok(x) => x,
                    Err(_) => {
                        crate::packet::write_message(&mut state.sender, writer, &crate::messages::MessageUnimplemented { sequence_number: state.receiver.sequence_number.0 })?;
                        return Ok((next, SessionStateEstablished::#struct_name(self.clone()).into()));
                    }
                };

                if message_type == MessageType::Disconnect {
                    return Ok((next, crate::session::PacketProcessingDecision::PeerTriggeredDisconnection));
                }

                #handle_messages_part

                if !#allowed_types.contains(&message_type) {
                    return Err(crate::error::Error::DisallowedMessageType(message_type));
                }

                let res = self.inner_process(state, writer, message_type, message_data)?;
                Ok((next, res))
            }
        }
    }
    .into())
}
