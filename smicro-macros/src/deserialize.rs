use proc_macro::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt};
use quote::{quote, quote_spanned};
use syn::{
    parse, parse::Parser, punctuated::Punctuated, spanned::Spanned, Attribute, Expr, ExprLit,
    Fields, GenericParam, Ident, ItemStruct, LifetimeParam, Lit, Meta, Token, Type,
};

struct Field<'a> {
    name: &'a Ident,
    ty: &'a Type,
    args: FieldArgs,
    attrs: Vec<&'a Attribute>,
}

struct FieldArgs {
    optional: bool,
    vec: bool,
    default_deserialize: bool,
    parser: Option<Expr>,
}

impl Default for FieldArgs {
    fn default() -> Self {
        Self {
            optional: false,
            default_deserialize: true,
            vec: false,
            parser: None,
        }
    }
}

fn parse_field_args(input: TokenStream) -> Result<FieldArgs, Diagnostic> {
    let mut res = FieldArgs::default();
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
                            res.optional = boolean.value;
                        } else {
                            return Err(namevalue.span().error("Expected a boolean"));
                        }
                    }
                    "vec" => {
                        if let Expr::Lit(ExprLit {
                            lit: Lit::Bool(boolean),
                            ..
                        }) = &namevalue.value
                        {
                            res.vec = boolean.value;
                        } else {
                            return Err(namevalue.span().error("Expected a boolean"));
                        }
                    }
                    "default_deserialize" => {
                        if let Expr::Lit(ExprLit {
                            lit: Lit::Bool(boolean),
                            ..
                        }) = &namevalue.value
                        {
                            res.default_deserialize = boolean.value;
                        } else {
                            return Err(namevalue.span().error("Expected a boolean"));
                        }
                    }
                    "parser" => {
                        res.parser = Some(namevalue.value.clone());
                    }
                    _ => return Err(arg.span().error("Unsupported macro parameter")),
                }
            }
            _ => return Err(arg.span().error("Unrecognized argument")),
        }
    }

    if !res.default_deserialize && res.parser.is_none() {
        return Err(attribute_args.span().error("A parser must be provided"));
    }

    Ok(res)
}

fn get_fields(fields: &Fields) -> Result<Vec<Field>, Diagnostic> {
    let mut res = Vec::with_capacity(fields.len());

    for field in fields.iter() {
        let mut args = Some(FieldArgs::default());
        let mut additional_attributes = Vec::new();
        for attr in field.attrs.iter() {
            match &attr.meta {
                Meta::Path(path) if path.get_ident().is_some() => {
                    if path.get_ident().unwrap() == "field" {
                        return Err(path.span().error("Please supply required arguments"));
                    }
                }
                Meta::List(list) if list.path.get_ident().is_some() => {
                    if list.path.get_ident().unwrap() == "field" {
                        args = match parse_field_args(list.tokens.clone().into()) {
                            Ok(x) => Some(x),
                            Err(_) => {
                                return Err(list
                                    .tokens
                                    .span()
                                    .error("Could not parse the field attributes"))
                            }
                        };

                        continue;
                    }
                }
                _ => {}
            };
            additional_attributes.push(attr);
        }

        res.push(Field {
            name: field.ident.as_ref().expect("Should be a named struct"),
            ty: &field.ty,
            args: args.unwrap(),
            attrs: additional_attributes,
        });
    }

    Ok(res)
}

pub(crate) fn declare_deserializable_struct_inner(
    item: TokenStream,
) -> Result<TokenStream, Diagnostic> {
    let ast: ItemStruct = parse(item.clone()).unwrap();
    let name = &ast.ident;
    let generics = &ast.generics;

    let fields = get_fields(&ast.fields)?;

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
            let field_type = &field.ty;
            let parser_call = if let Some(parser) = &field.args.parser {
                quote!(#parser.parse)
            } else {
                assert!(field.args.default_deserialize);
                quote!(<#field_type>::deserialize)
            };

            let mut parsing_code = quote!(
                let (next_data, new_field_value) = #parser_call(remaining_data)?;
                remaining_data = next_data;
            );

            if field.args.vec {
                parsing_code = quote!(
                    let mut iter = nom::combinator::iterator(remaining_data, #parser_call);
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
        impl<'a  , #fake_lifetime> DeserializePacket<'a> for #name<#fake_lifetime> where Self: Sized  #lifetime_constraint {
            fn deserialize(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, ::smicro_types::error::ParsingError>  {
                log::trace!("Deserializing {}", std::any::type_name::<Self>());
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

    Ok(quote! {
        #(#attrs) * #vis struct #name #generics {
            #(#new_fields)*
        }

        #deserialize_impl
    }
    .into())
}
