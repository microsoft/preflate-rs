/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use std::{collections::BTreeMap, env, fs, path::PathBuf};

use quote::{format_ident, quote};
use syn::{Fields, Ident, Item, Type, parse_quote};

struct Declaration {
    module: Ident,
    item: Item,
}

fn fields(item: &Item) -> Vec<&syn::Field> {
    match item {
        Item::Struct(value) => value.fields.iter().collect(),
        Item::Enum(value) => value.variants.iter().flat_map(|v| &v.fields).collect(),
        _ => unreachable!(),
    }
}

fn type_name(ty: &Type) -> &Ident {
    let Type::Path(path) = ty else {
        panic!("wire fields must use named types");
    };
    path.path
        .get_ident()
        .expect("wire fields must use unqualified type names")
}

fn collect(
    name: &str,
    available: &BTreeMap<String, Declaration>,
    selected: &mut BTreeMap<String, ()>,
) {
    if matches!(name, "bool" | "u16" | "u32") || selected.insert(name.to_owned(), ()).is_some() {
        return;
    }
    let declaration = available.get(name).expect("missing wire type declaration");
    for field in fields(&declaration.item) {
        collect(&type_name(&field.ty).to_string(), available, selected);
    }
}

fn prepare_fields(fields: &mut Fields) {
    for field in fields {
        field.attrs.clear();
        field.vis = syn::Visibility::Inherited;
        match type_name(&field.ty).to_string().as_str() {
            "u16" => field.ty = parse_quote!(super::VariableU16),
            "u32" => field.ty = parse_quote!(super::VariableU32),
            _ => {}
        }
    }
}

fn construction(target: &proc_macro2::TokenStream, fields: &Fields) -> proc_macro2::TokenStream {
    match fields {
        Fields::Named(fields) => {
            let values = fields.named.iter().map(|field| {
                let name = field.ident.as_ref().unwrap();
                if type_name(&field.ty) == "bool" {
                    quote!(#name)
                } else {
                    quote!(#name: #name.into())
                }
            });
            quote!(#target { #(#values),* })
        }
        Fields::Unnamed(fields) => {
            let values = fields.unnamed.iter().enumerate().map(|(i, field)| {
                let name = format_ident!("field_{i}");
                converted(quote!(#name), &field.ty)
            });
            quote!(#target(#(#values),*))
        }
        Fields::Unit => quote!(#target),
    }
}

fn converted(value: proc_macro2::TokenStream, ty: &Type) -> proc_macro2::TokenStream {
    if type_name(ty) == "bool" {
        value
    } else {
        quote!(#value.into())
    }
}

fn conversion(
    source: &proc_macro2::TokenStream,
    target: &proc_macro2::TokenStream,
    item: &Item,
) -> proc_macro2::TokenStream {
    match item {
        Item::Struct(value) => {
            let Fields::Named(fields) = &value.fields else {
                panic!("wire structs must have named fields");
            };
            let names: Vec<_> = fields
                .named
                .iter()
                .map(|f| f.ident.as_ref().unwrap())
                .collect();
            let values = fields
                .named
                .iter()
                .zip(&names)
                .map(|(field, name)| converted(quote!(value.#name), &field.ty));
            quote!(#target { #(#names: #values),* })
        }
        Item::Enum(value) => {
            let arms = value.variants.iter().map(|variant| {
                let name = &variant.ident;
                let pattern = match &variant.fields {
                    Fields::Named(fields) => {
                        let names = fields.named.iter().map(|f| f.ident.as_ref().unwrap());
                        quote!(#source::#name { #(#names),* })
                    }
                    Fields::Unnamed(fields) => {
                        let names = (0..fields.unnamed.len()).map(|i| format_ident!("field_{i}"));
                        quote!(#source::#name(#(#names),*))
                    }
                    Fields::Unit => quote!(#source::#name),
                };
                let constructed = construction(&quote!(#target::#name), &variant.fields);
                quote!(#pattern => #constructed)
            });
            quote!(match value { #(#arms),* })
        }
        _ => unreachable!(),
    }
}

fn main() {
    let mut available = BTreeMap::new();
    for module in ["parameters", "reconstruction_parameters"] {
        let path = PathBuf::from("src").join(format!("{module}.rs"));
        println!("cargo:rerun-if-changed={}", path.display());
        let source = fs::read_to_string(path).expect("read parameter declarations");
        for item in syn::parse_file(&source)
            .expect("parse parameter declarations")
            .items
        {
            let name = match &item {
                Item::Struct(value) => value.ident.to_string(),
                Item::Enum(value) => value.ident.to_string(),
                _ => continue,
            };
            assert!(
                available
                    .insert(
                        name,
                        Declaration {
                            module: format_ident!("{module}"),
                            item,
                        }
                    )
                    .is_none(),
                "duplicate parameter type"
            );
        }
    }
    let mut selected = BTreeMap::new();
    collect("ReconstructionParameters", &available, &mut selected);
    let mut generated = Vec::new();
    for name in selected.keys() {
        let declaration = &available[name];
        let name = format_ident!("{name}");
        let module = &declaration.module;
        let runtime = quote!(crate::#module::#name);
        let to_wire = conversion(&runtime, &quote!(Self), &declaration.item);
        let to_runtime = conversion(&quote!(#name), &quote!(Self), &declaration.item);
        let mut wire = declaration.item.clone();
        let attributes = match &mut wire {
            Item::Struct(value) => {
                value.vis = parse_quote!(pub(super));
                prepare_fields(&mut value.fields);
                &mut value.attrs
            }
            Item::Enum(value) => {
                value.vis = parse_quote!(pub(super));
                for variant in &mut value.variants {
                    variant.attrs.clear();
                    variant.discriminant = None;
                    prepare_fields(&mut variant.fields);
                }
                &mut value.attrs
            }
            _ => unreachable!(),
        };
        *attributes = vec![parse_quote!(
            #[derive(Debug, Copy, Clone, PartialEq, naia_serde::SerdeInternal)]
        )];
        generated.push(quote! {
            #wire
            impl From<#runtime> for #name {
                fn from(value: #runtime) -> Self { #to_wire }
            }
            impl From<#name> for #runtime {
                fn from(value: #name) -> Self { #to_runtime }
            }
        });
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    fs::write(
        output.join("parameter_wire.rs"),
        quote!(#(#generated)*).to_string(),
    )
    .expect("write generated parameter codec");
}
