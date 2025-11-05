use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{braced, parse_macro_input, Attribute, Ident, ItemMod, LitStr, Result, Token, Visibility};

pub fn expand_credential_module(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as CredentialArgs);
    let module = parse_macro_input!(item as ItemMod);

    match build_credential_module(&args, module) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

struct CredentialArgs {
    resource: Option<LitStr>,
    model: LitStr,
    builder: LitStr,
    requests: LitStr,
    operations: Option<LitStr>,
    shared: Option<TokenStream2>,
    exports: Option<TokenStream2>,
}

impl Parse for CredentialArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut resource = None;
        let mut model = None;
        let mut builder = None;
        let mut requests = None;
        let mut operations = None;
        let mut shared = None;
        let mut exports = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match ident.to_string().as_str() {
                "resource" => {
                    resource = Some(input.parse()?);
                }
                "model" => {
                    model = Some(input.parse()?);
                }
                "builder" => {
                    builder = Some(input.parse()?);
                }
                "requests" => {
                    requests = Some(input.parse()?);
                }
                "operations" => {
                    operations = Some(input.parse()?);
                }
                "shared" => {
                    let content;
                    syn::braced!(content in input);
                    shared = Some(content.parse()?);
                }
                "exports" => {
                    let content;
                    syn::braced!(content in input);
                    exports = Some(content.parse()?);
                }
                other => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!("unknown argument `{}`", other),
                    ));
                }
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        let model = model.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `model` argument")
        })?;
        let builder = builder.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `builder` argument")
        })?;
        let requests = requests.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `requests` argument")
        })?;

        Ok(Self {
            resource,
            model,
            builder,
            requests,
            operations,
            shared,
            exports,
        })
    }
}

fn build_credential_module(args: &CredentialArgs, mut module: ItemMod) -> Result<TokenStream2> {
    let ItemMod {
        attrs,
        vis,
        ident,
        ..
    } = module;

    let resource_const = args.resource.as_ref().map(|lit| {
        let value = lit.value();
        quote! {
            pub const RESOURCE_TYPE: &str = #value;
        }
    });

    let shared = args.shared.clone().unwrap_or_default();
    let exports = args.exports.clone().unwrap_or_default();

    let model_path = &args.model;
    let builder_path = &args.builder;
    let requests_path = &args.requests;
    let operations_block = args.operations.as_ref().map(|path| {
        quote! {
            pub mod operations {
                include!(#path);
            }
        }
    });

    Ok(quote! {
        #(#attrs)*
        #vis mod #ident {
            #shared

            pub mod model {
                include!(#model_path);
            }

            pub mod builder {
                include!(#builder_path);
            }

            pub mod requests {
                include!(#requests_path);
            }

            #operations_block

            #resource_const

            #exports
        }
    })
}
