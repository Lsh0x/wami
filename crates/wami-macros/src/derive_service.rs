use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{parse_macro_input, parse_quote, Attribute, Data, DeriveInput, Ident, Result, Type};

pub fn expand(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match expand_inner(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn expand_inner(input: DeriveInput) -> Result<proc_macro2::TokenStream> {
    let ident = input.ident;

    if !matches!(input.data, Data::Struct(_)) {
        return Err(syn::Error::new_spanned(
            ident,
            "#[derive(Service)] can only be applied to structs",
        ));
    }

    let args = parse_args(&input.attrs)?;

    let delegate = args.delegate;
    let request_ty = args.request.ok_or_else(|| {
        syn::Error::new_spanned(&ident, "`request` must be specified in #[service(...)]")
    })?;
    let response_ty = args.response.ok_or_else(|| {
        syn::Error::new_spanned(&ident, "`response` must be specified in #[service(...)]")
    })?;
    let error_ty = args
        .error
        .unwrap_or_else(|| parse_quote!(::wami_core::error::AmiError));

    Ok(quote! {
        impl ::wami_core::traits::Service for #ident {
            type Request = #request_ty;
            type Response = #response_ty;
            type Error = #error_ty;

            fn handle(&self, req: Self::Request) -> std::result::Result<Self::Response, Self::Error> {
                self.#delegate.handle(req)
            }
        }
    })
}

struct ServiceArgs {
    delegate: Ident,
    request: Option<Type>,
    response: Option<Type>,
    error: Option<Type>,
}

impl Default for ServiceArgs {
    fn default() -> Self {
        Self {
            delegate: parse_quote!(inner),
            request: None,
            response: None,
            error: None,
        }
    }
}

fn parse_args(attrs: &[Attribute]) -> Result<ServiceArgs> {
    let mut args = ServiceArgs::default();

    for attr in attrs {
        if !attr.path().is_ident("service") {
            continue;
        }

        let parsed = attr.parse_args::<ServiceAttrList>()?;
        for item in parsed.items {
            match item.key.to_string().as_str() {
                "delegate" => args.delegate = item.value.parse_delegate()?,
                "request" => args.request = Some(item.value.parse_type()?),
                "response" => args.response = Some(item.value.parse_type()?),
                "error" => args.error = Some(item.value.parse_type()?),
                other => {
                    return Err(syn::Error::new_spanned(
                        item.key,
                        format!("unknown #[service] argument `{}`", other),
                    ));
                }
            }
        }
    }

    Ok(args)
}

struct ServiceAttrList {
    items: Vec<ServiceAttrItem>,
}

struct ServiceAttrItem {
    key: Ident,
    value: ServiceAttrValue,
}

enum ServiceAttrValue {
    Ident(Ident),
    Type(Box<Type>),
}

impl ServiceAttrValue {
    fn parse_delegate(self) -> Result<Ident> {
        match self {
            ServiceAttrValue::Ident(ident) => Ok(ident),
            ServiceAttrValue::Type(_) => Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "delegate must be an identifier",
            )),
        }
    }

    fn parse_type(self) -> Result<Type> {
        match self {
            ServiceAttrValue::Ident(ident) => Ok(parse_quote!(#ident)),
            ServiceAttrValue::Type(ty) => Ok(*ty),
        }
    }
}

impl Parse for ServiceAttrList {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut items = Vec::new();

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<syn::Token![=]>()?;

            let value = if input.peek(syn::Ident) && !input.peek2(syn::Token![::]) {
                let ident: Ident = input.parse()?;
                ServiceAttrValue::Ident(ident)
            } else {
                ServiceAttrValue::Type(Box::new(input.parse()?))
            };

            items.push(ServiceAttrItem { key, value });

            if input.peek(syn::Token![,]) {
                input.parse::<syn::Token![,]>()?;
            } else {
                break;
            }
        }

        Ok(ServiceAttrList { items })
    }
}
