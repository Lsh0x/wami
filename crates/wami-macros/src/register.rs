use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{parse_macro_input, Ident, Result, Token};

pub fn expand(input: TokenStream) -> TokenStream {
    let services = parse_macro_input!(input as ServiceList);

    match generate(&services.idents) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn generate(idents: &[Ident]) -> Result<proc_macro2::TokenStream> {
    if idents.is_empty() {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "register_services! expects at least one service identifier",
        ));
    }

    let registrations = idents.iter().map(|ident| {
        quote! {
            registry.register(
                stringify!(#ident),
                std::sync::Arc::new(#ident::default()),
            );
        }
    });

    Ok(quote! {
        pub fn register_all_services(
            registry: &mut dyn wami_traits::ServiceRegistry,
        ) {
            #( #registrations )*
        }
    })
}

struct ServiceList {
    idents: Vec<Ident>,
}

impl Parse for ServiceList {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut idents = Vec::new();

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            idents.push(ident);

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else {
                break;
            }
        }

        Ok(ServiceList { idents })
    }
}
