//! Procedural macros supporting the WAMI workspace.

extern crate proc_macro;

use proc_macro::TokenStream;

mod derive_service;
mod register;
mod service_attr;

#[proc_macro_derive(Service, attributes(service))]
pub fn derive_service(input: TokenStream) -> TokenStream {
    derive_service::expand(input)
}

#[proc_macro_attribute]
pub fn service(attr: TokenStream, item: TokenStream) -> TokenStream {
    service_attr::expand(attr, item)
}

#[proc_macro]
pub fn register_services(input: TokenStream) -> TokenStream {
    register::expand(input)
}
