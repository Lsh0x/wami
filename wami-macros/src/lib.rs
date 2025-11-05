//! Procedural macros for the WAMI workspace.

extern crate proc_macro;

use proc_macro::TokenStream;

mod credential;
mod service;
mod store;

#[proc_macro_attribute]
pub fn credential_module(attr: TokenStream, item: TokenStream) -> TokenStream {
    credential::expand_credential_module(attr, item)
}

#[proc_macro_attribute]
pub fn service(attr: TokenStream, item: TokenStream) -> TokenStream {
    service::expand_service(attr, item)
}

#[proc_macro_attribute]
pub fn store_trait(attr: TokenStream, item: TokenStream) -> TokenStream {
    store::expand_store_trait(attr, item)
}

#[proc_macro_attribute]
pub fn store_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    store::expand_store_impl(attr, item)
}

