use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{braced, parse_macro_input, parse_quote, Attribute, Ident, ItemMod, LitStr, Path, Result, Token, Visibility};

pub fn expand_service(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as ServiceArgs);
    let module = parse_macro_input!(item as ItemMod);

    match build_service(&args, module) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

struct ServiceArgs {
    service_ident: Ident,
    store_trait: Path,
    visibility: Option<Visibility>,
    shared: Option<TokenStream2>,
    helpers: Option<TokenStream2>,
    methods: TokenStream2,
    tests: Option<TokenStream2>,
}

impl Parse for ServiceArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut service_ident: Option<Ident> = None;
        let mut store_trait: Option<Path> = None;
        let mut visibility: Option<Visibility> = None;
        let mut shared = None;
        let mut helpers = None;
        let mut methods = None;
        let mut tests = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match ident.to_string().as_str() {
                "service" => {
                    if service_ident.is_some() {
                        return Err(syn::Error::new(
                            ident.span(),
                            "`service` argument specified more than once",
                        ));
                    }
                    service_ident = Some(input.parse()?);
                }
                "store_trait" => {
                    if store_trait.is_some() {
                        return Err(syn::Error::new(
                            ident.span(),
                            "`store_trait` argument specified more than once",
                        ));
                    }
                    store_trait = Some(input.parse()?);
                }
                "visibility" => {
                    if visibility.is_some() {
                        return Err(syn::Error::new(
                            ident.span(),
                            "`visibility` argument specified more than once",
                        ));
                    }
                    visibility = Some(input.parse()?);
                }
                "shared" => {
                    let content;
                    braced!(content in input);
                    shared = Some(content.parse()?);
                }
                "helpers" => {
                    let content;
                    braced!(content in input);
                    helpers = Some(content.parse()?);
                }
                "methods" => {
                    if methods.is_some() {
                        return Err(syn::Error::new(
                            ident.span(),
                            "`methods` argument specified more than once",
                        ));
                    }
                    let content;
                    braced!(content in input);
                    methods = Some(content.parse()?);
                }
                "tests" => {
                    let content;
                    braced!(content in input);
                    tests = Some(content.parse()?);
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

        let service_ident = service_ident.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `service` argument")
        })?;

        let store_trait = store_trait.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `store_trait` argument")
        })?;

        let methods = methods.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `methods` argument")
        })?;

        Ok(Self {
            service_ident,
            store_trait,
            visibility,
            shared,
            helpers,
            methods,
            tests,
        })
    }
}

fn build_service(args: &ServiceArgs, module: ItemMod) -> Result<TokenStream2> {
    let ItemMod {
        attrs,
        ..
    } = module;

    let vis_struct = args
        .visibility
        .clone()
        .unwrap_or_else(|| parse_quote!(pub));

    let shared = args.shared.clone().unwrap_or_default();
    let helpers = args.helpers.clone().unwrap_or_default();
    let methods = &args.methods;
    let tests = args.tests.clone().unwrap_or_default();
    let service_ident = &args.service_ident;
    let store_trait = &args.store_trait;

    Ok(quote! {
        use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

        #shared

        #(#attrs)*
        #vis_struct struct #service_ident<S> {
            store: Arc<RwLock<S>>,
        }

        impl<S> #service_ident<S>
        where
            S: #store_trait,
        {
            pub fn new(store: Arc<RwLock<S>>) -> Self {
                Self { store }
            }

            pub fn store(&self) -> &Arc<RwLock<S>> {
                &self.store
            }

            fn read_store(&self) -> RwLockReadGuard<'_, S> {
                self.store
                    .read()
                    .expect("store read lock poisoned")
            }

            fn write_store(&self) -> RwLockWriteGuard<'_, S> {
                self.store
                    .write()
                    .expect("store write lock poisoned")
            }

            #methods
        }

        #helpers

        #tests
    })
}
