use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{braced, bracketed, parse_macro_input, parse_quote, Attribute, Ident, ItemMod, Result, Token, TypeParamBound, Visibility};

pub fn expand_store_trait(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as StoreTraitArgs);
    let module = parse_macro_input!(item as ItemMod);

    match build_store_trait(&args, module) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

pub fn expand_store_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as StoreImplArgs);
    let module = parse_macro_input!(item as ItemMod);

    match build_store_impl(&args, module) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

struct StoreTraitArgs {
    trait_ident: Ident,
    visibility: Option<Visibility>,
    supertraits: Vec<TypeParamBound>,
    shared: Option<TokenStream2>,
    items: Option<TokenStream2>,
    methods: TokenStream2,
    tests: Option<TokenStream2>,
}

impl Parse for StoreTraitArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut trait_ident: Option<Ident> = None;
        let mut visibility: Option<Visibility> = None;
        let mut supertraits: Option<Vec<TypeParamBound>> = None;
        let mut shared = None;
        let mut items = None;
        let mut methods = None;
        let mut tests = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match ident.to_string().as_str() {
                "trait" => {
                    if trait_ident.is_some() {
                        return Err(syn::Error::new(
                            ident.span(),
                            "`trait` argument specified more than once",
                        ));
                    }
                    trait_ident = Some(input.parse()?);
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
                "supertraits" => {
                    if supertraits.is_some() {
                        return Err(syn::Error::new(
                            ident.span(),
                            "`supertraits` argument specified more than once",
                        ));
                    }
                    let content;
                    bracketed!(content in input);
                    let mut bounds = Vec::new();
                    while !content.is_empty() {
                        bounds.push(content.parse()?);
                        if content.peek(Token![,]) {
                            content.parse::<Token![,]>()?;
                        }
                    }
                    supertraits = Some(bounds);
                }
                "shared" => {
                    let content;
                    braced!(content in input);
                    shared = Some(content.parse()?);
                }
                "items" => {
                    let content;
                    braced!(content in input);
                    items = Some(content.parse()?);
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

        let trait_ident = trait_ident.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `trait` argument")
        })?;

        let methods = methods.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `methods` argument")
        })?;

        let bounds = supertraits.unwrap_or_else(|| {
            vec![parse_quote!(Send), parse_quote!(Sync)]
        });

        Ok(Self {
            trait_ident,
            visibility,
            supertraits: bounds,
            shared,
            items,
            methods,
            tests,
        })
    }
}

fn build_store_trait(args: &StoreTraitArgs, module: ItemMod) -> Result<TokenStream2> {
    let ItemMod { attrs, .. } = module;

    let vis_trait = args
        .visibility
        .clone()
        .unwrap_or_else(|| parse_quote!(pub));

    let shared = args.shared.clone().unwrap_or_default();
    let items = args.items.clone().unwrap_or_default();
    let methods = &args.methods;
    let tests = args.tests.clone().unwrap_or_default();
    let trait_ident = &args.trait_ident;

    let trait_bounds = if args.supertraits.is_empty() {
        quote! {}
    } else {
        let mut iter = args.supertraits.iter();
        let first = iter.next().unwrap();
        let rest: Vec<_> = iter.collect();
        quote! { : #first #( + #rest )* }
    };

    Ok(quote! {
        use async_trait::async_trait;

        #shared

        #[async_trait]
        #(#attrs)*
        #vis_trait trait #trait_ident #trait_bounds {
            #items
            #methods
        }

        #tests
    })
}

struct StoreImplArgs {
    trait_path: syn::Path,
    for_type: syn::Type,
    shared: Option<TokenStream2>,
    methods: TokenStream2,
    tests: Option<TokenStream2>,
}

impl Parse for StoreImplArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut trait_path: Option<syn::Path> = None;
        let mut for_type: Option<syn::Type> = None;
        let mut shared = None;
        let mut methods = None;
        let mut tests = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match ident.to_string().as_str() {
                "trait" => {
                    if trait_path.is_some() {
                        return Err(syn::Error::new(
                            ident.span(),
                            "`trait` argument specified more than once",
                        ));
                    }
                    trait_path = Some(input.parse()?);
                }
                "for" => {
                    if for_type.is_some() {
                        return Err(syn::Error::new(
                            ident.span(),
                            "`for` argument specified more than once",
                        ));
                    }
                    for_type = Some(input.parse()?);
                }
                "shared" => {
                    let content;
                    braced!(content in input);
                    shared = Some(content.parse()?);
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

        let trait_path = trait_path.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `trait` argument")
        })?;

        let for_type = for_type.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `for` argument")
        })?;

        let methods = methods.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "missing `methods` argument")
        })?;

        Ok(Self {
            trait_path,
            for_type,
            shared,
            methods,
            tests,
        })
    }
}

fn build_store_impl(args: &StoreImplArgs, module: ItemMod) -> Result<TokenStream2> {
    let ItemMod { attrs, .. } = module;

    let shared = args.shared.clone().unwrap_or_default();
    let methods = &args.methods;
    let tests = args.tests.clone().unwrap_or_default();
    let trait_path = &args.trait_path;
    let for_type = &args.for_type;

    Ok(quote! {
        use async_trait::async_trait;

        #shared

        #[async_trait]
        #(#attrs)*
        impl #trait_path for #for_type {
            #methods
        }

        #tests
    })
}
