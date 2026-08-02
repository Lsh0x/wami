use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{parse_macro_input, parse_quote, ItemStruct, LitBool, Path, Result, Token};

pub fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as ServiceArgs);
    let item_struct = parse_macro_input!(item as ItemStruct);

    match expand_inner(args, item_struct) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

struct ServiceArgs {
    store_trait: Path,
    generate_new: bool,
}

impl Parse for ServiceArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let ident: syn::Ident = input.parse()?;

        if ident != "store_trait" {
            return Err(syn::Error::new(
                ident.span(),
                "expected `store_trait = \"path\"`",
            ));
        }

        input.parse::<Token![=]>()?;

        let lit: syn::LitStr = input.parse()?;
        let store_trait: Path = lit.parse()?;

        let mut generate_new = true;

        while input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }

            let key: syn::Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match key.to_string().as_str() {
                "generate_new" => {
                    let value: LitBool = input.parse()?;
                    generate_new = value.value;
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("unknown argument `{}`", other),
                    ));
                }
            }
        }

        Ok(Self {
            store_trait,
            generate_new,
        })
    }
}

fn expand_inner(args: ServiceArgs, item_struct: ItemStruct) -> Result<proc_macro2::TokenStream> {
    let struct_ident = &item_struct.ident;
    let mut generics = item_struct.generics.clone();

    // Ensure the struct has a field named `store`
    let store_field = item_struct
        .fields
        .iter()
        .find(|field| {
            field
                .ident
                .as_ref()
                .map(|ident| ident == "store")
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            syn::Error::new(
                struct_ident.span(),
                "service struct must have a `store` field",
            )
        })?;

    // Validate the store field type is Arc<tokio::sync::RwLock<...>>
    if !matches!(store_field.ty, syn::Type::Path(_)) {
        return Err(syn::Error::new(
            store_field.ty.span(),
            "`store` field must be of type Arc<tokio::sync::RwLock<S>>",
        ));
    }

    // Ensure there is a generic parameter we can constrain (typically `S`)
    let type_param = generics.type_params().next().ok_or_else(|| {
        syn::Error::new(
            struct_ident.span(),
            "service struct must be generic over `S`",
        )
    })?;
    let type_ident = type_param.ident.clone();

    // Add store trait bound to where clause
    {
        let where_clause = generics.make_where_clause();
        let store_trait_path = &args.store_trait;
        where_clause
            .predicates
            .push(parse_quote!(#type_ident: #store_trait_path));
    }

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let new_fn = if args.generate_new {
        Some(quote! {
            pub fn new(store: std::sync::Arc<tokio::sync::RwLock<#type_ident>>) -> Self {
                Self { store }
            }
        })
    } else {
        None
    };

    // The lock is `tokio::sync::RwLock` because the store traits are async: a
    // service holding a `std::sync` guard across an `.await` blocks a runtime
    // thread, and its futures are not `Send`. The accessors are therefore
    // async too, and there is no poisoning to report.
    let expanded = quote! {
        #item_struct

        impl #impl_generics #struct_ident #ty_generics #where_clause {
            #new_fn

            pub fn store(&self) -> &std::sync::Arc<tokio::sync::RwLock<#type_ident>> {
                &self.store
            }

            async fn read_store(&self) -> tokio::sync::RwLockReadGuard<'_, #type_ident> {
                self.store.read().await
            }

            async fn write_store(&self) -> tokio::sync::RwLockWriteGuard<'_, #type_ident> {
                self.store.write().await
            }
        }
    };

    Ok(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> ServiceArgs {
        ServiceArgs {
            store_trait: parse_quote!(MyStore),
            generate_new: true,
        }
    }

    #[test]
    fn a_store_field_that_is_not_a_path_type_is_refused() {
        // A tuple, a reference, a pointer — anything the generated accessors
        // cannot call `.read().await` on. Rejected with the shape it wanted,
        // rather than by whatever the expansion would have failed on later.
        let item: ItemStruct = parse_quote! {
            struct Svc<S> { store: (S, S) }
        };

        let err = expand_inner(args(), item).unwrap_err();
        assert!(
            err.to_string().contains("Arc<tokio::sync::RwLock<S>>"),
            "{err}"
        );
    }

    #[test]
    fn a_struct_without_a_store_field_is_refused() {
        let item: ItemStruct = parse_quote! {
            struct Svc<S> { other: S }
        };

        let err = expand_inner(args(), item).unwrap_err();
        assert!(err.to_string().contains("`store` field"), "{err}");
    }

    #[test]
    fn a_non_generic_struct_is_refused() {
        let item: ItemStruct = parse_quote! {
            struct Svc { store: std::sync::Arc<tokio::sync::RwLock<Concrete>> }
        };

        let err = expand_inner(args(), item).unwrap_err();
        assert!(err.to_string().contains("generic over `S`"), "{err}");
    }

    #[test]
    fn the_generated_accessors_are_async_and_tokio() {
        // The point of #115: were these to go back to `std::sync`, every
        // service would hold a blocking guard across an await again.
        let item: ItemStruct = parse_quote! {
            struct Svc<S> { store: std::sync::Arc<tokio::sync::RwLock<S>> }
        };

        let expanded = expand_inner(args(), item).unwrap().to_string();
        assert!(expanded.contains("async fn read_store"), "{expanded}");
        assert!(expanded.contains("async fn write_store"), "{expanded}");
        assert!(expanded.contains("tokio :: sync :: RwLock"), "{expanded}");
        assert!(!expanded.contains("std :: sync :: RwLock"), "{expanded}");
    }
}
