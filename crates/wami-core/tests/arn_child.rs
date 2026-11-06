use wami_core::arn::{CloudMapping, Service, WamiArn};

#[test]
fn descendants_preserve_namespace_and_do_not_mutate_parent() {
    for mapping in [
        None,
        Some(CloudMapping::new("aws", "123")),
        Some(CloudMapping::with_region("gcp", "456", "europe-west1")),
    ] {
        let mut builder = WamiArn::builder()
            .service_str("gitsense")
            .tenant_hierarchy(vec![42, 7])
            .wami_instance("anatta")
            .resource("project", "p");
        if let Some(mapping) = mapping {
            builder = builder.cloud_mapping(mapping);
        }
        let parent = builder.build().unwrap();
        let original = parent.clone();
        let child = parent
            .child("source", "github.com")
            .unwrap()
            .child("owner", "anatta-rs")
            .unwrap()
            .child("repo", "gitsense")
            .unwrap();
        assert_eq!(
            child.to_string(),
            format!("{parent}/source/github.com/owner/anatta-rs/repo/gitsense")
        );
        assert_eq!(child.to_string().parse::<WamiArn>().unwrap(), child);
        assert_eq!(child.prefix(), parent.prefix());
        assert_eq!(parent, original);
        assert_eq!(
            parent.child("repo", "other").unwrap().resource_id(),
            "p/repo/other"
        );
    }
}

#[test]
fn rejects_invalid_child_components_in_both_positions() {
    let parent: WamiArn = "arn:wami:s3:42:wami:anatta:bucket/b".parse().unwrap();
    for value in [
        "", ".", "..", "a/b", "a:b", "*", "?", "a b", "é", "x\n", "%2f",
    ] {
        assert!(parent.child(value, "ok").is_err(), "type {value:?}");
        assert!(parent.child("ok", value).is_err(), "key {value:?}");
    }
    assert!(parent.child("object", "file.tar.gz_1-2").is_ok());
}

#[test]
fn rejects_unchecked_and_pattern_parents() {
    let parent: WamiArn = "arn:wami:s3:42:wami:anatta:bucket/b".parse().unwrap();
    let mut invalid = Vec::new();
    let mut p = parent.clone();
    p.tenant_path.segments.clear();
    invalid.push(p);
    let mut p = parent.clone();
    p.wami_instance_id.clear();
    invalid.push(p);
    let mut p = parent.clone();
    p.resource.resource_id.clear();
    invalid.push(p);
    let mut p = parent.clone();
    p.resource.resource_type.clear();
    invalid.push(p);
    let mut p = parent.clone();
    p.service = Service::Custom("x:y".into());
    invalid.push(p);
    let mut p = parent.clone();
    p.cloud_mapping = Some(CloudMapping::with_region("aws", "1", "global"));
    invalid.push(p);
    let mut p = parent.clone();
    p.service = Service::Custom(String::new());
    invalid.push(p);
    for field in ["b/*", "b?", "b\n"] {
        let mut p = parent.clone();
        p.resource.resource_id = field.into();
        invalid.push(p);
    }
    let mut p = parent.clone();
    p.wami_instance_id = "*".into();
    invalid.push(p);
    for p in invalid {
        assert!(p.child("object", "x").is_err(), "{p:?}");
    }
}
