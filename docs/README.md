# WAMI Documentation

Welcome to the WAMI documentation! Choose your path:

## 🎯 I want to...

### Get Started Quickly
- **[5-Minute Quickstart](GETTING_STARTED.md)** - Install and run your first example
- **[Examples Catalog](EXAMPLES.md)** - Browse all code examples

### Learn Core Features
- **[IAM Operations](IAM_GUIDE.md)** - Manage users, roles, policies, groups
- **[STS Operations](STS_GUIDE.md)** - Get temporary credentials
- **[SSO Admin](SSO_ADMIN_GUIDE.md)** - Configure permission sets
- **[OAuth 2.0 & OIDC](OAUTH_OIDC_GUIDE.md)** - Issue tokens, sign users in
- **[Multi-Tenant](MULTI_TENANT_GUIDE.md)** - Isolate resources by tenant

### Implement Advanced Features
- **[Multicloud Providers](MULTICLOUD_PROVIDERS.md)** - AWS, GCP, Azure, Custom
- **[Store Implementation](STORE_IMPLEMENTATION.md)** - Add database persistence
- **[Permission Checking](PERMISSION_CHECKING.md)** - Policy evaluation only

### Understand the System
- **[Architecture](ARCHITECTURE.md)** - System design and components
- **[API Reference](API_REFERENCE.md)** - Quick API lookup

## 📚 Documentation by Use Case

### Use Case: Testing IAM Policies
→ Start with [Permission Checking](PERMISSION_CHECKING.md)

### Use Case: Building a SaaS with Isolated Tenants
→ Start with [Multi-Tenant Guide](MULTI_TENANT_GUIDE.md)

### Use Case: Implementing Cloud-Agnostic IAM
→ Start with [Multicloud Providers](MULTICLOUD_PROVIDERS.md)

### Use Case: Persisting IAM Data to Database
→ Start with [Store Implementation](STORE_IMPLEMENTATION.md)

### Use Case: Managing AWS-like Identities
→ Start with [IAM Guide](IAM_GUIDE.md)

### Use Case: Generating Temporary Access Keys
→ Start with [STS Guide](STS_GUIDE.md)

### Use Case: Letting Users Sign In to Your Applications
→ Start with [OAuth 2.0 & OIDC Guide](OAUTH_OIDC_GUIDE.md)

## 📖 Full Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| [Getting Started](GETTING_STARTED.md) | 5-minute quickstart | Everyone |
| [IAM Guide](IAM_GUIDE.md) | Complete IAM operations | Developers |
| [STS Guide](STS_GUIDE.md) | Temporary credentials | Developers |
| [SSO Admin Guide](SSO_ADMIN_GUIDE.md) | SSO configuration | Developers |
| [OAuth & OIDC Guide](OAUTH_OIDC_GUIDE.md) | Authorization server, OpenID Provider | Developers |
| [Multi-Tenant](MULTI_TENANT_GUIDE.md) | Tenant isolation | SaaS Builders |
| [Multicloud Providers](MULTICLOUD_PROVIDERS.md) | Cloud abstraction | Platform Teams |
| [Store Implementation](STORE_IMPLEMENTATION.md) | Custom persistence | Backend Developers |
| [Permission Checking](PERMISSION_CHECKING.md) | Policy evaluation | Security Teams |
| [Architecture](ARCHITECTURE.md) | System design | Architects |
| [Examples](EXAMPLES.md) | Code samples | Everyone |
| [API Reference](API_REFERENCE.md) | Quick lookup | Developers |

## 🚀 Roadmap & Issues

- **[Issues Tracker](issues/README.md)** - Active feature requests and enhancements
- **[Issue #001: Condition Keys](issues/ISSUE_001_CONDITION_KEYS.md)** - Policy condition support (In Planning)
- **[Condition Keys Summary](CONDITION_KEYS_SUMMARY.md)** - Executive summary of condition implementation

## 🔗 External Resources

- **[API Documentation](https://docs.rs/wami)** - Full rustdoc
- **[Crates.io](https://crates.io/crates/wami)** - Package registry
- **[GitHub](https://github.com/lsh0x/wami)** - Source code
- **[Examples](../examples/)** - Working code examples

## 💡 Quick Links

- [Installation](#) → [Getting Started](GETTING_STARTED.md#installation)
- [First Example](#) → [Getting Started](GETTING_STARTED.md#your-first-example)
- [Core Concepts](#) → [Architecture](ARCHITECTURE.md#core-concepts)
- [Testing Guide](#) → [Examples](EXAMPLES.md#testing-examples)
- [Migration Guide](#) → [Multi-Tenant Guide](MULTI_TENANT_GUIDE.md#migration-guide)

