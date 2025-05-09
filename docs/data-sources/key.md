---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pbkdf2_key Data Source - pbkdf2"
subcategory: ""
description: |-
  
---

# pbkdf2_key (Data Source)



## Example Usage

```terraform
data "pbkdf2_key" "example" {
  password      = "<PASSWORD>"
  salt          = base64encode("<SALT>")
  iterations    = 100000
  key_length    = 64
  hash_function = "sha512"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `hash_function` (String) The hash function to use when generating the key. Supports `sha1`, `sha256`, and `sha512`.
- `password` (String, Sensitive) The password to generate a key for.

### Optional

- `iterations` (Number) The number of iterations to use when generating the key. Defaults to 100,000.
- `key_length` (Number) The byte length of the key to generate. Defaults to the length of the result of the hash function.
- `salt` (String) The base64-encoded salt to use when generating the key. If not provided, a random salt will be generated.

### Read-Only

- `key` (String) The base64-encoded key.
