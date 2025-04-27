terraform {
  required_providers {
    pbkdf2 = {
      source = "registry.terraform.io/jleight/pbkdf2"
    }
  }
}

data "pbkdf2_key" "test" {
  password      = "<PASSWORD>"
  hash_function = "sha512"
}

output "key" {
  value = data.pbkdf2_key.test.key
}
