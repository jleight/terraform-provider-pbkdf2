data "pbkdf2_key" "example" {
  password      = "<PASSWORD>"
  salt          = base64encode("<SALT>")
  iterations    = 100000
  key_length    = 64
  hash_function = "sha512"
}
