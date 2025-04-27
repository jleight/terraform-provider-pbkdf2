// Copyright (c) Jonathon Leight
// SPDX-License-Identifier: MIT

package provider

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"golang.org/x/crypto/pbkdf2"
)

var _ datasource.DataSource = &KeyDataSource{}

func NewKeyDataSource() datasource.DataSource {
	return &KeyDataSource{}
}

type KeyDataSource struct {
}

type KeyDataSourceModel struct {
	Password     types.String `tfsdk:"password"`
	Salt         types.String `tfsdk:"salt"`
	Iterations   types.Int32  `tfsdk:"iterations"`
	KeyLength    types.Int32  `tfsdk:"key_length"`
	HashFunction types.String `tfsdk:"hash_function"`
	Key          types.String `tfsdk:"key"`
}

func (d *KeyDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_key"
}

func (d *KeyDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"password": schema.StringAttribute{
				Description: "The password to generate a key for.",
				Required:    true,
				Sensitive:   true,
			},
			"salt": schema.StringAttribute{
				Description: "The base64-encoded salt to use when generating the key. If not provided, a random salt will be generated.",
				Optional:    true,
			},
			"iterations": schema.Int32Attribute{
				Description: "The number of iterations to use when generating the key. Defaults to 100,000.",
				Optional:    true,
			},
			"key_length": schema.Int32Attribute{
				Description: "The byte length of the key to generate. Defaults to the length of the result of the hash function.",
				Optional:    true,
			},
			"hash_function": schema.StringAttribute{
				MarkdownDescription: "The hash function to use when generating the key. Supports `sha1`, `sha256`, and `sha512`.",
				Required:            true,
			},
			"key": schema.StringAttribute{
				Description: "The base64-encoded key.",
				Computed:    true,
			},
		},
	}
}

func (d *KeyDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data KeyDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	password := data.Password.ValueString()
	if len(password) == 0 {
		resp.Diagnostics.AddError(
			"PBKDF2 Error",
			"password is required",
		)
		return
	}

	var salt []byte
	salt64 := data.Salt.ValueString()

	if len(salt64) == 0 {
		salt = make([]byte, 16)

		_, err := rand.Read(salt)
		if err != nil {
			resp.Diagnostics.AddError(
				"PBKDF2 Error",
				fmt.Sprintf("error generating salt: %s", err),
			)
			return
		}

		salt64 = base64.StdEncoding.EncodeToString(salt)
		data.Salt = types.StringValue(salt64)
	} else {
		salt = make([]byte, base64.StdEncoding.DecodedLen(len(salt64)))

		n, err := base64.StdEncoding.Decode(
			salt,
			[]byte(salt64),
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"PBKDF2 Error",
				fmt.Sprintf("error decoding salt: %s", err),
			)
			return
		}

		salt = salt[:n]
	}

	iterations := int(data.Iterations.ValueInt32())
	if iterations <= 0 {
		iterations = 100_000
	}

	var hashFunction func() hash.Hash
	keyLength := int(data.KeyLength.ValueInt32())

	switch data.HashFunction.ValueString() {
	case "sha1":
		hashFunction = sha1.New
		if keyLength <= 0 {
			keyLength = sha1.Size
		}
	case "sha256":
		hashFunction = sha256.New
		if keyLength <= 0 {
			keyLength = sha256.Size
		}
	case "sha512":
		hashFunction = sha512.New
		if keyLength <= 0 {
			keyLength = sha512.Size
		}
	default:
		resp.Diagnostics.AddError(
			"PBKDF2 Error",
			"unknown hash function",
		)
		return
	}

	key := pbkdf2.Key(
		[]byte(password),
		salt,
		iterations,
		keyLength,
		hashFunction,
	)

	key64 := base64.StdEncoding.EncodeToString(key)
	data.Key = types.StringValue(key64)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
