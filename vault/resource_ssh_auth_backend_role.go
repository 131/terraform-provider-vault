// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var sshAuthBackendRoleNameFromPathRegex = regexp.MustCompile("^auth/ssh/role/(.+)$")

func sshAuthBackendRoleEmptyStringSet() (interface{}, error) {
	return []string{}, nil
}

func sshAuthBackendRoleTokenConfig() *addTokenFieldsConfig {
	return &addTokenFieldsConfig{
		TokenPeriodConflict: []string{"token_ttl"},
		TokenTTLConflict:    []string{"token_period"},

		TokenTypeDefault: "default-service",
	}
}

func sshAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"role_name": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Name of the role.",
		},
		"token_policies": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			DefaultFunc: sshAuthBackendRoleEmptyStringSet,
			Description: "List of allowed policies for given role.",
		},
		"public_keys": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			DefaultFunc: sshAuthBackendRoleEmptyStringSet,
			Description: "Public keys for given role.",
		},
	}

	addTokenFields(fields, sshAuthBackendRoleTokenConfig())

	return &schema.Resource{
		CreateContext: sshAuthBackendRoleCreate,
		ReadContext:   provider.ReadContextWrapper(sshAuthBackendRoleRead),
		UpdateContext: sshAuthBackendRoleUpdate,
		DeleteContext: sshAuthBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

func sshAuthBackendRoleUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	setTokenFields(d, data, sshAuthBackendRoleTokenConfig())

	data["token_policies"] = d.Get("token_policies").(*schema.Set).List()
	data["public_keys"] = d.Get("public_keys").(*schema.Set).List()
	data["token_type"] = d.Get("token_type").(string)
}

func sshAuthBackendRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	role := d.Get("role_name").(string)

	path := sshAuthBackendRolePath(role)

	log.Printf("[DEBUG] Writing Token auth backend role %q", path)

	data := map[string]interface{}{}
	sshAuthBackendRoleUpdateFields(d, data)

	d.SetId(path)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("Error writing Token auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Token auth backend role %q", path)

	return sshAuthBackendRoleRead(ctx, d, meta)
}

func sshAuthBackendRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	roleName, err := sshAuthBackendRoleNameFromPath(path)
	if err != nil {
		return diag.Errorf("Invalid path %q for Token auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading Token auth backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("Error reading Token auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Token auth backend role %q", path)
	if resp == nil {
		log.Printf("[WARN] Token auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	d.Set("role_name", roleName)

	params := []string{
		"token_policies",
		"public_keys",
	}
	for _, k := range params {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error reading %s for Token auth backend role %q: %q", k, path, err)
		}
	}

	diags := checkCIDRs(d, TokenFieldBoundCIDRs)

	return diags
}

func sshAuthBackendRoleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Updating Token auth backend role %q", path)

	data := map[string]interface{}{}
	sshAuthBackendRoleUpdateFields(d, data)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error updating Token auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated Token auth backend role %q", path)

	return sshAuthBackendRoleRead(ctx, d, meta)
}

func sshAuthBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting Token auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting Token auth backend role %q", path)
	}
	log.Printf("[DEBUG] Deleted Token auth backend role %q", path)

	return nil
}

func sshAuthBackendRolePath(role string) string {
	return "auth/ssh/role/" + strings.Trim(role, "/")
}

func sshAuthBackendRoleNameFromPath(path string) (string, error) {
	if !sshAuthBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := sshAuthBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}
