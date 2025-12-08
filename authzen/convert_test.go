// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package authzen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
)

func TestSubject(t *testing.T) {
	t.Run("create with basic fields", func(t *testing.T) {
		subject := NewSubject("user", "alice")
		require.NotNil(t, subject)
		assert.Equal(t, "user", subject.Type())
		assert.Equal(t, "alice", subject.ID())
		assert.NoError(t, subject.Err())
	})

	t.Run("with properties", func(t *testing.T) {
		subject := NewSubject("user", "alice").
			WithProperty("department", "engineering").
			WithProperty("level", 5)

		require.NotNil(t, subject)
		assert.NoError(t, subject.Err())
		assert.NotNil(t, subject.Proto().GetProperties())
	})

	t.Run("with Cerbos-specific properties", func(t *testing.T) {
		subject := NewSubject("user", "alice").
			WithCerbosRoles("admin", "user").
			WithCerbosPolicyVersion("v1.0").
			WithCerbosScope("acme.corp")

		require.NotNil(t, subject)
		assert.NoError(t, subject.Err())

		props := subject.Proto().GetProperties()
		assert.Contains(t, props, "cerbos.roles")
		assert.Contains(t, props, "cerbos.policyVersion")
		assert.Contains(t, props, "cerbos.scope")
	})
}

func TestResource(t *testing.T) {
	t.Run("create with basic fields", func(t *testing.T) {
		resource := NewResource("document", "doc123")
		require.NotNil(t, resource)
		assert.Equal(t, "document", resource.Type())
		assert.Equal(t, "doc123", resource.ID())
		assert.NoError(t, resource.Err())
	})

	t.Run("with properties", func(t *testing.T) {
		resource := NewResource("document", "doc123").
			WithProperty("owner", "alice").
			WithProperty("public", true)

		require.NotNil(t, resource)
		assert.NoError(t, resource.Err())
		assert.NotNil(t, resource.Proto().GetProperties())
	})

	t.Run("with Cerbos properties", func(t *testing.T) {
		resource := NewResource("document", "doc123").
			WithCerbosPolicyVersion("v1.0").
			WithCerbosScope("acme.corp")

		require.NotNil(t, resource)
		assert.NoError(t, resource.Err())

		props := resource.Proto().GetProperties()
		assert.Contains(t, props, "cerbos.policyVersion")
		assert.Contains(t, props, "cerbos.scope")
	})
}

func TestAction(t *testing.T) {
	t.Run("create with name", func(t *testing.T) {
		action := NewAction("read")
		require.NotNil(t, action)
		assert.Equal(t, "read", action.Name())
		assert.NoError(t, action.Err())
	})

	t.Run("with properties", func(t *testing.T) {
		action := NewAction("read").
			WithProperty("scope", "full")

		require.NotNil(t, action)
		assert.NoError(t, action.Err())
		assert.NotNil(t, action.Proto().GetProperties())
	})
}

func TestContext(t *testing.T) {
	t.Run("create empty", func(t *testing.T) {
		ctx := NewContext()
		require.NotNil(t, ctx)
		assert.NoError(t, ctx.Err())
	})

	t.Run("with request ID", func(t *testing.T) {
		ctx := NewContext().
			WithRequestID("test-request-123")

		require.NotNil(t, ctx)
		assert.NoError(t, ctx.Err())
		assert.Contains(t, ctx.Data(), "cerbos.requestId")
	})

	t.Run("with include meta", func(t *testing.T) {
		ctx := NewContext().
			WithIncludeMeta(true)

		require.NotNil(t, ctx)
		assert.NoError(t, ctx.Err())
		assert.Contains(t, ctx.Data(), "cerbos.includeMeta")
	})
}

func TestFromCerbosPrincipal(t *testing.T) {
	t.Run("convert basic principal", func(t *testing.T) {
		principal := cerbos.NewPrincipal("alice", "admin", "user")
		subject, err := FromCerbosPrincipal(principal)

		require.NoError(t, err)
		require.NotNil(t, subject)
		assert.Equal(t, "alice", subject.ID())
		assert.Equal(t, "user", subject.Type())
	})

	t.Run("convert principal with attributes", func(t *testing.T) {
		principal := cerbos.NewPrincipal("alice", "admin").
			WithAttr("department", "engineering").
			WithAttr("level", 5).
			WithPolicyVersion("v1.0").
			WithScope("acme.corp")

		subject, err := FromCerbosPrincipal(principal)

		require.NoError(t, err)
		require.NotNil(t, subject)

		props := subject.Proto().GetProperties()
		assert.Contains(t, props, "department")
		assert.Contains(t, props, "level")
		assert.Contains(t, props, "cerbos.policyVersion")
		assert.Contains(t, props, "cerbos.scope")
		assert.Contains(t, props, "cerbos.roles")
	})

	t.Run("nil principal", func(t *testing.T) {
		subject, err := FromCerbosPrincipal(nil)
		require.Error(t, err)
		require.Nil(t, subject)
	})
}

func TestFromCerbosResource(t *testing.T) {
	t.Run("convert basic resource", func(t *testing.T) {
		resource := cerbos.NewResource("document", "doc123")
		esource, err := FromCerbosResource(resource)

		require.NoError(t, err)
		require.NotNil(t, esource)
		assert.Equal(t, "document", esource.Type())
		assert.Equal(t, "doc123", esource.ID())
	})

	t.Run("convert resource with attributes", func(t *testing.T) {
		resource := cerbos.NewResource("document", "doc123").
			WithAttr("owner", "alice").
			WithAttr("public", true).
			WithPolicyVersion("v1.0").
			WithScope("acme.corp")

		esource, err := FromCerbosResource(resource)

		require.NoError(t, err)
		require.NotNil(t, esource)

		props := esource.Proto().GetProperties()
		assert.Contains(t, props, "owner")
		assert.Contains(t, props, "public")
		assert.Contains(t, props, "cerbos.policyVersion")
		assert.Contains(t, props, "cerbos.scope")
	})
}
