package lowlevel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/h44z/wg-portal/internal/config"
)

func mikrotikTestClient(t *testing.T, handler http.HandlerFunc) (*MikrotikApiClient, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client, err := NewMikrotikApiClient(&config.Config{}, &config.BackendMikrotik{
		BackendBase: config.BackendBase{Id: "test"},
		ApiUrl:      srv.URL + "/rest",
		ApiUser:     "user",
		ApiPassword: "secret",
	})
	require.NoError(t, err)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return client, u.Host
}

func TestMikrotikQuerySendsBasicAuth(t *testing.T) {
	client, _ := mikrotikTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":401,"message":"Unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	})

	reply := client.Query(context.Background(), "/interface/wireguard", nil)
	assert.Equal(t, MikrotikApiStatusOk, reply.Status)
}

func TestMikrotikAuthErrorHint(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		contains string
	}{
		{"unauthorized", http.StatusUnauthorized, `{"error":401,"message":"Unauthorized"}`, "verify api_user and api_password"},
		{"forbidden", http.StatusForbidden, `{"error":403,"message":"Forbidden"}`, "rest-api policies"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, host := mikrotikTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})

			reply := client.Query(context.Background(), "/interface/wireguard", nil)
			require.Equal(t, MikrotikApiStatusError, reply.Status)
			require.NotNil(t, reply.Error)
			assert.Equal(t, tt.status, reply.Error.Code)
			assert.Contains(t, reply.Error.Details, tt.contains)
			assert.Contains(t, reply.Error.Details, host)
		})
	}
}

func TestMikrotikErrorDetailIsKept(t *testing.T) {
	client, _ := mikrotikTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":400,"message":"Bad Request","detail":"no such command"}`))
	})

	reply := client.Query(context.Background(), "/interface/wireguard", nil)
	require.NotNil(t, reply.Error)
	assert.Equal(t, "no such command", reply.Error.Details)
}
