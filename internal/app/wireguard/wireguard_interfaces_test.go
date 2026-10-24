package wireguard

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/h44z/wg-portal/internal/config"
	"github.com/h44z/wg-portal/internal/domain"
)

func TestInferImportedInterfaceType(t *testing.T) {
	tests := []struct {
		name       string
		listenPort int
		peerCount  int
		expected   domain.InterfaceType
	}{
		{
			name:       "no peers stays unknown",
			listenPort: 51820,
			peerCount:  0,
			expected:   domain.InterfaceTypeAny,
		},
		{
			name:       "single peer with listen port is server",
			listenPort: 51820,
			peerCount:  1,
			expected:   domain.InterfaceTypeServer,
		},
		{
			name:       "single peer without listen port stays client",
			listenPort: 0,
			peerCount:  1,
			expected:   domain.InterfaceTypeClient,
		},
		{
			name:       "multiple peers is server",
			listenPort: 0,
			peerCount:  2,
			expected:   domain.InterfaceTypeServer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface := &domain.Interface{ListenPort: tt.listenPort}
			peers := make([]domain.PhysicalPeer, tt.peerCount)

			assert.Equal(t, tt.expected, inferImportedInterfaceType(iface, peers))
		})
	}
}

func TestImportPeer_AddressMapping(t *testing.T) {
	tests := []struct {
		name                 string
		allowedIPs           []string
		expectedInterface    []string
		expectedExtraAllowed string
	}{
		{
			name:                 "IPv4 host address",
			allowedIPs:           []string{"10.0.0.1/32"},
			expectedInterface:    []string{"10.0.0.1/32"},
			expectedExtraAllowed: "",
		},
		{
			name:                 "IPv6 host address",
			allowedIPs:           []string{"fd00::1/128"},
			expectedInterface:    []string{"fd00::1/128"},
			expectedExtraAllowed: "",
		},
		{
			name:                 "IPv4 network address",
			allowedIPs:           []string{"10.0.1.0/24"},
			expectedInterface:    []string{},
			expectedExtraAllowed: "10.0.1.0/24",
		},
		{
			name:                 "IPv4 normal address with mask",
			allowedIPs:           []string{"10.0.1.5/24"},
			expectedInterface:    []string{"10.0.1.5/24"},
			expectedExtraAllowed: "",
		},
		{
			name: "Mixed addresses",
			allowedIPs: []string{
				"10.0.0.1/32", "192.168.1.0/24", "172.16.0.5/24", "fd00::1/128", "fd00:1::/64",
			},
			expectedInterface:    []string{"10.0.0.1/32", "172.16.0.5/24", "fd00::1/128"},
			expectedExtraAllowed: "192.168.1.0/24,fd00:1::/64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &mockDB{}
			m := Manager{
				db: db,
			}

			iface := &domain.Interface{
				Identifier: "wg0",
				Type:       domain.InterfaceTypeServer,
			}

			allowedIPs := make([]domain.Cidr, len(tt.allowedIPs))
			for i, s := range tt.allowedIPs {
				cidr, _ := domain.CidrFromString(s)
				allowedIPs[i] = cidr
			}

			p := &domain.PhysicalPeer{
				Identifier: "peer1",
				PublicKey:  "peer1-public-key-is-long-enough",
				AllowedIPs: allowedIPs,
			}

			err := m.importPeer(context.Background(), iface, p)
			assert.NoError(t, err)

			savedPeer := db.savedPeers["peer1"]
			assert.NotNil(t, savedPeer)

			// Check interface addresses
			actualInterface := make([]string, len(savedPeer.Interface.Addresses))
			for i, addr := range savedPeer.Interface.Addresses {
				actualInterface[i] = addr.String()
			}
			assert.ElementsMatch(t, tt.expectedInterface, actualInterface)

			// Check extra allowed IPs
			assert.Equal(t, tt.expectedExtraAllowed, savedPeer.ExtraAllowedIPsStr)
		})
	}
}

func TestInterface_IsUserAllowed(t *testing.T) {
	cfg := &config.Config{
		Auth: config.Auth{
			Ldap: []config.LdapProvider{
				{
					ProviderName: "ldap1",
					InterfaceFilter: map[string]string{
						"wg0": "(memberOf=CN=VPNUsers,...)",
					},
				},
			},
		},
	}

	tests := []struct {
		name   string
		iface  domain.Interface
		userId domain.UserIdentifier
		expect bool
	}{
		{
			name: "Unrestricted interface",
			iface: domain.Interface{
				Identifier: "wg1",
			},
			userId: "user1",
			expect: true,
		},
		{
			name: "Restricted interface - user allowed",
			iface: domain.Interface{
				Identifier: "wg0",
				LdapAllowedUsers: map[string][]domain.UserIdentifier{
					"ldap1": {"user1"},
				},
			},
			userId: "user1",
			expect: true,
		},
		{
			name: "Restricted interface - user allowed (at least one match)",
			iface: domain.Interface{
				Identifier: "wg0",
				LdapAllowedUsers: map[string][]domain.UserIdentifier{
					"ldap1": {"user2"},
					"ldap2": {"user1"},
				},
			},
			userId: "user1",
			expect: true,
		},
		{
			name: "Restricted interface - user NOT allowed",
			iface: domain.Interface{
				Identifier: "wg0",
				LdapAllowedUsers: map[string][]domain.UserIdentifier{
					"ldap1": {"user2"},
				},
			},
			userId: "user1",
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, tt.iface.IsUserAllowed(tt.userId, cfg))
		})
	}
}

func TestManager_GetUserInterfaces_Filtering(t *testing.T) {
	cfg := &config.Config{}
	cfg.Core.SelfProvisioningAllowed = true
	cfg.Auth.Ldap = []config.LdapProvider{
		{
			ProviderName: "ldap1",
			InterfaceFilter: map[string]string{
				"wg_restricted": "(some-filter)",
			},
		},
	}

	db := &mockDB{
		interfaces: []domain.Interface{
			{Identifier: "wg_public", Type: domain.InterfaceTypeServer},
			{
				Identifier: "wg_restricted",
				Type:       domain.InterfaceTypeServer,
				LdapAllowedUsers: map[string][]domain.UserIdentifier{
					"ldap1": {"allowed_user"},
				},
			},
		},
	}
	m := Manager{
		cfg: cfg,
		db:  db,
	}

	t.Run("Allowed user sees both", func(t *testing.T) {
		ifaces, err := m.GetUserInterfaces(context.Background(), "allowed_user")
		assert.NoError(t, err)
		assert.Equal(t, 2, len(ifaces))
	})

	t.Run("Unallowed user sees only public", func(t *testing.T) {
		ifaces, err := m.GetUserInterfaces(context.Background(), "other_user")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(ifaces))
		if len(ifaces) > 0 {
			assert.Equal(t, domain.InterfaceIdentifier("wg_public"), ifaces[0].Identifier)
		}
	})
}

type failingInterfacesController struct {
	mockController
}

func (f *failingInterfacesController) GetInterfaces(_ context.Context) ([]domain.PhysicalInterface, error) {
	return nil, errors.New("API error 401: Unauthorized")
}

type countingInterfacesController struct {
	mockController
	calls int
}

func (f *countingInterfacesController) GetInterfaces(_ context.Context) ([]domain.PhysicalInterface, error) {
	f.calls++
	return nil, nil
}

func TestManager_ImportNewInterfaces_SkipsFailingBackend(t *testing.T) {
	healthy := &countingInterfacesController{}
	m := Manager{
		cfg: &config.Config{},
		db:  &mockDB{},
		wg: &ControllerManager{
			controllers: map[domain.InterfaceBackend]backendInstance{
				"mikrotik": {
					Config:         config.BackendBase{Id: "mikrotik"},
					Implementation: &failingInterfacesController{},
				},
				config.LocalBackendName: {
					Config:         config.BackendBase{Id: config.LocalBackendName},
					Implementation: healthy,
				},
			},
		},
	}
	ctx := domain.SetUserInfo(context.Background(), domain.SystemAdminContextUserInfo())

	imported, err := m.ImportNewInterfaces(ctx)

	assert.NoError(t, err)
	assert.Equal(t, 0, imported)
	assert.Equal(t, 1, healthy.calls, "the healthy backend must still be queried")
}

type unreachableController struct {
	mockController
}

func (f *unreachableController) GetInterface(_ context.Context, _ domain.InterfaceIdentifier) (
	*domain.PhysicalInterface,
	error,
) {
	return nil, errors.New("API error 401: Unauthorized")
}

func (f *unreachableController) SaveInterface(
	_ context.Context,
	_ domain.InterfaceIdentifier,
	_ func(pi *domain.PhysicalInterface) (*domain.PhysicalInterface, error),
) error {
	return errors.New("API error 401: Unauthorized")
}

type countingSaveController struct {
	mockController
	savedInterfaces []domain.InterfaceIdentifier
}

func (f *countingSaveController) SaveInterface(
	ctx context.Context,
	id domain.InterfaceIdentifier,
	updateFunc func(pi *domain.PhysicalInterface) (*domain.PhysicalInterface, error),
) error {
	f.savedInterfaces = append(f.savedInterfaces, id)
	return f.mockController.SaveInterface(ctx, id, updateFunc)
}

func TestManager_RestoreInterfaceState_ContinuesAfterFailingInterface(t *testing.T) {
	healthy := &countingSaveController{}
	m := Manager{
		cfg: &config.Config{},
		bus: &mockBus{},
		db: &mockDB{
			interfaces: []domain.Interface{
				{Identifier: "wg_mt", Type: domain.InterfaceTypeServer, Backend: "mikrotik"},
				{Identifier: "wg_local", Type: domain.InterfaceTypeServer, Backend: config.LocalBackendName},
			},
		},
		wg: &ControllerManager{
			controllers: map[domain.InterfaceBackend]backendInstance{
				"mikrotik": {
					Config:         config.BackendBase{Id: "mikrotik"},
					Implementation: &unreachableController{},
				},
				config.LocalBackendName: {
					Config:         config.BackendBase{Id: config.LocalBackendName},
					Implementation: healthy,
				},
			},
		},
	}
	ctx := domain.SetUserInfo(context.Background(), domain.SystemAdminContextUserInfo())

	err := m.RestoreInterfaceState(ctx, false)

	assert.ErrorContains(t, err, "wg_mt")
	assert.NotContains(t, err.Error(), "wg_local")
	assert.Contains(t, healthy.savedInterfaces, domain.InterfaceIdentifier("wg_local"),
		"interfaces after a failing one must still be restored")
}
