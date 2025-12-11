package relay

import (
	"context"
	"fmt"
	"net/http"
	"time"

	comatproto "github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/util/ssrf"
	"github.com/bluesky-social/indigo/xrpc"
)

// Simple interface for doing host and account status checks.
//
// The main reason this is an interface is to make testing/mocking easy.
type HostChecker interface {
	// host should be a URL, including scheme, hostname (and optional port), but no path segment
	CheckHost(ctx context.Context, host string) error
	FetchAccountStatus(ctx context.Context, ident *identity.Identity) (string, error)
}

var _ HostChecker = (*HostClient)(nil)

// Allows SSRF to succeed on listed internal domain names if they resolve to listed internal IP address ranges,
// without compromising SSRF on other public hostnames.

type HostClient struct {
	Client         *http.Client
	InternalClient *http.Client
	UserAgent      string
}

func NewHostClient(userAgent string) *HostClient {
	if userAgent == "" {
		userAgent = "indigo-relay (atproto-relay)"
	}
	c := http.Client{
		Timeout:   5 * time.Second,
		Transport: ssrf.PublicOnlyTransport(),
	}
	ic := http.Client{
		Timeout:   5 * time.Second,
		Transport: ssrf.InternalOnlyTransport(),
	}
	return &HostClient{
		Client:         &c,
		InternalClient: &ic,
		UserAgent:      userAgent,
	}
}

func (hc *HostClient) GetClient(host string) *http.Client {
	if ssrf.IsInternalHostname(host) {
		return hc.InternalClient
	}
	return hc.Client
}

func (hc *HostClient) CheckHost(ctx context.Context, host string) error {
	xrpcc := xrpc.Client{
		Client:    hc.GetClient(host),
		UserAgent: &hc.UserAgent,
		Host:      host,
	}

	_, err := comatproto.ServerDescribeServer(ctx, &xrpcc)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHostNotPDS, err)
	}
	return nil
}

func (hc *HostClient) FetchAccountStatus(ctx context.Context, ident *identity.Identity) (string, error) {
	pdsEndpoint := ident.PDSEndpoint()
	if pdsEndpoint == "" {
		return "", fmt.Errorf("account does not declare a PDS: %s", ident.DID)
	}

	xrpcc := xrpc.Client{
		Client:    hc.GetClient(pdsEndpoint),
		UserAgent: &hc.UserAgent,
		Host:      pdsEndpoint,
	}

	info, err := comatproto.SyncGetRepoStatus(ctx, &xrpcc, ident.DID.String())
	if err != nil {
		return "", err
	}
	if info.Active {
		return "active", nil
	} else if info.Status != nil {
		return *info.Status, nil
	} else {
		return "inactive", nil
	}
}

type MockHostChecker struct {
	Hosts    map[string]bool
	Accounts map[string]string
}

func NewMockHostChecker() *MockHostChecker {
	return &MockHostChecker{
		Hosts:    make(map[string]bool),
		Accounts: make(map[string]string),
	}
}

func (hc *MockHostChecker) CheckHost(ctx context.Context, host string) error {
	_, ok := hc.Hosts[host]
	if !ok {
		return ErrHostNotPDS
	}
	return nil
}

func (hc *MockHostChecker) FetchAccountStatus(ctx context.Context, ident *identity.Identity) (string, error) {
	status, ok := hc.Accounts[ident.DID.String()]
	if !ok {
		return "", ErrAccountNotFound
	}
	return status, nil
}
