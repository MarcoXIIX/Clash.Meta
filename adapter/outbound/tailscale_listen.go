//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
)

// TailscalePeer is the node behind a connection that Listen accepted, as the
// engine knows it from the coordination server and the WireGuard session.
// Nothing in it comes from what the peer sent over the connection.
type TailscalePeer struct {
	NodeKey string
	Name    string
	User    string
	Addrs   []netip.Addr
}

// Start brings the engine up without waiting for a first dial, so that a
// node which only receives is present on the tailnet.
func (t *Tailscale) Start(ctx context.Context) error {
	return t.ensureStarted(ctx)
}

// Addrs returns this node's tailnet addresses, invalid until the engine has
// been given them.
func (t *Tailscale) Addrs() (v4, v6 netip.Addr) {
	return t.server.TailscaleIPs()
}

// Listen accepts TCP connections that peers open to this node's tailnet
// addresses on port. The listener lives inside the engine's own network
// stack; nothing is bound on the host.
func (t *Tailscale) Listen(ctx context.Context, port uint16) (net.Listener, error) {
	if err := t.ensureStarted(ctx); err != nil {
		return nil, err
	}
	return t.server.Listen("tcp", ":"+strconv.Itoa(int(port)))
}

// WhoIs names the peer at the remote address of an accepted connection.
func (t *Tailscale) WhoIs(ctx context.Context, remote net.Addr) (*TailscalePeer, error) {
	if remote == nil {
		return nil, errors.New("no remote address")
	}
	lc, err := t.server.LocalClient()
	if err != nil {
		return nil, err
	}
	who, err := lc.WhoIs(ctx, remote.String())
	if err != nil {
		return nil, err
	}
	if who.Node == nil {
		return nil, errors.New("peer has no node")
	}
	peer := &TailscalePeer{
		NodeKey: who.Node.Key.String(),
		Name:    who.Node.ComputedName,
	}
	if who.UserProfile != nil {
		peer.User = who.UserProfile.LoginName
	}
	for _, prefix := range who.Node.Addresses {
		peer.Addrs = append(peer.Addrs, prefix.Addr())
	}
	return peer, nil
}

// PeerPath says how packets reach the peer with the given node key right
// now: a direct address, or the relay's region when there is none.
func (t *Tailscale) PeerPath(ctx context.Context, nodeKey string) (direct string, relay string, err error) {
	lc, err := t.server.LocalClient()
	if err != nil {
		return "", "", err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return "", "", err
	}
	for key, peer := range status.Peer {
		if key.String() == nodeKey {
			return peer.CurAddr, peer.Relay, nil
		}
	}
	return "", "", errors.New("peer not found")
}

// NodeKey returns this node's own public key once the engine runs.
func (t *Tailscale) NodeKey(ctx context.Context) (string, error) {
	lc, err := t.server.LocalClient()
	if err != nil {
		return "", err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return "", err
	}
	if status.Self == nil || status.Self.PublicKey.IsZero() {
		return "", errors.New("engine has no identity yet")
	}
	return status.Self.PublicKey.String(), nil
}
