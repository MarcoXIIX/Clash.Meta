//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// Two engines in one process against a real coordination server. Needs
//
//	GG_TS_CONTROL_URL  the server, e.g. https://headscale.example
//	GG_TS_AUTHKEY_A/B  files holding one pre-auth key each (same user)
//
// and is skipped without them.
func TestTailscaleListenAcceptsPeer(t *testing.T) {
	control := os.Getenv("GG_TS_CONTROL_URL")
	keyA := readKey(t, "GG_TS_AUTHKEY_A")
	keyB := readKey(t, "GG_TS_AUTHKEY_B")
	if control == "" || keyA == "" || keyB == "" {
		t.Skip("no coordination server given")
	}
	C.SetHomeDir(t.TempDir())

	node := func(name, key string) *Tailscale {
		ts, err := NewTailscale(TailscaleOption{
			Name:       name,
			Hostname:   name,
			AuthKey:    key,
			ControlURL: control,
			StateDir:   name,
			Ephemeral:  true,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ts.Close() })
		return ts
	}
	a, b := node("gg-test-a", keyA), node("gg-test-b", keyB)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	const port = 47801
	ln, err := a.Listen(ctx, port)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err = b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	addrA := waitAddr(ctx, t, a)
	keyOfB := waitNodeKey(ctx, t, b)

	payload := make([]byte, 4<<20)
	if _, err = rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)

	type accepted struct {
		peer *TailscalePeer
		sum  [32]byte
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- accepted{err: err}
			return
		}
		defer conn.Close()
		peer, err := a.WhoIs(ctx, conn.RemoteAddr())
		if err != nil {
			done <- accepted{err: err}
			return
		}
		hash := sha256.New()
		if _, err = io.Copy(hash, conn); err != nil {
			done <- accepted{err: err}
			return
		}
		var sum [32]byte
		copy(sum[:], hash.Sum(nil))
		done <- accepted{peer: peer, sum: sum}
	}()

	metadata := &C.Metadata{NetWork: C.TCP, DstIP: addrA, DstPort: port}
	var conn net.Conn
	for {
		conn, err = b.DialContext(ctx, metadata)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("dial: %v", err)
		case <-time.After(time.Second):
		}
	}
	start := time.Now()
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.sum != want {
			t.Fatal("payload arrived damaged")
		}
		if got.peer.NodeKey != keyOfB {
			t.Fatalf("accepted %s, dialled from %s", got.peer.NodeKey, keyOfB)
		}
		direct, relay, err := a.PeerPath(ctx, got.peer.NodeKey)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("peer %q (user %q), %d bytes in %s, direct=%v relay=%q",
			got.peer.Name, got.peer.User, len(payload), time.Since(start).Round(time.Millisecond),
			direct != "", relay)
	case <-ctx.Done():
		t.Fatal("nothing arrived")
	}
}

func readKey(t *testing.T, env string) string {
	path := os.Getenv(env)
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func waitAddr(ctx context.Context, t *testing.T, ts *Tailscale) netip.Addr {
	for {
		if v4, _ := ts.Addrs(); v4.IsValid() {
			return v4
		}
		select {
		case <-ctx.Done():
			t.Fatal("engine got no address")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func waitNodeKey(ctx context.Context, t *testing.T, ts *Tailscale) string {
	for {
		if key, err := ts.NodeKey(ctx); err == nil {
			return key
		}
		select {
		case <-ctx.Done():
			t.Fatal("engine got no identity")
		case <-time.After(200 * time.Millisecond):
		}
	}
}
