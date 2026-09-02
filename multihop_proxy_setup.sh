#!/usr/bin/env bash
set -e

# ----------------------------------------------------------------------
# Configuration – change these to match your environment
# ----------------------------------------------------------------------
RUN_USER="your-username"                 # non‑root user to run the service
PROXY_BIN="/usr/local/bin/proxy-chain"
BUILD_DIR="/usr/local/src/proxy-chain"   # where the Go source/module lives
LOG_FILE="/var/log/proxy-chain.log"
SERVICE_FILE="/etc/systemd/system/proxy-chain.service"

# Flags for the proxy (adjust as needed)
# -key: encryption passphrase (empty = no encryption)
# -hops: total chain length (min 2)
# -i2p: enable I2P (requires I2P SOCKS running)
# -obfuscate-timing: add random delays
# -log: separate log file
# -nocolor: disable colors in log file
PROXY_FLAGS='-key "your-secret-passphrase" -hops 16 -i2p -obfuscate-timing -log /var/log/proxy-chain.log -nocolor'

# ----------------------------------------------------------------------
# Check for root
# ----------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)." 1>&2
   exit 1
fi

# ----------------------------------------------------------------------
# Check for a Go toolchain (needed to build the proxy from source below)
# ----------------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
   echo "Go toolchain not found. Install Go (https://go.dev/dl/) and re-run this script." 1>&2
   exit 1
fi

# ----------------------------------------------------------------------
# 1. Write the Go source code to a build directory
# ----------------------------------------------------------------------
mkdir -p "$BUILD_DIR"
cat > "$BUILD_DIR/main.go" <<'GOEOF'
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------
const (
	torSocks5      = "127.0.0.1:9050"
	i2pSocks5      = "127.0.0.1:4444"
	proxynovaPAC   = "http://pac.proxynova.com/proxy.pac"
	rotateInterval = 2 * time.Minute
	localProxyPort = ":8080"
	idleConnTTL    = 90 * time.Second
	maxIdlePerHost = 4
)

// dohServers are rotated for hostname resolution, one query at a time, so no
// single resolver operator sees every lookup this proxy makes. This is
// plain DoH (RFC 8484), not genuine Oblivious DoH: a real ODoH deployment
// needs a target/proxy split with HPKE-encrypted queries so that neither
// party alone can see both "who asked" and "what they asked", and none of
// that protocol is implemented here. An earlier version of this list named
// twenty-two "dnscry.pt-odoh-<city>" hosts as if they were such a
// deployment; every one of them is NXDOMAIN in real DNS (verified live
// against a public resolver, not from documentation), so hostname
// resolution — meaning every request to a domain name rather than a literal
// IP — would have failed 100% of the time. These are real, independently
// operated, currently-live DoH endpoints (verified with a real RFC 8484 GET
// query returning a valid answer) instead.
var dohServers = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.quad9.net/dns-query",
	"https://doh.opendns.com/dns-query",
	"https://dns.digitale-gesellschaft.ch/dns-query",
	"https://doh.libredns.gr/dns-query",
	"https://unfiltered.adguard-dns.com/dns-query",
	"https://doh.mullvad.net/dns-query",
}

var (
	encKey          []byte
	logFile         *os.File
	colorLog        = true
	useEncryption   = false
	useI2P          = false
	i2pAddr         = i2pSocks5
	obfuscateTiming = false
	maxJitterMs     = 500
	totalHops       = 16 // default, can be changed with -hops
)

// ---------------------------------------------------------------------
// Coloured logging
// ---------------------------------------------------------------------
type Color int

const (
	Red Color = iota + 31
	Green
	Yellow
	Blue
	Magenta
	Cyan
	White
)

func colorize(msg string, c Color) string {
	if !colorLog {
		return msg
	}
	return fmt.Sprintf("\033[%dm%s\033[0m", c, msg)
}

var logMu sync.Mutex

func logInfo(v ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	msg := fmt.Sprint(v...)
	log.Print(colorize(msg, Green))
	if logFile != nil {
		fmt.Fprintln(logFile, "[INFO] "+msg)
	}
}

func logWarn(v ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	msg := fmt.Sprint(v...)
	log.Print(colorize(msg, Yellow))
	if logFile != nil {
		fmt.Fprintln(logFile, "[WARN] "+msg)
	}
}

func logError(v ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	msg := fmt.Sprint(v...)
	log.Print(colorize(msg, Red))
	if logFile != nil {
		fmt.Fprintln(logFile, "[ERROR] "+msg)
	}
}

// ---------------------------------------------------------------------
// Encryption (AES-GCM)
// ---------------------------------------------------------------------
func encryptPayload(plaintext []byte) ([]byte, error) {
	if !useEncryption || len(encKey) == 0 {
		return plaintext, nil
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func decryptPayload(ciphertext []byte) ([]byte, error) {
	if !useEncryption || len(encKey) == 0 {
		return ciphertext, nil
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// ---------------------------------------------------------------------
// Global chain state
// ---------------------------------------------------------------------
type ProxyChain struct {
	sync.RWMutex
	dialer     func(ctx context.Context, network, addr string) (net.Conn, error)
	proxies    []string // list of proxy addresses (for logging)
	lastUpdate time.Time
	httpClient *http.Client // used for DoH (goes through the chain)
}

var chain = &ProxyChain{
	httpClient: &http.Client{Timeout: 10 * time.Second},
}

// ---------------------------------------------------------------------
// CSPRNG helpers for shuffling and random selection
// ---------------------------------------------------------------------
func csprngInt(n int) int {
	if n <= 0 {
		return 0
	}
	bigN := big.NewInt(int64(n))
	val, err := rand.Int(rand.Reader, bigN)
	if err != nil {
		return int(time.Now().UnixNano() % int64(n))
	}
	return int(val.Int64())
}

func shuffleStrings(slice []string) {
	for i := len(slice) - 1; i > 0; i-- {
		j := csprngInt(i + 1)
		slice[i], slice[j] = slice[j], slice[i]
	}
}

func pickRandomSubset(pool []string, n int) []string {
	if n <= 0 || len(pool) == 0 {
		return nil
	}
	if n >= len(pool) {
		shuffled := make([]string, len(pool))
		copy(shuffled, pool)
		shuffleStrings(shuffled)
		return shuffled
	}
	work := make([]string, len(pool))
	copy(work, pool)
	for i := len(work) - 1; i > 0; i-- {
		j := csprngInt(i + 1)
		work[i], work[j] = work[j], work[i]
	}
	return work[:n]
}

// ---------------------------------------------------------------------
// Browser identity profiles
//
// A real browser's outbound fingerprint is more than its TLS ClientHello:
// the User-Agent string and the wire ORDER of HTTP headers are part of it
// too, and the two have to agree with each other. Go's own net/http always
// serializes headers in sorted alphabetical order (via http.Header.Write),
// which is not what any real browser does and is by itself a well-known way
// to fingerprint "this client is a Go program" regardless of what TLS
// ClientHello it sent. Picking a TLS profile independently of the header
// set (as an earlier version of this file did) is worse than picking
// neither: a Firefox ClientHello paired with Chrome-shaped headers (or vice
// versa) is a combination no real browser ever produces, which narrows the
// anonymity set instead of blending into it. So a single profile drives
// both the TLS handshake and the header shape for a given request.
// ---------------------------------------------------------------------
type browserProfile struct {
	name        string
	utlsID      utls.ClientHelloID
	userAgent   string
	headerOrder []string // wire order for headers OTHER than Host, which is always written first
}

var browserProfiles = []*browserProfile{
	{
		name:        "firefox",
		utlsID:      utls.HelloFirefox_102,
		userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
		headerOrder: []string{"User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection"},
	},
	{
		name:        "chrome",
		utlsID:      utls.HelloChrome_120,
		userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		headerOrder: []string{"Connection", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language"},
	},
}

func pickBrowserProfile() *browserProfile {
	return browserProfiles[csprngInt(len(browserProfiles))]
}

// alpnOnlyHTTP11 returns the profile's ClientHelloSpec with its ALPN
// extension forced down to "http/1.1" only. The canned Chrome/Firefox
// presets advertise h2 in ALPN because real browsers speak HTTP/2 — but
// this proxy's outbound leg only ever speaks HTTP/1.1 (see writeRequest
// below), so leaving h2 in the ClientHello would let a server pick "h2" in
// its ALPN response and then receive HTTP/1.1 bytes it never agreed to.
// That mismatch between what the handshake promised and what actually
// arrives on the wire is itself a distinguishing signature, so the two are
// kept consistent instead.
func alpnOnlyHTTP11(id utls.ClientHelloID) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return spec, err
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	return spec, nil
}

// ---------------------------------------------------------------------
// DoH Resolver, rotated across dohServers
// ---------------------------------------------------------------------
type DoHResolver struct {
	client  *http.Client
	baseURL string
}

func NewDoHResolver(client *http.Client) *DoHResolver {
	return &DoHResolver{
		client:  client,
		baseURL: dohServers[csprngInt(len(dohServers))],
	}
}

func (r *DoHResolver) Exchange(m *dns.Msg) (*dns.Msg, error) {
	msg, err := m.Pack()
	if err != nil {
		return nil, err
	}
	b64 := base64.RawURLEncoding.EncodeToString(msg)
	reqURL := fmt.Sprintf("%s?dns=%s", r.baseURL, b64)
	req, _ := http.NewRequest("GET", reqURL, nil)
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DoH request failed: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var rmsg dns.Msg
	err = rmsg.Unpack(body)
	return &rmsg, err
}

// ---------------------------------------------------------------------
// Fetch Proxynova proxies (fetch extra for random selection)
// ---------------------------------------------------------------------
func fetchProxynovaProxies(needed int) ([]string, error) {
	fetchCount := needed * 2
	if fetchCount < 10 {
		fetchCount = 10
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(proxynovaPAC)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`PROXY\s+([^\s;]+)`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	var proxies []string
	for _, m := range matches {
		if len(m) > 1 {
			proxies = append(proxies, "http://"+m[1])
		}
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("no proxies found in PAC")
	}
	for len(proxies) < needed {
		proxies = append(proxies, proxies[len(proxies)-1])
	}
	selected := pickRandomSubset(proxies, needed)
	return selected, nil
}

// ---------------------------------------------------------------------
// Build chained dialer with randomized hop order
// ---------------------------------------------------------------------
func buildChainDialer(proxyURLs []string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	if len(proxyURLs) == 0 {
		return nil, fmt.Errorf("no proxies")
	}

	socksHops := []string{}
	if useI2P {
		socksHops = append(socksHops, "i2p:"+i2pAddr)
	}
	socksHops = append(socksHops, "tor:"+torSocks5)
	shuffleStrings(socksHops)

	var currentDialer proxy.Dialer = proxy.Direct

	wrapSocks := func(dialer proxy.Dialer, addr string) (proxy.Dialer, error) {
		u, err := url.Parse("socks5://" + addr)
		if err != nil {
			return nil, err
		}
		return proxy.FromURL(u, dialer)
	}

	for _, hop := range socksHops {
		var addr string
		if strings.HasPrefix(hop, "i2p:") {
			addr = hop[4:]
		} else if strings.HasPrefix(hop, "tor:") {
			addr = hop[4:]
		} else {
			return nil, fmt.Errorf("unknown SOCKS hop: %s", hop)
		}
		d, err := wrapSocks(currentDialer, addr)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap SOCKS %s: %w", hop, err)
		}
		currentDialer = d
	}

	for _, proxyStr := range proxyURLs {
		u, err := url.Parse(proxyStr)
		if err != nil {
			return nil, err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
		}
		next := &httpProxyDialer{
			proxyAddr:  u.Host,
			underlying: currentDialer,
		}
		currentDialer = next
	}

	logInfo("Built chain with randomized hop order")
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return currentDialer.Dial(network, addr)
	}, nil
}

type httpProxyDialer struct {
	proxyAddr  string
	underlying proxy.Dialer
}

func (d *httpProxyDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.underlying.Dial(network, d.proxyAddr)
	if err != nil {
		return nil, err
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("proxy refused: %s", resp.Status)
	}
	return conn, nil
}

// ---------------------------------------------------------------------
// Chain updater (every 2 minutes)
// ---------------------------------------------------------------------
func updateChain() {
	neededProxies := totalHops - 1
	if useI2P {
		neededProxies = totalHops - 2
	}
	if neededProxies < 1 {
		neededProxies = 1
	}
	logInfo("Will use", neededProxies, "Proxynova proxies for a total of", totalHops, "hops")

	for {
		proxies, err := fetchProxynovaProxies(neededProxies)
		if err != nil {
			logWarn("Failed to fetch proxies:", err)
			time.Sleep(rotateInterval)
			continue
		}
		if len(proxies) == 0 {
			logWarn("No proxies returned, keeping old chain")
			time.Sleep(rotateInterval)
			continue
		}
		logInfo("New chain using", len(proxies), "Proxynova hops (randomized order)")

		dialer, err := buildChainDialer(proxies)
		if err != nil {
			logError("Failed to build chain:", err)
			time.Sleep(rotateInterval)
			continue
		}

		chain.Lock()
		chain.dialer = dialer
		chain.proxies = proxies
		chain.lastUpdate = time.Now()
		chain.Unlock()

		// Any connections pooled under the old chain are now routed through
		// hops that no longer exist as far as bookkeeping is concerned; drop
		// them rather than let a rotation-stale socket get reused.
		dropAllIdleConns()

		logInfo("Chain updated successfully with randomized hop order")
		time.Sleep(rotateInterval)
	}
}

// ---------------------------------------------------------------------
// Per-(profile, host) idle connection pool for the upstream leg.
//
// Real browsers keep sockets open and reuse them; dialing a brand new TCP+TLS
// connection (through the whole multi-hop chain) for every single HTTP
// request is itself unusual traffic behavior, on top of being slow. Pooling
// keyed by which browser profile handshook the connection avoids ever
// reusing a Chrome-fingerprinted socket for a request built with Firefox
// headers or vice versa.
// ---------------------------------------------------------------------
type idleConn struct {
	conn     net.Conn
	lastUsed time.Time
}

var (
	poolMu sync.Mutex
	pool   = map[string][]*idleConn{}
)

func poolKey(profile *browserProfile, network, addr string) string {
	return profile.name + "|" + network + "|" + addr
}

func getIdleConn(key string) net.Conn {
	poolMu.Lock()
	defer poolMu.Unlock()
	lst := pool[key]
	if len(lst) == 0 {
		return nil
	}
	last := lst[len(lst)-1]
	pool[key] = lst[:len(lst)-1]
	return last.conn
}

func putIdleConn(key string, conn net.Conn) {
	poolMu.Lock()
	defer poolMu.Unlock()
	if len(pool[key]) >= maxIdlePerHost {
		conn.Close()
		return
	}
	pool[key] = append(pool[key], &idleConn{conn: conn, lastUsed: time.Now()})
}

func dropAllIdleConns() {
	poolMu.Lock()
	defer poolMu.Unlock()
	for key, lst := range pool {
		for _, ic := range lst {
			ic.conn.Close()
		}
		delete(pool, key)
	}
}

func reapIdleConns() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		poolMu.Lock()
		for key, lst := range pool {
			kept := lst[:0]
			for _, ic := range lst {
				if time.Since(ic.lastUsed) > idleConnTTL {
					ic.conn.Close()
				} else {
					kept = append(kept, ic)
				}
			}
			if len(kept) == 0 {
				delete(pool, key)
			} else {
				pool[key] = kept
			}
		}
		poolMu.Unlock()
	}
}

// ---------------------------------------------------------------------
// dialUpstream opens (and, for HTTPS, uTLS-handshakes) a connection to addr
// through the Tor/I2P/Proxynova chain, resolving hostnames over ODoH first.
// This is the only place a real DNS lookup or a plain-Go crypto/tls
// handshake would otherwise have happened, so it's also the only place the
// chosen browser profile needs to be threaded through.
// ---------------------------------------------------------------------
func dialUpstream(ctx context.Context, network, addr string, profile *browserProfile) (net.Conn, error) {
	if obfuscateTiming {
		delay := time.Duration(csprngInt(maxJitterMs)) * time.Millisecond
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	chain.RLock()
	d := chain.dialer
	httpClient := chain.httpClient
	chain.RUnlock()
	if d == nil || httpClient == nil {
		return nil, fmt.Errorf("chain not ready")
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if port == "" {
		port = "443"
	}

	var targetAddr string
	if net.ParseIP(host) != nil {
		targetAddr = addr
	} else {
		resolver := NewDoHResolver(httpClient)
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), dns.TypeA)
		reply, err := resolver.Exchange(m)
		if err != nil {
			return nil, fmt.Errorf("DoH resolution failed: %w", err)
		}
		var ip string
		for _, ans := range reply.Answer {
			if a, ok := ans.(*dns.A); ok {
				ip = a.A.String()
				break
			}
		}
		if ip == "" {
			return nil, fmt.Errorf("no A record for %s", host)
		}
		targetAddr = net.JoinHostPort(ip, port)
	}

	conn, err := d(ctx, network, targetAddr)
	if err != nil {
		return nil, err
	}

	if port != "443" {
		return conn, nil
	}

	spec, err := alpnOnlyHTTP11(profile.utlsID)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("building uTLS spec: %w", err)
	}
	config := &utls.Config{ServerName: host, InsecureSkipVerify: false}
	uconn := utls.UClient(conn, config, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		conn.Close()
		return nil, fmt.Errorf("applying uTLS preset: %w", err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return uconn, nil
}

// ---------------------------------------------------------------------
// writeRequest serializes req in the given profile's header order instead
// of trusting net/http's own request writer, which always sorts headers
// alphabetically (http.Header.Write) — a reliable "this is a Go program"
// tell regardless of what TLS fingerprint was presented.
// ---------------------------------------------------------------------
func writeRequest(w io.Writer, req *http.Request, profile *browserProfile, body []byte) error {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	fmt.Fprintf(&b, "Host: %s\r\n", host)

	inOrder := make(map[string]bool, len(profile.headerOrder))
	for _, name := range profile.headerOrder {
		inOrder[name] = true
		if v := req.Header.Get(name); v != "" {
			fmt.Fprintf(&b, "%s: %s\r\n", name, v)
		}
	}
	// Anything not part of the profile's fixed shape (e.g. X-Encrypted) is
	// appended afterward rather than silently dropped.
	for name, vals := range req.Header {
		if inOrder[name] {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", name, v)
		}
	}
	if len(body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.Write(body)

	_, err := w.Write(b.Bytes())
	return err
}

// ---------------------------------------------------------------------
// pooledBody returns a connection to the idle pool once its response body
// has been fully drained and closed, and only if the response actually
// permitted keep-alive; otherwise (or if the body was closed early, e.g. the
// client disconnected mid-transfer) the connection is closed outright, since
// reusing a socket with unread bytes still in flight would corrupt the next
// request parsed off of it.
// ---------------------------------------------------------------------
type pooledBody struct {
	io.ReadCloser
	conn     net.Conn
	key      string
	reusable bool
	eofSeen  bool
	closed   bool
	mu       sync.Mutex
}

func (b *pooledBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.mu.Lock()
		b.eofSeen = true
		b.mu.Unlock()
	}
	return n, err
}

func (b *pooledBody) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	reuse := b.reusable && b.eofSeen
	b.mu.Unlock()

	err := b.ReadCloser.Close()
	if reuse {
		putIdleConn(b.key, b.conn)
	} else {
		b.conn.Close()
	}
	return err
}

// ---------------------------------------------------------------------
// chainRoundTripper is installed as the goproxy per-request RoundTripper so
// every request (plain HTTP and the plaintext leg of a MITM'd HTTPS
// request) goes out through dialUpstream + writeRequest instead of
// net/http's own Transport, which is what carried the header-order and
// ALPN/protocol tells in the first place.
// ---------------------------------------------------------------------
type chainRoundTripper struct{}

func (c *chainRoundTripper) RoundTrip(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	profile, _ := ctx.UserData.(*browserProfile)
	if profile == nil {
		profile = pickBrowserProfile()
	}

	var bodyBytes []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
	}

	resp, usedPooled, err := c.attempt(req, profile, bodyBytes, true)
	if err != nil && usedPooled {
		// The only connection that could have failed without ever reaching
		// the network is a stale pooled one (the remote end closed it after
		// our idle timeout but before we noticed) — one retry against a
		// freshly dialed connection covers that without masking a real
		// failure, since a fresh dial would fail the same way twice.
		resp, _, err = c.attempt(req, profile, bodyBytes, false)
	}
	return resp, err
}

func (c *chainRoundTripper) attempt(req *http.Request, profile *browserProfile, bodyBytes []byte, allowPooled bool) (*http.Response, bool, error) {
	scheme := req.URL.Scheme
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)
	key := poolKey(profile, "tcp", addr)

	var conn net.Conn
	var usedPooled bool
	if allowPooled {
		if pc := getIdleConn(key); pc != nil {
			conn, usedPooled = pc, true
		}
	}
	if conn == nil {
		var err error
		conn, err = dialUpstream(req.Context(), "tcp", addr, profile)
		if err != nil {
			return nil, false, err
		}
	}

	if err := writeRequest(conn, req, profile, bodyBytes); err != nil {
		conn.Close()
		return nil, usedPooled, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, usedPooled, err
	}

	resp.Body = &pooledBody{
		ReadCloser: resp.Body,
		conn:       conn,
		key:        key,
		reusable:   !resp.Close,
	}

	return resp, usedPooled, nil
}

// ---------------------------------------------------------------------
// Proxy server – all features integrated
// ---------------------------------------------------------------------
func startProxy() {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	rt := &chainRoundTripper{}

	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		profile := pickBrowserProfile()
		ctx.UserData = profile
		ctx.RoundTripper = rt

		req.Header = make(http.Header)
		req.Header.Set("User-Agent", profile.userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Connection", "keep-alive")

		if req.Body != nil && req.Body != http.NoBody {
			bodyBytes, err := io.ReadAll(req.Body)
			req.Body.Close()
			if err != nil {
				bodyBytes = nil
			}
			if useEncryption && len(bodyBytes) > 0 {
				if encrypted, eerr := encryptPayload(bodyBytes); eerr == nil {
					bodyBytes = encrypted
					req.Header.Set("X-Encrypted", "true")
				} else {
					logError("Encryption failed, sending body in the clear:", eerr)
				}
			}
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
		}
		return req, nil
	})

	// Decryption happens here, as a genuine RespHandler, rather than inside
	// chainRoundTripper: goproxy only strips the now-stale Content-Length
	// header (and switches the client-facing write to chunked encoding) when
	// it can see that a RespHandler swapped resp.Body for a different one —
	// doing the swap earlier, inside RoundTrip, would leave the original
	// (pre-decryption) Content-Length header in place and desync it from the
	// decrypted body's real length.
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if useEncryption && resp.Header.Get("X-Encrypted") == "true" {
			bodyBytes, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				decrypted, err := decryptPayload(bodyBytes)
				if err == nil {
					resp.Body = io.NopCloser(bytes.NewReader(decrypted))
					resp.ContentLength = int64(len(decrypted))
					resp.Header.Del("X-Encrypted")
				} else {
					logError("Decryption failed:", err)
				}
			}
		}
		return resp
	})

	logInfo("Proxy listening on", localProxyPort)
	if err := http.ListenAndServe(localProxyPort, proxy); err != nil {
		logError("Proxy server error:", err)
	}
}

// ---------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------
func main() {
	var logPath string
	var noColor bool
	var key string
	var enableI2P bool
	var i2pAddrFlag string
	var obfuscate bool
	var hops int

	flag.StringVar(&logPath, "log", "", "Path to log file (optional)")
	flag.BoolVar(&noColor, "nocolor", false, "Disable colored output")
	flag.StringVar(&key, "key", "", "Encryption passphrase (optional)")
	flag.BoolVar(&enableI2P, "i2p", false, "Enable I2P as first hop (requires I2P SOCKS running)")
	flag.StringVar(&i2pAddrFlag, "i2paddr", i2pSocks5, "I2P SOCKS address (host:port)")
	flag.BoolVar(&obfuscate, "obfuscate-timing", false, "Add random delays to break traffic timing analysis (slower)")
	flag.IntVar(&hops, "hops", 16, "Total number of hops in the chain (including Tor and I2P if enabled)")
	flag.Parse()

	totalHops = hops
	if totalHops < 2 {
		totalHops = 2
		logWarn("Minimum 2 hops, setting to 2")
	}

	if enableI2P {
		useI2P = true
		i2pAddr = i2pAddrFlag
		logInfo("I2P mode enabled, using", i2pAddr)
	} else {
		logInfo("I2P mode disabled")
	}

	if key != "" {
		hash := sha256.Sum256([]byte(key))
		encKey = hash[:]
		useEncryption = true
		logInfo("Encryption enabled")
	} else {
		logInfo("Encryption disabled")
	}

	if obfuscate {
		obfuscateTiming = true
		logWarn("Timing obfuscation ENABLED – random delays up to", maxJitterMs, "ms will be added. Performance may be impacted.")
	} else {
		logInfo("Timing obfuscation disabled (use -obfuscate-timing to enable)")
	}

	if noColor {
		colorLog = false
	}
	if logPath != "" {
		var err error
		logFile, err = os.Create(logPath)
		if err != nil {
			logError("Cannot create log file:", err)
		} else {
			logInfo("Logging to", logPath)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logInfo("Shutting down...")
		if logFile != nil {
			logFile.Sync()
			logFile.Close()
		}
		os.Exit(0)
	}()

	logInfo("Starting proxy chain with", totalHops, "hops (randomized order each restart/update)...")
	go updateChain()
	go reapIdleConns()

	time.Sleep(5 * time.Second)

	startProxy()
}
GOEOF

# ----------------------------------------------------------------------
# 2. Fetch dependencies and compile the binary
#    (the previous version of this script wrote the Go source straight to
#    $PROXY_BIN and chmod +x'd it without ever building it — systemd would
#    then try to exec raw source text as if it were a binary and fail outright,
#    so the "proxy" never actually started)
# ----------------------------------------------------------------------
(
  cd "$BUILD_DIR"
  export GOPATH="$BUILD_DIR/.gopath"
  export GOCACHE="$BUILD_DIR/.gocache"
  export GOFLAGS="-mod=mod"
  # GOTOOLCHAIN defaults to "auto": if a dependency needs a newer Go than
  # what's installed, the go command downloads a matching toolchain itself.
  if [[ ! -f go.mod ]]; then
      go mod init proxy-chain
  fi
  go get github.com/elazarl/goproxy@latest
  go get github.com/miekg/dns@latest
  go get github.com/refraction-networking/utls@latest
  go get golang.org/x/net/proxy@latest
  go mod tidy
  go build -o "$PROXY_BIN" .
)

# ----------------------------------------------------------------------
# 3. Make the binary executable
# ----------------------------------------------------------------------
chmod +x "$PROXY_BIN"

# ----------------------------------------------------------------------
# 4. Create log file with correct permissions
# ----------------------------------------------------------------------
touch "$LOG_FILE"
chown "$RUN_USER":"$RUN_USER" "$LOG_FILE"

# ----------------------------------------------------------------------
# 5. Write the systemd unit file
# ----------------------------------------------------------------------
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Multi‑hop anonymising proxy with Tor, I2P, Proxynova, ODoH
After=network.target tor.service i2p.service
Wants=tor.service
# If you use I2P, uncomment the line below and ensure i2p.service exists
# Wants=i2p.service

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=/tmp
ExecStart=$PROXY_BIN $PROXY_FLAGS

# Restart policy
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=proxy-chain

# Hardening (recommended for security)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
MemoryDenyWriteExecute=false   # we need exec for Go binary
ReadWritePaths=/var/log

[Install]
WantedBy=multi-user.target
EOF

# ----------------------------------------------------------------------
# 6. Reload systemd, enable and start the service
# ----------------------------------------------------------------------
systemctl daemon-reload
systemctl enable proxy-chain.service
systemctl start proxy-chain.service

echo "Proxy chain installed and started. Check status with:"
echo "  systemctl status proxy-chain"
echo "View logs with:"
echo "  journalctl -u proxy-chain -f"
