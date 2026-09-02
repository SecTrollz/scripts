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
	"crypto/tls"
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
)

// ODoH servers from your screenshots
var odohServers = []string{
	"dnscry.pt-odoh-atlanta",
	"dnscry.pt-odoh-berkeleysprings",
	"dnscry.pt-odoh-detroit",
	"dnscry.pt-odoh-chicago",
	"dnscry.pt-odoh-halifax",
	"dnscry.pt-odoh-grandrapids",
	"dnscry.pt-odoh-flint",
	"dnscry.pt-odoh-portedwards",
	"dnscry.pt-odoh-denver",
	"dnscry.pt-odoh-sanjose",
	"dnscry.pt-odoh-santaclara",
	"dnscry.pt-odoh-seattle",
	"dnscry.pt-odoh-phoenix",
	"dnscry.pt-odoh-portland",
	"dnscry.pt-odoh-prague",
	"dnscry.pt-odoh-lasvegas",
	"dnscry.pt-odoh-libertylake",
	"dnscry.pt-odoh-lisbon",
	"dnscry.pt-odoh-geneva",
	"dnscry.pt-odoh-frankfurt",
	"dnscry.pt-odoh-copenhagen",
	"dnscry.pt-odoh-dublin",
}

const dohBaseDomain = "dnscry.pt"

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
// Encryption (AES-GCM) with buffer pooling
// ---------------------------------------------------------------------
var bufPool = sync.Pool{
	New: func() interface{} { return new(bytes.Buffer) },
}

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
		// fallback to time-based (should not happen)
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

// pickRandomSubset picks `n` random elements from `pool` (without replacement) and returns them in random order.
func pickRandomSubset(pool []string, n int) []string {
	if n <= 0 || len(pool) == 0 {
		return nil
	}
	if n >= len(pool) {
		// shuffle and return all
		shuffled := make([]string, len(pool))
		copy(shuffled, pool)
		shuffleStrings(shuffled)
		return shuffled
	}
	// Fisher-Yates style selection: create a copy, then shuffle only the first n elements
	work := make([]string, len(pool))
	copy(work, pool)
	// Shuffle the whole slice but we only need first n
	for i := len(work) - 1; i > 0; i-- {
		j := csprngInt(i + 1)
		work[i], work[j] = work[j], work[i]
	}
	return work[:n]
}

// ---------------------------------------------------------------------
// DoH Resolver using ODoH servers (rotated)
// ---------------------------------------------------------------------
type DoHResolver struct {
	client  *http.Client
	baseURL string
}

func NewDoHResolver(client *http.Client) *DoHResolver {
	server := odohServers[csprngInt(len(odohServers))]
	url := fmt.Sprintf("https://%s.%s/dns-query", server, dohBaseDomain)
	return &DoHResolver{
		client:  client,
		baseURL: url,
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
	// Fetch more than needed to have a pool for random selection
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
	// If we have fewer than needed, repeat the last one to fill
	for len(proxies) < needed {
		proxies = append(proxies, proxies[len(proxies)-1])
	}
	// Pick a random subset of size 'needed' and shuffle it
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
	// We'll construct the chain dynamically.

	// 1. Collect SOCKS hops (I2P and Tor)
	socksHops := []string{}
	if useI2P {
		socksHops = append(socksHops, "i2p:"+i2pAddr)
	}
	socksHops = append(socksHops, "tor:"+torSocks5)

	// Randomize order of SOCKS hops
	shuffleStrings(socksHops)

	// 2. Build a list of dialer constructors in the chosen order
	var currentDialer proxy.Dialer = proxy.Direct

	// Helper to wrap with SOCKS5 proxy
	wrapSocks := func(dialer proxy.Dialer, addr string) (proxy.Dialer, error) {
		u, err := url.Parse("socks5://" + addr)
		if err != nil {
			return nil, err
		}
		return proxy.FromURL(u, dialer)
	}

	// Apply SOCKS hops
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

	// 3. Add HTTP CONNECT proxies (Proxynova) – they are already shuffled
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
	// Compute how many Proxynova proxies we need
	neededProxies := totalHops - 1 // Tor is always one hop, but might be randomized with I2P
	if useI2P {
		neededProxies = totalHops - 2 // I2P and Tor take two slots
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
		transport := &http.Transport{
			DialContext: dialer,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		}

		chain.Lock()
		chain.dialer = dialer
		chain.proxies = proxies
		chain.lastUpdate = time.Now()
		chain.httpClient = httpClient
		chain.Unlock()

		logInfo("Chain updated successfully with randomized hop order")
		time.Sleep(rotateInterval)
	}
}

// ---------------------------------------------------------------------
// IP spoofing – generate a fake IP for each hop (now randomized order)
// ---------------------------------------------------------------------
var spoofPool = []string{
	"192.168.1.1", "10.0.0.1", "172.16.0.1",
	"45.33.22.11", "104.248.0.1", "159.89.0.1",
	"198.51.100.0", "203.0.113.0",
	"54.0.0.0", "52.0.0.0", "35.0.0.0",
}

func getRandomSpoofIP() string {
	return spoofPool[csprngInt(len(spoofPool))]
}

// getSpoofedIPChain returns a comma‑separated list of fake IPs, one per hop.
func getSpoofedIPChain() string {
	hopCount := totalHops
	ips := make([]string, hopCount)
	for i := 0; i < hopCount; i++ {
		ips[i] = getRandomSpoofIP()
	}
	return strings.Join(ips, ", ")
}

// ---------------------------------------------------------------------
// Custom Transport with utls, DoH, connection pooling, and timing obfuscation
// ---------------------------------------------------------------------
func newCustomTransport() *http.Transport {
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// ---- TIMING OBFUSCATION ----
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
		if net.ParseIP(host) != nil {
			return d(ctx, network, addr)
		}
		// Resolve via DoH (random ODoH server)
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
		targetAddr := net.JoinHostPort(ip, port)
		conn, err := d(ctx, network, targetAddr)
		if err != nil {
			return nil, err
		}
		if port == "443" {
			config := &utls.Config{ServerName: host, InsecureSkipVerify: false}
			var uconn *utls.UConn
			if time.Now().Unix()%2 == 0 {
				uconn = utls.UClient(conn, config, utls.HelloFirefox_102)
			} else {
				uconn = utls.UClient(conn, config, utls.HelloChrome_120)
			}
			if err := uconn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return uconn, nil
		}
		return conn, nil
	}

	return &http.Transport{
		DialContext:         dialer,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}
}

// ---------------------------------------------------------------------
// Proxy server – all features integrated
// ---------------------------------------------------------------------
func startProxy() {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	proxy.Tr = newCustomTransport()

	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Strip all existing headers
		req.Header = make(http.Header)

		// Add chain‑spoofed X-Forwarded-For (one IP per hop)
		req.Header.Set("X-Forwarded-For", getSpoofedIPChain())

		// Set minimal browser-like headers
		req.Header.Set("User-Agent", randomUserAgent())
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Connection", "keep-alive")

		// Encrypt body if enabled
		if useEncryption && req.Body != nil && req.Body != http.NoBody {
			bodyBytes, err := io.ReadAll(req.Body)
			req.Body.Close()
			if err == nil && len(bodyBytes) > 0 {
				encrypted, err := encryptPayload(bodyBytes)
				if err == nil {
					req.Body = io.NopCloser(bytes.NewReader(encrypted))
					req.Header.Set("X-Encrypted", "true")
					req.ContentLength = int64(len(encrypted))
				} else {
					logError("Encryption failed:", err)
				}
			}
		}
		return req, nil
	})

	// Decrypt response if encrypted
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
// Utilities
// ---------------------------------------------------------------------
func randomUserAgent() string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
	}
	return uas[time.Now().Unix()%int64(len(uas))]
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

	// Graceful shutdown
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

	// Wait for first chain to build
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
