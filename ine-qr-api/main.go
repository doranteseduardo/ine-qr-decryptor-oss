// INE QR Decoder — HTTP API
//
// Exposes the embedded ine_decode library as a stateless REST endpoint.
//
// Supported input formats for POST /decode:
//   multipart/form-data  — field "photo" (file upload)
//   application/json     — {"photo_base64": "<base64>", "filename": "cred.jpg"}
//
// Response: JSON with 18 biographical fields + "foto_base64" (WebP, base64).
//
// Concurrency model:
//   The decoder is invoked in-process via cgo (libine_decode.a). A semaphore
//   caps concurrent decodes; once full a request waits up to QUEUE_WAIT_MS
//   for a slot before returning 503. Per-API-key (or per-IP) rate limiting
//   sits in front of the semaphore so a single client cannot monopolise
//   the queue.
//
// Environment variables:
//   PORT             HTTP listen port (default: 8080)
//   API_KEY          If set, requests must carry X-API-Key: <value>
//   WORKERS          Concurrent decodes (default: NumCPU * 5/4)
//   QUEUE_WAIT_MS    Max wait for a worker slot before 503 (default: 2000)
//   MAX_BODY_MB      Max request body size in MiB (default: 25)
//   RATE_PER_SEC     Per-key/IP token bucket refill rate (default: 5)
//   RATE_BURST       Per-key/IP burst capacity         (default: 10)
//   MAX_LONG_EDGE    Downsample images longer than this (px). 0 = off.
//                    Default: 3000.
//   READ_TIMEOUT_S   ReadTimeout in seconds   (default: 30)
//   WRITE_TIMEOUT_S  WriteTimeout in seconds  (default: 60)
//   IDLE_TIMEOUT_S   IdleTimeout in seconds   (default: 120)
//   CORS_ORIGIN      Value for Access-Control-Allow-Origin (default: "*").
//                    Set to a specific origin (e.g. https://demo.example.com)
//                    if you ever need credentialed requests.

package main

/*
#cgo CFLAGS: -I${SRCDIR}/../ine-qr-c/include
#cgo LDFLAGS: -L${SRCDIR}/../ine-qr-c -line_decode -lZXing -lssl -lcrypto -lstdc++ -lm -lpthread

#include <stdlib.h>
#include "ine_lib.h"
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/time/rate"
)

// ─── Configuration ──────────────────────────────────────────────────────────

type config struct {
	port           string
	apiKey         string
	workers        int
	queueWaitMS    int
	maxBodyBytes   int64
	ratePerSec     float64
	rateBurst      int
	maxLongEdge    int
	readTimeoutS   int
	writeTimeoutS  int
	idleTimeoutS   int
	headerTimeoutS int
	corsOrigin     string
}

func loadConfig() config {
	c := config{
		port:           envOr("PORT", "8080"),
		apiKey:         os.Getenv("API_KEY"),
		workers:        envInt("WORKERS", runtime.NumCPU()*5/4),
		queueWaitMS:    envInt("QUEUE_WAIT_MS", 2000),
		maxBodyBytes:   int64(envInt("MAX_BODY_MB", 25)) << 20,
		ratePerSec:     envRateFloat("RATE_PER_SEC", 5),
		rateBurst:      envInt("RATE_BURST", 10),
		maxLongEdge:    envInt("MAX_LONG_EDGE", 3000),
		readTimeoutS:   envInt("READ_TIMEOUT_S", 30),
		writeTimeoutS:  envInt("WRITE_TIMEOUT_S", 60),
		idleTimeoutS:   envInt("IDLE_TIMEOUT_S", 120),
		headerTimeoutS: envInt("HEADER_TIMEOUT_S", 5),
		corsOrigin:     envOr("CORS_ORIGIN", "*"),
	}
	if c.workers < 1 {
		c.workers = 1
	}
	return c
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v, err := strconv.ParseFloat(os.Getenv(key), 64); err == nil && v > 0 {
		return v
	}
	return def
}

// envRateFloat is like envFloat but treats 0 (and negatives) as a valid
// "disabled" value rather than falling back to the default. Used only for
// RATE_PER_SEC where setting 0 explicitly turns off rate limiting.
func envRateFloat(key string, def float64) float64 {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return def
	}
	if v < 0 {
		return 0
	}
	return v
}

// ─── Server state ───────────────────────────────────────────────────────────

type server struct {
	cfg config
	sem chan struct{}

	// Rate limiting — one token bucket per identity (API key or remote IP).
	limMu  sync.Mutex
	limMap map[string]*rateEntry

	// Stats
	totalReq   atomic.Int64
	totalOK    atomic.Int64
	total4xx   atomic.Int64
	total5xx   atomic.Int64
	totalBusy  atomic.Int64
	inFlight   atomic.Int64
	queueDepth atomic.Int64
	latMu      sync.Mutex
	latencies  []time.Duration // ring buffer of recent successful decodes
}

type rateEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newServer(cfg config) *server {
	s := &server{
		cfg:       cfg,
		sem:       make(chan struct{}, cfg.workers),
		latencies: make([]time.Duration, 0, 1024),
	}
	// Allocate the per-identity bucket map only when rate limiting is on.
	// With ratePerSec == 0 the limiter is fully bypassed and the map +
	// sweeper goroutine are skipped (saves memory and one goroutine).
	if cfg.ratePerSec > 0 {
		s.limMap = make(map[string]*rateEntry)
	}
	return s
}

func (s *server) rateEnabled() bool { return s.cfg.ratePerSec > 0 }

// ─── Rate limiter ───────────────────────────────────────────────────────────

// limiterFor returns the token bucket for the given identity, lazily
// constructing one on first sight. A background sweep evicts entries idle
// for more than 10 minutes so the map cannot grow unboundedly under
// per-IP keying.
func (s *server) limiterFor(id string) *rate.Limiter {
	s.limMu.Lock()
	defer s.limMu.Unlock()
	if e, ok := s.limMap[id]; ok {
		e.lastSeen = time.Now()
		return e.limiter
	}
	lim := rate.NewLimiter(rate.Limit(s.cfg.ratePerSec), s.cfg.rateBurst)
	s.limMap[id] = &rateEntry{limiter: lim, lastSeen: time.Now()}
	return lim
}

func (s *server) sweepLimiters() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-10 * time.Minute)
		s.limMu.Lock()
		for k, e := range s.limMap {
			if e.lastSeen.Before(cutoff) {
				delete(s.limMap, k)
			}
		}
		s.limMu.Unlock()
	}
}

// identity picks the API key when present, falling back to the remote IP.
// X-Forwarded-For is honoured as a single hop; reject spoofing by trusting
// only the left-most address (typical when behind a reverse proxy).
func identity(r *http.Request) string {
	if k := r.Header.Get("X-API-Key"); k != "" {
		return "k:" + k
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if comma := strings.IndexByte(xff, ','); comma > 0 {
			xff = xff[:comma]
		}
		return "ip:" + strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return "ip:" + host
}

// ─── Decoder (cgo) ──────────────────────────────────────────────────────────

type decodeOutput struct {
	json []byte
	webp []byte
	qrMS float64
}

// decode invokes the embedded C library on the image bytes. Safe to call
// from many goroutines concurrently; the C side has no shared mutable
// state beyond a once-init character table.
func decode(img []byte, maxLongEdge int) (*decodeOutput, error) {
	if len(img) == 0 {
		return nil, errors.New("empty image")
	}

	var res C.IneResult
	rc := C.ine_decode_bytes(
		(*C.uint8_t)(unsafe.Pointer(&img[0])),
		C.size_t(len(img)),
		C.int(maxLongEdge),
		&res,
	)

	defer C.ine_result_free(&res)

	if rc != 0 || res.ok == 0 {
		errMsg := C.GoString(&res.err[0])
		if errMsg == "" {
			errMsg = "decode failed"
		}
		return nil, errors.New(errMsg)
	}

	// Copy out before C buffers are freed.
	out := &decodeOutput{
		qrMS: float64(res.qr_ms),
		json: C.GoBytes(unsafe.Pointer(res.json), C.int(res.json_len)),
	}
	if res.webp != nil && res.webp_len > 0 {
		out.webp = C.GoBytes(unsafe.Pointer(res.webp), C.int(res.webp_len))
	}
	return out, nil
}

// ─── HTTP handlers ──────────────────────────────────────────────────────────

func main() {
	cfg := loadConfig()
	s := newServer(cfg)
	if s.rateEnabled() {
		go s.sweepLimiters()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/decode", s.middleware(s.handleDecode))

	rateDesc := fmt.Sprintf("%.1f/s burst=%d", cfg.ratePerSec, cfg.rateBurst)
	if !s.rateEnabled() {
		rateDesc = "disabled"
	}
	log.Printf("INE QR API — workers=%d queue_wait=%dms max_body=%dMiB rate=%s max_long_edge=%dpx",
		cfg.workers, cfg.queueWaitMS, cfg.maxBodyBytes>>20,
		rateDesc, cfg.maxLongEdge)
	if cfg.apiKey == "" {
		log.Printf("WARNING: API_KEY not set — running without authentication")
	}

	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           s.corsMiddleware(mux),
		ReadHeaderTimeout: time.Duration(cfg.headerTimeoutS) * time.Second,
		ReadTimeout:       time.Duration(cfg.readTimeoutS) * time.Second,
		WriteTimeout:      time.Duration(cfg.writeTimeoutS) * time.Second,
		IdleTimeout:       time.Duration(cfg.idleTimeoutS) * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	log.Printf("listening on :%s", cfg.port)
	log.Fatal(srv.ListenAndServe())
}

// corsMiddleware sets Access-Control-* headers on every response and
// short-circuits OPTIONS preflight with 204. Required for browser clients
// that POST application/json (which is not a CORS-simple Content-Type and
// triggers a preflight). Multipart and simple GETs would work without this,
// but adding the headers uniformly keeps clients flexible.
//
// Allow-Origin defaults to "*" (matches the API-key auth model: the secret
// is the key, not the origin). Set CORS_ORIGIN to a specific origin only if
// you later need credentialed requests (cookies / Authorization with
// withCredentials), in which case "*" is forbidden by the spec.
func (s *server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", s.cfg.corsOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
		w.Header().Set("Access-Control-Max-Age", "86400")
		// Vary so caches don't serve a response with the wrong CORS header
		// to a different origin (matters once CORS_ORIGIN is non-"*").
		w.Header().Add("Vary", "Origin")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// middleware composes API-key auth + rate limiting in front of a handler.
// /healthz and /stats are intentionally kept outside this chain so monitors
// can poll them without consuming rate budget.
//
// Rate limiting is fully bypassed when RATE_PER_SEC <= 0; the middleware
// drops straight through to the handler with nothing more than auth.
func (s *server) middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.totalReq.Add(1)
		if s.cfg.apiKey != "" && r.Header.Get("X-API-Key") != s.cfg.apiKey {
			s.total4xx.Add(1)
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if s.rateEnabled() && !s.limiterFor(identity(r)).Allow() {
			s.total4xx.Add(1)
			w.Header().Set("Retry-After", "1")
			jsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{"status":"ok"}`)
}

func (s *server) handleStats(w http.ResponseWriter, _ *http.Request) {
	stats := map[string]any{
		"workers":     s.cfg.workers,
		"in_flight":   s.inFlight.Load(),
		"queued":      s.queueDepth.Load(),
		"total_req":   s.totalReq.Load(),
		"total_ok":    s.totalOK.Load(),
		"total_4xx":   s.total4xx.Load(),
		"total_5xx":   s.total5xx.Load(),
		"total_busy":  s.totalBusy.Load(),
		"latency_p50": s.latencyPct(0.50).String(),
		"latency_p95": s.latencyPct(0.95).String(),
		"latency_p99": s.latencyPct(0.99).String(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats) //nolint:errcheck
}

func (s *server) recordLatency(d time.Duration) {
	s.latMu.Lock()
	defer s.latMu.Unlock()
	if len(s.latencies) >= 1024 {
		copy(s.latencies, s.latencies[1:])
		s.latencies = s.latencies[:1023]
	}
	s.latencies = append(s.latencies, d)
}

func (s *server) latencyPct(p float64) time.Duration {
	s.latMu.Lock()
	defer s.latMu.Unlock()
	if len(s.latencies) == 0 {
		return 0
	}
	cp := make([]time.Duration, len(s.latencies))
	copy(cp, s.latencies)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := int(float64(len(cp)-1) * p)
	return cp[idx]
}

// ─── /decode ────────────────────────────────────────────────────────────────

type photoInput struct {
	data     []byte
	filename string
}

func (s *server) extractPhoto(w http.ResponseWriter, r *http.Request) (*photoInput, error) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)
	ct := r.Header.Get("Content-Type")

	switch {
	case strings.HasPrefix(ct, "multipart/form-data"):
		if err := r.ParseMultipartForm(s.cfg.maxBodyBytes); err != nil {
			return nil, fmt.Errorf("invalid multipart form: %w", err)
		}
		file, header, err := r.FormFile("photo")
		if err != nil {
			return nil, fmt.Errorf("photo field required")
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("read error: %w", err)
		}
		return &photoInput{data: data, filename: header.Filename}, nil

	case strings.HasPrefix(ct, "application/json"):
		var body struct {
			PhotoBase64 string `json:"photo_base64"`
			Filename    string `json:"filename"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, fmt.Errorf("invalid JSON body: %w", err)
		}
		if body.PhotoBase64 == "" {
			return nil, fmt.Errorf("photo_base64 field required")
		}
		data, err := base64.StdEncoding.DecodeString(body.PhotoBase64)
		if err != nil {
			data, err = base64.URLEncoding.DecodeString(body.PhotoBase64)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid base64 encoding")
		}
		return &photoInput{data: data, filename: body.Filename}, nil

	default:
		return nil, fmt.Errorf("Content-Type must be multipart/form-data or application/json")
	}
}

// acquireSlot tries to claim a worker slot. Returns:
//   - nil           : slot acquired, caller must release with releaseSlot
//   - errBusy       : queue full, return 503
//   - context error : client cancelled
func (s *server) acquireSlot(r *http.Request) error {
	s.queueDepth.Add(1)
	defer s.queueDepth.Add(-1)

	// Fast path — slot immediately available.
	select {
	case s.sem <- struct{}{}:
		s.inFlight.Add(1)
		return nil
	default:
	}

	wait := time.Duration(s.cfg.queueWaitMS) * time.Millisecond
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case s.sem <- struct{}{}:
		s.inFlight.Add(1)
		return nil
	case <-timer.C:
		return errBusy
	case <-r.Context().Done():
		return r.Context().Err()
	}
}

func (s *server) releaseSlot() {
	<-s.sem
	s.inFlight.Add(-1)
}

var errBusy = errors.New("server busy")

func (s *server) handleDecode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.total4xx.Add(1)
		jsonError(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	photo, err := s.extractPhoto(w, r)
	if err != nil {
		s.total4xx.Add(1)
		// MaxBytesReader returns *http.MaxBytesError which we surface as 413.
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			jsonError(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.acquireSlot(r); err != nil {
		if errors.Is(err, errBusy) {
			s.total5xx.Add(1)
			s.totalBusy.Add(1)
			w.Header().Set("Retry-After", "2")
			jsonError(w, "server busy — retry shortly", http.StatusServiceUnavailable)
			return
		}
		// Client cancelled — best-effort cleanup, no body write.
		return
	}
	defer s.releaseSlot()

	start := time.Now()
	out, err := decode(photo.data, s.cfg.maxLongEdge)
	elapsed := time.Since(start)

	if err != nil {
		s.total4xx.Add(1)
		log.Printf("decode error after %s: %v", elapsed.Round(time.Millisecond), err)
		jsonError(w, "decode failed — check image quality and QR code visibility",
			http.StatusUnprocessableEntity)
		return
	}

	s.totalOK.Add(1)
	s.recordLatency(elapsed)
	log.Printf("decoded %q in %s (qr=%.0fms, body=%d bytes)",
		photo.filename, elapsed.Round(time.Millisecond), out.qrMS, len(photo.data))

	// Merge biographical fields with the photo.
	var fields map[string]any
	if err := json.Unmarshal(out.json, &fields); err != nil {
		// Library output should always be valid JSON; pass through if not.
		w.Header().Set("Content-Type", "application/json")
		w.Write(out.json) //nolint:errcheck
		return
	}
	if len(out.webp) > 0 {
		fields["foto_base64"] = base64.StdEncoding.EncodeToString(out.webp)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fields) //nolint:errcheck
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}
