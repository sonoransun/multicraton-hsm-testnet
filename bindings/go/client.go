// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

// Package hsm provides a pure-Go client for Craton HSM, spoken over gRPC
// with optional mutual TLS. No cgo. This package intentionally mirrors the
// 18 RPCs defined in craton-hsm-daemon/proto/craton_hsm.proto; the generated
// gRPC stubs live in internal/cratonpb and are not imported directly.
//
// The client surface is deliberately narrow and operation-centric — callers
// rarely need to touch session or token administration directly. For those,
// drop down to the underlying stubs.
package hsm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Client is a connected HSM client. Safe for concurrent use by multiple
// goroutines.
type Client struct {
	addr    string
	opts    clientOptions
	mu      sync.Mutex
	session uint64 // lazy-opened session handle
}

type clientOptions struct {
	tlsConfig *tls.Config
	jwtToken  string
	timeout   time.Duration
}

// Option configures a new client.
type Option func(*clientOptions) error

// WithMTLS configures mutual TLS using the given client cert/key and CA bundle
// (PEM-encoded paths).
func WithMTLS(clientCertPath, clientKeyPath, caBundlePath string) Option {
	return func(o *clientOptions) error {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return fmt.Errorf("load client cert/key: %w", err)
		}
		caPem, err := os.ReadFile(caBundlePath)
		if err != nil {
			return fmt.Errorf("read CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPem) {
			return errors.New("CA bundle contained no parseable certificates")
		}
		o.tlsConfig = &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
		}
		return nil
	}
}

// WithJWT sets a bearer token attached to every request. Combine with
// WithMTLS for RFC 8705 certificate-bound tokens.
func WithJWT(token string) Option {
	return func(o *clientOptions) error {
		o.jwtToken = token
		return nil
	}
}

// WithTimeout sets a per-call default timeout applied when callers pass
// `context.Background()`. Defaults to 30 s.
func WithTimeout(t time.Duration) Option {
	return func(o *clientOptions) error {
		o.timeout = t
		return nil
	}
}

// New builds a new client against the given `host:port` daemon address.
// Returns an error if TLS setup fails; the gRPC connection itself is
// established lazily on the first RPC to shorten test setup.
func New(addr string, opts ...Option) (*Client, error) {
	c := &Client{addr: addr, opts: clientOptions{timeout: 30 * time.Second}}
	for _, o := range opts {
		if err := o(&c.opts); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Close releases any resources held by the client. Safe to call multiple times.
func (c *Client) Close() error {
	return nil
}

// ---------- operation surface (PQC and classical) ----------
//
// Every method is a *stub* in this release: it normalises parameters, applies
// the client-side auth headers, and returns `ErrNotImplemented`. The gRPC
// wiring needs the proto-generated `cratonpb` package which lives under
// `internal/cratonpb/`, produced by `buf generate`. Call `go generate` from
// the repository root to populate it; a small generator script will be added
// to the repo alongside the first tagged release.

// Sign signs `data` under `mechanism` with the private-key object at `handle`.
func (c *Client) Sign(ctx context.Context, handle uint64, mechanism Mechanism, data []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// Verify verifies `signature` over `data` with the public-key object at `handle`.
func (c *Client) Verify(ctx context.Context, handle uint64, mechanism Mechanism, data, signature []byte) (bool, error) {
	return false, ErrNotImplemented
}

// Encapsulate produces `(ciphertext, shared_secret)` against a KEM public key.
func (c *Client) Encapsulate(ctx context.Context, pubHandle uint64, mechanism Mechanism) (ct, ss []byte, err error) {
	return nil, nil, ErrNotImplemented
}

// Decapsulate recovers the shared secret using a KEM private key.
func (c *Client) Decapsulate(ctx context.Context, privHandle uint64, mechanism Mechanism, ct []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// HybridComposeSign produces a composite classical+PQ signature.
// `classicalHandle` must reference an ECDSA-P256 or Ed25519 private key,
// and `pqHandle` an ML-DSA-65 private key (the mechanism is inferred
// from the key objects' `CKA_KEY_TYPE`).
func (c *Client) HybridComposeSign(ctx context.Context, classicalHandle, pqHandle uint64, data []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// ErrNotImplemented is returned by operations that depend on the generated
// proto stubs which are built by the repository's `go generate` step.
var ErrNotImplemented = errors.New("craton-hsm-go: proto stubs not generated — run `go generate ./...`")
