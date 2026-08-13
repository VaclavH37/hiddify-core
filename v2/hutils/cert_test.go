package hutils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

// The certificate must be verifiable by a client dialling loopback, because that
// is the only thing that ever dials it.
//
// It was not. The template carried `CN=Hiddify` and no SAN at all, and every
// current TLS stack matches the server name against the SAN and ignores
// CommonName — so the secure gRPC modes could never have completed a handshake.
// This is a real handshake rather than a field assertion, because the failure it
// guards against is exactly the kind that a field-by-field check reports as fine.
func TestGeneratedCertificateVerifiesOverLoopback(t *testing.T) {
	pair, err := GenerateCertificatePair()
	if err != nil {
		t.Fatalf("GenerateCertificatePair: %v", err)
	}

	serverCert, err := tls.X509KeyPair(pair.Certificate, pair.PrivateKey)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pair.Certificate) {
		t.Fatal("client could not parse the certificate it is meant to pin")
	}

	for _, host := range []string{"127.0.0.1", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			ln, err := net.Listen("tcp", host+":0")
			if err != nil {
				t.Skipf("cannot listen on %s here: %v", host, err)
			}
			defer ln.Close()

			errCh := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					errCh <- err
					return
				}
				defer conn.Close()
				tlsConn := tls.Server(conn, &tls.Config{
					Certificates: []tls.Certificate{serverCert},
					ClientAuth:   tls.NoClientCert,
					MinVersion:   tls.VersionTLS12,
				})
				errCh <- tlsConn.Handshake()
			}()

			// No InsecureSkipVerify: pinning the served certificate as the root is
			// precisely what the client does, so anything short of full
			// verification would pass while the real client failed.
			client, err := tls.DialWithDialer(
				&net.Dialer{Timeout: 5 * time.Second},
				"tcp", ln.Addr().String(),
				&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			)
			if err != nil {
				t.Fatalf("client handshake to %s failed: %v", ln.Addr(), err)
			}
			defer client.Close()

			if err := <-errCh; err != nil {
				t.Fatalf("server handshake failed: %v", err)
			}
		})
	}
}

// A wrong clock must not take the tunnel out. There is no NTP correction in this
// build — it was removed from the config builder — so nothing puts a skewed
// device right, and an expiry buys no security on a certificate the client
// fetched in-process moments earlier.
func TestGeneratedCertificateToleratesClockSkew(t *testing.T) {
	pair, err := GenerateCertificatePair()
	if err != nil {
		t.Fatalf("GenerateCertificatePair: %v", err)
	}
	block, _ := pem.Decode(pair.Certificate)
	if block == nil {
		t.Fatal("certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if !cert.NotBefore.Before(time.Now()) {
		t.Errorf("NotBefore %v is not backdated; a device running slightly slow rejects it", cert.NotBefore)
	}
	if cert.NotAfter.Sub(time.Now()) < 5*365*24*time.Hour {
		t.Errorf("NotAfter %v is under five years away", cert.NotAfter)
	}
	if len(cert.IPAddresses) == 0 && len(cert.DNSNames) == 0 {
		t.Error("certificate carries no SAN, so no client can verify it")
	}
}

// The old subject named another product. Nothing functional depends on it, but a
// certificate is inspectable by anything that can reach the port.
func TestGeneratedCertificateIsNotBrandedUpstream(t *testing.T) {
	pair, err := GenerateCertificatePair()
	if err != nil {
		t.Fatalf("GenerateCertificatePair: %v", err)
	}
	block, _ := pem.Decode(pair.Certificate)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	subject := cert.Subject.String()
	for _, needle := range []string{"Hiddify", "hiddify"} {
		if contains(subject, needle) {
			t.Errorf("certificate subject %q still names upstream", subject)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}
