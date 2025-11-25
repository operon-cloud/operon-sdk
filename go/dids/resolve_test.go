package dids

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveSuccess(t *testing.T) {
	docJSON := `{"id":"did:operon:root","verificationMethod":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/1.0/identifiers/did:operon:root" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("content-type", "application/did+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(docJSON))
	}))
	defer srv.Close()

	doc, err := Resolve(context.Background(), "did:operon:root", WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if doc.ID != "did:operon:root" {
		t.Fatalf("unexpected id: %s", doc.ID)
	}
}

func TestResolveInvalidMethod(t *testing.T) {
	_, err := Resolve(context.Background(), "did:example:123")
	if err == nil || err != ErrUnsupported {
		t.Fatalf("expected ErrUnsupported, got %v", err)
	}
}

func TestResolveNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := Resolve(context.Background(), "did:operon:missing", WithBaseURL(srv.URL))
	if err == nil || err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
