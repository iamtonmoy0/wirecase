package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestSignVerifyAndTamper(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	job, err := NewJob("https://example.test", 5*time.Second, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(job, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, publicKey, time.Now()); err != nil {
		t.Fatalf("valid job rejected: %v", err)
	}
	signed.Job.Target = "https://attacker.test"
	if err := Verify(signed, publicKey, time.Now()); err == nil {
		t.Fatal("tampered job should fail signature verification")
	}
}

func TestVerifyRejectsExpiredJob(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	job, err := NewJob("example.test", time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(job, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, publicKey, job.ExpiresAt); err == nil {
		t.Fatal("expired job should be rejected")
	}
}
