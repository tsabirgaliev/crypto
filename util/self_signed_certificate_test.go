package util

import "testing"

func TestSelfSignedCertificate(t *testing.T) {
	_, err := SelfSignedCertificate(Options{})
	if err != nil {
		t.Errorf("Failed to generate self signed certificate: %v", err)
	}
}
