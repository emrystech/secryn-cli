package config

import "testing"

func TestEncryptionMode(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		want    string
		wantErr bool
	}{
		{name: "legacy", config: Config{}, want: "legacy"},
		{name: "e2ee", config: Config{RecipientID: "recipient", RecipientPrivateKey: "encoded"}, want: "e2ee"},
		{name: "pending", config: Config{RecipientID: "recipient", RecipientPrivateKey: "encoded", E2EEBootstrapPending: true}, want: "e2ee_pending"},
		{name: "pending without identity", config: Config{E2EEBootstrapPending: true}, wantErr: true},
		{name: "missing private key", config: Config{RecipientID: "recipient"}, wantErr: true},
		{name: "missing recipient", config: Config{RecipientPrivateKey: "encoded"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.config.EncryptionMode()
			if (err != nil) != test.wantErr {
				t.Fatalf("EncryptionMode() error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("EncryptionMode() = %q, want %q", got, test.want)
			}
		})
	}
}
