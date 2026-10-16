package redact

import "testing"

func TestCommandLine(t *testing.T) {
	cases := map[string]string{
		"node server.js":                                   "node server.js",
		"mysql -u root --password=hunter2 db":              "mysql -u root --password=••• db",
		"app --token abcdef123456 --verbose":               "app --token ••• --verbose",
		"env DB_PASSWORD=s3cret ./run":                     "env DB_PASSWORD=••• ./run",
		"curl https://alex:pa55w0rd@example.com/x":         "curl https://alex:•••@example.com/x",
		"curl -H Authorization: Bearer abcdefghijklmnop":   "curl -H Authorization: Bearer •••",
		"git push https://ghp_abcdefghijklmnopqrstuvwxyz1": "git push https://•••",
	}
	for in, want := range cases {
		if got := CommandLine(in); got != want {
			t.Errorf("CommandLine(%q) = %q, want %q", in, got, want)
		}
	}
}
