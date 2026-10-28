package auth

import (
	"testing"
)

// Path tests are pure string assertions, so they run on every host and cover
// all three layouts, including windows, without touching any filesystem.
func TestStateDBPathLayouts(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("APPDATA", "")
	cases := []struct {
		name string
		goos string
		opts Options
		want string
	}{
		{
			name: "darwin default",
			goos: "darwin",
			opts: Options{HomeDir: "/Users/synthetic"},
			want: "/Users/synthetic/Library/Application Support/Cursor/User/globalStorage/state.vscdb",
		},
		{
			name: "linux default",
			goos: "linux",
			opts: Options{HomeDir: "/home/synthetic"},
			want: "/home/synthetic/.config/Cursor/User/globalStorage/state.vscdb",
		},
		{
			name: "linux xdg option",
			goos: "linux",
			opts: Options{HomeDir: "/home/synthetic", XDGConfigHome: "/synthetic-xdg"},
			want: "/synthetic-xdg/Cursor/User/globalStorage/state.vscdb",
		},
		{
			name: "windows default",
			goos: "windows",
			opts: Options{HomeDir: `C:\Users\synthetic`},
			want: `C:\Users\synthetic\AppData\Roaming\Cursor\User\globalStorage\state.vscdb`,
		},
		{
			name: "windows appdata option",
			goos: "windows",
			opts: Options{HomeDir: `C:\Users\synthetic`, AppData: `D:\SyntheticRoaming`},
			want: `D:\SyntheticRoaming\Cursor\User\globalStorage\state.vscdb`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := stateDBPath(tc.opts, tc.goos)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("stateDBPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Injected options take precedence over environment variables, which take
// precedence over the home-derived defaults.
func TestStateDBPathEnvFallbacks(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/env-xdg")
	t.Setenv("APPDATA", `E:\EnvRoaming`)

	got, err := stateDBPath(Options{HomeDir: "/home/synthetic"}, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if want := "/env-xdg/Cursor/User/globalStorage/state.vscdb"; got != want {
		t.Fatalf("linux env fallback: got %q, want %q", got, want)
	}

	got, err = stateDBPath(Options{HomeDir: `C:\synthetic`}, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if want := `E:\EnvRoaming\Cursor\User\globalStorage\state.vscdb`; got != want {
		t.Fatalf("windows env fallback: got %q, want %q", got, want)
	}

	got, err = stateDBPath(Options{HomeDir: "/home/synthetic", XDGConfigHome: "/option-xdg"}, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if want := "/option-xdg/Cursor/User/globalStorage/state.vscdb"; got != want {
		t.Fatalf("option must beat env: got %q, want %q", got, want)
	}
}

func TestStateDBPathUnsupportedGOOS(t *testing.T) {
	if _, err := stateDBPath(Options{HomeDir: "/synthetic"}, "plan9"); err == nil {
		t.Fatal("expected an error for an unsupported goos")
	}
}

func TestJoinPathUsesTargetGOOSSeparator(t *testing.T) {
	if got, want := joinPath("linux", "/a", "b", "c"), "/a/b/c"; got != want {
		t.Fatalf("unix join: got %q, want %q", got, want)
	}
	if got, want := joinPath("windows", `C:\a`, "b", "c"), `C:\a\b\c`; got != want {
		t.Fatalf("windows join: got %q, want %q", got, want)
	}
}
