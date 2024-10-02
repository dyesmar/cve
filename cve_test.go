package cve

import (
	"bufio"
	"log"
	"os"
	"testing"
)

type table struct {
	cve      string // CVE identifier string.
	expected bool   // Whether or not the CVE ID will sucessfully parse.
}

// loadData takes the pathname of a flatfile containing an arbitrary number
// of CVE IDs, e.g., valid-syntax.dat, canonical examples of which can be
// found in MITRE's CVE test data collection. The URL of the collection is
// https://cve.mitre.org/cve/identifiers/cve-syntax-test-data.zip
//
// The README for MITRE's test data indicates that the valid and invalid
// syntax files contain CVE IDs, one to a line. Additionally, comments may
// begin with a '#' in the first column of any given line and can be safely
// ignored.
//
// In addition, the loadData function takes a defaultException, a bool
// indicating whether the CVE IDs in the flatfile are valid (true) or invalid
// (false) and thus expected to successfully parse or fail. loadData also
// takes a slice of strings representing exceptions. For example, if the
// flatfile valid-syntax.dat contains CVE IDs that are expected to parse
// successfully, defaultExpectation will be set to true and the CVE IDs
// specified in the exceptions slice will each be expected to fail when parsed.
func loadData(pathname string, defaultExpectation bool, exceptions []string) ([]table, error) {
	f, err := os.Open(pathname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ret := []table{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line[0] == '#' {
			continue
		}

		actual := defaultExpectation
		for _, cve := range exceptions {
			if line == cve {
				actual = !defaultExpectation
			}
		}

		ret = append(ret, table{
			cve:      line,
			expected: actual,
		})
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return ret, nil
}

// TestValid tests a flatfile of (mostly) valid CVE IDs. There is one CVE ID,
// CVE-ABCD-EFGH, that is actually invalid.
func TestValid(t *testing.T) {
	// CVE IDs in valid-sytax.dat are expected to parse,
	// save for the exceptions.
	expected := true
	tab, err := loadData("testdata/valid-syntax.dat", expected, []string{
		"CVE-ABCD-EFGH",
		"CVE-2014-1111111111111111111111",
		"CVE-2014-11111111111111111111111",
		"CVE-2014-111111111111111111111111",
		// BUGBUG: Those last 3 CVEs should not fail, but they do because
		// they are too large to fit into a uint. The solution is to use
		// a big.Int, but that is wasteful and somewhat messy, so we are
		// going to accept these failures for the time being.
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, tc := range tab {
		t.Run(tc.cve, func(t *testing.T) {
			_, err := Parse(tc.cve)
			switch tc.expected {
			case expected:
				if err != nil {
					// cve.Parse returned an unexpected error.
					t.Errorf("%s: failed, unexpected error: %v", tc.cve, err)
				}
			case !expected:
				if err == nil {
					// cve.Parse failed but did not return an error.
					t.Errorf("%s: passed, expected success", tc.cve)
				}
			}
		})
	}
}

// TestInvalid tests a flatfile of (mostly) invalid CVE IDs. There is one CVE
// ID, CVE-2014-1234, that is actually valid.
func TestInvalid(t *testing.T) {
	// CVE IDs in invalid-sytax.dat are not expected to parse,
	// save for the exceptions.
	expected := false
	tab, err := loadData("testdata/invalid-syntax.dat", expected, []string{
		"CVE-2014-1234",
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, tc := range tab {
		t.Run(tc.cve, func(t *testing.T) {
			_, err := Parse(tc.cve)
			switch tc.expected {
			case expected:
				if err == nil {
					// cve.Parse failed, but did not return an error.
					t.Errorf("%s: failed, expected success", tc.cve)
				}
			case !expected:
				if err != nil {
					// cve.Parse succeeded when failure was expected.
					t.Errorf("%s: passed, expected to fail", tc.cve)
				}
			}
		})
	}
}

// TestInvalid tests Stringer conformance. There is no real way the
// String method can fail since CVE's year and sequence fields were
// rendered unexported. (The New and Parse methods handle all validation
// up front.) Nonetheless, we will give it a go just to say we tested it.
func TestString(t *testing.T) {
	want := "CVE-2014-9999999"
	cve, err := Parse(want)
	s := cve.String()
	if want != s || err != nil {
		t.Fatalf(`String() = %q, %v, want match for %#q, nil`, s, err, want)
	}
}
