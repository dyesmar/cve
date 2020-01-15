// Copyright 2020 Ramsey Dow. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command cve illustrates one way to use package cve. You specify a CVE
// identifier on the command line and the program will open a browser pointing
// to the associated CVE entry in the National Vulnerability Database. Because
// humans are lazy, parsing of the CVE has been relaxed. You may omit the CVE
// prefix. Moreover, the CVE prefix can appear in any case. For example, the
// following are equivalently valid invocations:
//
//	cve CVE-2020-6629
//	cve cve-2020-6629
//	cve cvE-2020-6629
//	cve 2020-6629
//
// You many specify as many CVE identifiers on the command line as you like.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strings"

	"github.com/yesmar/cve"
)

func main() {
	program := path.Base(os.Args[0])
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [CVE-]<year>-<sequence> [...]\n",
			program)
		os.Exit(1)
	}

	status := 0
	for _, arg := range os.Args[1:] {
		xs := strings.Split(arg, "-")
		var cveId string
		switch len(xs) {
		case 2:
			// No CVE prefix.
			cveId = "CVE-" + strings.Join(xs, "-")
		case 3:
			// CVE prefix.
			if xs[0] != "CVE" {
				matched, err := regexp.MatchString(`(?i)cve`, xs[0])
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: %s: malformed CVE identifier\n",
						program, arg)
					status = 1
					continue
				}
				if !matched {
					fmt.Fprintf(os.Stderr, "%s: %s: malformed CVE identifier\n",
						program, arg)
					status = 1
					continue
				}
				xs[0] = "CVE"
			}
			cveId = strings.Join(xs, "-")
		default:
			// Incorrect number of components.
			fmt.Fprintf(os.Stderr, "%s: %s: malformed CVE identifier\n",
				program, arg)
			status = 1
			continue
		}

		cve, err := cve.Parse(cveId)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s: %v\n", program, cveId, err)
			status = 1
			continue
		}

		var browserHelper string
		switch runtime.GOOS {
		case "linux":
			browserHelper = "xdg-open"
		case "darwin":
			fallthrough
		case "windows":
			browserHelper = "open"
		}

		url, err := cve.URL()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v: %v\n", program, cve, err)
			status = 1
			continue
		}

		cmd := exec.Command(browserHelper, url.String())
		err = cmd.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v: %v\n", program, url, err)
			status = 1
			continue
		}
	}

	os.Exit(status)
}
