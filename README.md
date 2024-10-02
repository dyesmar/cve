# cve

Package `cve` provides a consistent mechanism for parsing, storing, and using [CVE identifiers](https://cve.mitre.org) as specified by the MITRE Corporation.

This code hit the cutting room floor from one of my private projects, so I thought I'd share.

SPDX short identifier: [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html)

## Installation

Assuming you have [Go]() installed…

```bash
go get github.com/dyesmar/cve
```

## Usage

```go
import "github.com/dyesmar/cve"
```

There are two APIs for creating new `CVE` types:

```go
// New
cve, err := cve.New(2020, 6629)

// Parse
cve, err := cve.Parse("CVE-2020-6629")
```

Once created, there are several methods you can call on a `CVE` type:

* `String` returns the `string` reprentation of the receiver.
* `URL` returns the [NVD](https://nvd.nist.gov/) [URL](https://golang.org/pkg/net/url/) representation of the receiver.
* `MarkdownLink` returns the [Markdown](https://daringfireball.net/projects/markdown/) link representation of the receiver.

The included sample program illustrates how these APIs can be used:

```bash
go run cmd/cve/main.go CVE-2020-6629
```

There will be no output from the program, but it should open your preferred web browser and point it to the URL for [CVE-2020-6629](https://nvd.nist.gov/vuln/detail/CVE-2020-6629) at [NVD](https://nvd.nist.gov).

## Implementation details and caveats

Internally, CVE identifiers are stored as a pair of `uint` types, one for the year part and one for the sequence number. This may seem wasteful, but consider:

* This code will continue to work in, say, AD 4324534534.
* This code will survive the initial onslaught of mass CVE filings perpetrated by our AI overlords. 😅

Unfortunately, storing the sequence number as a `uint` causes the implementation to fail three of MITRE's valid test cases:

* `CVE-2014-1111111111111111111111`
* `CVE-2014-11111111111111111111111`
* `CVE-2014-111111111111111111111111`

These sequence numbers are too large to store in a `uint`. One solution would be to store the sequence number as a [big.Int](https://golang.org/pkg/math/big/), but that seems excessive. Alternately, the CVE sequence number could be stored as a `string`, but that would require more code to achieve the same level of error checking present for the `uint` sequence number. I'm fine with sequence numbers having `Uint.max` as an upper bound.

## Legal

Copyright &copy; 2020 Ramsey Dow. All rights reserved.

Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.
