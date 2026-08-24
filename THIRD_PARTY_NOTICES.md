# Third-Party Notices

UEG's Go binary directly depends on the pinned Go modules listed below. The separately
packaged Python verifier installs the exact dependencies listed below from
`requirements.lock`; those Python packages are not embedded in the Go binary.

| Component | Version | License expression |
|---|---:|---|
| golang.org/x/crypto | v0.33.0 | BSD-3-Clause |
| golang.org/x/sys | v0.30.0 | BSD-3-Clause |
| golang.org/x/term | v0.29.0 | BSD-3-Clause |
| attrs | 25.3.0 | MIT |
| cffi | 2.0.0 | MIT |
| cryptography | 46.0.3 | Apache-2.0 OR BSD-3-Clause |
| jsonschema | 4.25.0 | MIT |
| jsonschema-specifications | 2025.4.1 | MIT |
| pycparser | 2.22 | BSD-3-Clause |
| referencing | 0.36.2 | MIT |
| rpds-py | 0.27.0 | MIT |
| typing-extensions | 4.15.0 | PSF-2.0 |

## golang.org/x modules BSD-3-Clause notice

Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of Google LLC nor the names of its contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The Python packages retain their own license files when installed by a Python
package manager. Their declared license expressions are also recorded in the
generated SPDX SBOM. Redistributors should preserve those installed-package
license files when repackaging dependencies rather than installing them from
`requirements.lock` at the destination.
