// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mediafile

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// markDownload sets the quarantine attribute, as a browser does for a
// download, so Gatekeeper checks a received program before it first runs.
// The flags 0083 say the file was downloaded and is not yet approved. A
// file system without extended attributes cannot hold it; the file is
// kept unmarked then.
func markDownload(path string) error {
	v := fmt.Sprintf("0083;%x;CBB;", time.Now().Unix())
	if err := unix.Setxattr(path, "com.apple.quarantine", []byte(v), 0); err != nil && err != unix.ENOTSUP {
		return err
	}
	return nil
}
