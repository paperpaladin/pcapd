package main

import "fmt"

// pcapng support arrives in milestone 2. Until then the format is named and
// refused rather than being handed to the classic reader, which would report
// a bad magic and so blame the wrong thing.
func readPcapng(b []byte) (*Capture, error) {
	return nil, fmt.Errorf("pcapng: not implemented yet")
}
