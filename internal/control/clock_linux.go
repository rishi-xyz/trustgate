package control

import (
	"log"
	"syscall"
	"time"
)

// syncClock sets the system clock if it is badly skewed. An enclave has no
// time source of its own and AWS SigV4 rejects requests with > 5 min skew.
// The parent can therefore influence enclave wall-clock time; nothing in
// receipts or attestation depends on it (attestation timestamps come from the
// NSM), and workloads see only a fixed clock.
func syncClock(unix int64) {
	if unix == 0 {
		return
	}
	skew := time.Since(time.Unix(unix, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew < 30*time.Second {
		return
	}
	tv := syscall.Timeval{Sec: unix}
	if err := syscall.Settimeofday(&tv); err != nil {
		log.Printf("control: settimeofday failed: %v", err)
		return
	}
	log.Printf("control: clock was skewed by %v, corrected", skew)
}
