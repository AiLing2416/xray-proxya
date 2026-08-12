package config

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// LifecycleLock serializes operations that change the Xray process together
// with kernel gateway state. The lock file intentionally lives beside the
// effective user's configuration, so root and rootless runtimes cannot block
// or control one another.
type LifecycleLock struct {
	file *os.File
}

func AcquireLifecycleLock() (*LifecycleLock, error) {
	path := filepath.Join(GetConfigDir(), "lifecycle.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &LifecycleLock{file: file}, nil
}

func (lock *LifecycleLock) Release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(unlockErr, closeErr)
}

func WithLifecycleLock(fn func() error) error {
	lock, err := AcquireLifecycleLock()
	if err != nil {
		return err
	}
	defer lock.Release()
	return fn()
}
