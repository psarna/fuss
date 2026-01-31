package tracer

import (
	"syscall"
	"unsafe"
)

func ReadString(pid int, addr uintptr, maxLen int) (string, error) {
	if addr == 0 {
		return "", nil
	}
	buf := make([]byte, maxLen)
	n, err := ReadBytes(pid, addr, buf)
	if err != nil {
		return "", err
	}
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return string(buf[:i]), nil
		}
	}
	return string(buf[:n]), nil
}

func ReadBytes(pid int, addr uintptr, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	wordSize := unsafe.Sizeof(uintptr(0))
	words := (len(buf) + int(wordSize) - 1) / int(wordSize)

	for i := 0; i < words; i++ {
		word, err := syscall.PtracePeekData(pid, addr+uintptr(i)*wordSize, nil)
		if err != nil {
			if i == 0 {
				return 0, err
			}
			return i * int(wordSize), nil
		}

		wordBytes := (*[8]byte)(unsafe.Pointer(&word))[:]
		start := i * int(wordSize)
		end := start + int(wordSize)
		if end > len(buf) {
			end = len(buf)
		}
		copy(buf[start:end], wordBytes[:end-start])
	}

	return len(buf), nil
}

func WriteBytes(pid int, addr uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	wordSize := int(unsafe.Sizeof(uintptr(0)))

	offset := int(addr) % wordSize
	if offset != 0 {
		alignedAddr := addr - uintptr(offset)
		word, err := syscall.PtracePeekData(pid, alignedAddr, nil)
		if err != nil {
			return err
		}

		wordBytes := (*[8]byte)(unsafe.Pointer(&word))[:]
		toCopy := wordSize - offset
		if toCopy > len(data) {
			toCopy = len(data)
		}
		copy(wordBytes[offset:offset+toCopy], data[:toCopy])

		_, err = syscall.PtracePokeData(pid, alignedAddr, wordBytes)
		if err != nil {
			return err
		}

		data = data[toCopy:]
		addr = alignedAddr + uintptr(wordSize)
	}

	for len(data) >= wordSize {
		var word [8]byte
		copy(word[:], data[:wordSize])
		_, err := syscall.PtracePokeData(pid, addr, word[:])
		if err != nil {
			return err
		}
		data = data[wordSize:]
		addr += uintptr(wordSize)
	}

	if len(data) > 0 {
		word, err := syscall.PtracePeekData(pid, addr, nil)
		if err != nil {
			return err
		}

		wordBytes := (*[8]byte)(unsafe.Pointer(&word))[:]
		copy(wordBytes[:len(data)], data)

		_, err = syscall.PtracePokeData(pid, addr, wordBytes)
		if err != nil {
			return err
		}
	}

	return nil
}

func WriteString(pid int, addr uintptr, s string) error {
	return WriteBytes(pid, addr, append([]byte(s), 0))
}
