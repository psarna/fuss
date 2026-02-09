package tracer

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var debugMem = os.Getenv("FUSS_DEBUG") != ""

func ReadString(pid int, addr uintptr, maxLen int) (string, error) {
	if addr == 0 {
		return "", nil
	}
	if maxLen <= 0 {
		maxLen = 256
	}
	if maxLen > 4096 {
		maxLen = 4096
	}
	var result []byte
	chunkSize := 256
	for len(result) < maxLen {
		toRead := chunkSize
		if len(result)+toRead > maxLen {
			toRead = maxLen - len(result)
		}
		buf := make([]byte, toRead)
		n, err := ReadBytes(pid, addr+uintptr(len(result)), buf)
		if debugMem {
			fmt.Fprintf(os.Stderr, "[FUSS] ReadString: pid=%d addr=%x n=%d err=%v\n", pid, addr+uintptr(len(result)), n, err)
		}
		if err != nil && len(result) == 0 {
			return "", err
		}
		for i := 0; i < n; i++ {
			if buf[i] == 0 {
				return string(append(result, buf[:i]...)), nil
			}
		}
		result = append(result, buf[:n]...)
		if n < toRead {
			break
		}
	}
	return string(result), nil
}

func ReadBytes(pid int, addr uintptr, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	wordSize := int(unsafe.Sizeof(uintptr(0)))
	words := (len(buf) + wordSize - 1) / wordSize

	for i := 0; i < words; i++ {
		var wordBuf [8]byte
		_, err := syscall.PtracePeekData(pid, addr+uintptr(i*wordSize), wordBuf[:])
		if err != nil {
			if i == 0 {
				return 0, err
			}
			return i * wordSize, nil
		}

		start := i * wordSize
		end := start + wordSize
		if end > len(buf) {
			end = len(buf)
		}
		copy(buf[start:end], wordBuf[:end-start])
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
