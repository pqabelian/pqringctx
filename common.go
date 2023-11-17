package pqringct

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

const (
	// binaryFreeListMaxItems is the number of buffers to keep in the free
	// list to use for binary serialization and deserialization.
	binaryFreeListMaxItems = 2048
)

var (
	// littleEndian is a convenience variable since binary.LittleEndian is
	// quite long.
	littleEndian = binary.LittleEndian

	// bigEndian is a convenience variable since binary.BigEndian is quite
	// long.
	bigEndian = binary.BigEndian
)

type binaryFreeList chan []byte

var binarySerializer binaryFreeList = make(chan []byte, binaryFreeListMaxItems)

// WriteVarInt serializes val to w using a variable number of bytes depending
// on its value.
func WriteVarInt(w io.Writer, val uint64) error {
	if val < 0xfd {
		return binarySerializer.PutUint8(w, uint8(val))
	}

	if val <= math.MaxUint16 {
		err := binarySerializer.PutUint8(w, 0xfd)
		if err != nil {
			return err
		}
		return binarySerializer.PutUint16(w, binary.LittleEndian, uint16(val))
	}

	if val <= math.MaxUint32 {
		err := binarySerializer.PutUint8(w, 0xfe)
		if err != nil {
			return err
		}
		return binarySerializer.PutUint32(w, binary.LittleEndian, uint32(val))
	}

	err := binarySerializer.PutUint8(w, 0xff)
	if err != nil {
		return err
	}
	return binarySerializer.PutUint64(w, binary.LittleEndian, val)
}

// ReadVarInt reads a variable length integer from r and returns it as a uint64.
func ReadVarInt(r io.Reader) (uint64, error) {
	discriminant, err := binarySerializer.Uint8(r)
	if err != nil {
		return 0, err
	}

	var rv uint64
	switch discriminant {
	case 0xff:
		sv, err := binarySerializer.Uint64(r, littleEndian)
		if err != nil {
			return 0, err
		}
		rv = sv

		// The encoding is not canonical if the value could have been
		// encoded using fewer bytes.
		min := uint64(0x100000000)
		if rv < min {
			return 0, errors.New("the encoding is not canonical")
		}

	case 0xfe:
		sv, err := binarySerializer.Uint32(r, littleEndian)
		if err != nil {
			return 0, err
		}
		rv = uint64(sv)

		// The encoding is not canonical if the value could have been
		// encoded using fewer bytes.
		min := uint64(0x10000)
		if rv < min {
			return 0, errors.New("the encoding is not canonical")
		}

	case 0xfd:
		sv, err := binarySerializer.Uint16(r, littleEndian)
		if err != nil {
			return 0, err
		}
		rv = uint64(sv)

		// The encoding is not canonical if the value could have been
		// encoded using fewer bytes.
		min := uint64(0xfd)
		if rv < min {
			return 0, errors.New("the encoding is not canonical")
		}

	default:
		rv = uint64(discriminant)
	}

	return rv, nil
}

// Uint8 reads a single byte from the provided reader using a buffer from the
// free list and returns it as a uint8.
func (l binaryFreeList) Uint8(r io.Reader) (uint8, error) {
	buf := l.Borrow()[:1]
	if _, err := io.ReadFull(r, buf); err != nil {
		l.Return(buf)
		return 0, err
	}
	rv := buf[0]
	l.Return(buf)
	return rv, nil
}

// Borrow returns a byte slice from the free list with a length of 8.  A new
// buffer is allocated if there are not any available on the free list.
func (l binaryFreeList) Borrow() []byte {
	var buf []byte
	select {
	case buf = <-l:
	default:
		buf = make([]byte, 8)
	}
	return buf[:8]
}

// Return puts the provided byte slice back on the free list.  The buffer MUST
// have been obtained via the Borrow function and therefore have a cap of 8.
func (l binaryFreeList) Return(buf []byte) {
	select {
	case l <- buf:
	default:
		// Let it go to the garbage collector.
	}
}

// Uint16 reads two bytes from the provided reader using a buffer from the
// free list, converts it to a number using the provided byte order, and returns
// the resulting uint16.
func (l binaryFreeList) Uint16(r io.Reader, byteOrder binary.ByteOrder) (uint16, error) {
	buf := l.Borrow()[:2]
	if _, err := io.ReadFull(r, buf); err != nil {
		l.Return(buf)
		return 0, err
	}
	rv := byteOrder.Uint16(buf)
	l.Return(buf)
	return rv, nil
}

// Uint32 reads four bytes from the provided reader using a buffer from the
// free list, converts it to a number using the provided byte order, and returns
// the resulting uint32.
func (l binaryFreeList) Uint32(r io.Reader, byteOrder binary.ByteOrder) (uint32, error) {
	buf := l.Borrow()[:4]
	if _, err := io.ReadFull(r, buf); err != nil {
		l.Return(buf)
		return 0, err
	}
	rv := byteOrder.Uint32(buf)
	l.Return(buf)
	return rv, nil
}

// Uint64 reads eight bytes from the provided reader using a buffer from the
// free list, converts it to a number using the provided byte order, and returns
// the resulting uint64.
func (l binaryFreeList) Uint64(r io.Reader, byteOrder binary.ByteOrder) (uint64, error) {
	buf := l.Borrow()[:8]
	if _, err := io.ReadFull(r, buf); err != nil {
		l.Return(buf)
		return 0, err
	}
	rv := byteOrder.Uint64(buf)
	l.Return(buf)
	return rv, nil
}

// PutUint8 copies the provided uint8 into a buffer from the free list and
// writes the resulting byte to the given writer.
func (l binaryFreeList) PutUint8(w io.Writer, val uint8) error {
	buf := l.Borrow()[:1]
	buf[0] = val
	_, err := w.Write(buf)
	l.Return(buf)
	return err
}

// PutUint16 serializes the provided uint16 using the given byte order into a
// buffer from the free list and writes the resulting two bytes to the given
// writer.
func (l binaryFreeList) PutUint16(w io.Writer, byteOrder binary.ByteOrder, val uint16) error {
	buf := l.Borrow()[:2]
	byteOrder.PutUint16(buf, val)
	_, err := w.Write(buf)
	l.Return(buf)
	return err
}

// PutUint32 serializes the provided uint32 using the given byte order into a
// buffer from the free list and writes the resulting four bytes to the given
// writer.
func (l binaryFreeList) PutUint32(w io.Writer, byteOrder binary.ByteOrder, val uint32) error {
	buf := l.Borrow()[:4]
	byteOrder.PutUint32(buf, val)
	_, err := w.Write(buf)
	l.Return(buf)
	return err
}

// PutUint64 serializes the provided uint64 using the given byte order into a
// buffer from the free list and writes the resulting eight bytes to the given
// writer.
func (l binaryFreeList) PutUint64(w io.Writer, byteOrder binary.ByteOrder, val uint64) error {
	buf := l.Borrow()[:8]
	byteOrder.PutUint64(buf, val)
	_, err := w.Write(buf)
	l.Return(buf)
	return err
}

// VarIntSerializeSize returns the number of bytes it would take to serialize
// val as a variable length integer.
// The only difference with VarIntSerializeSize() is return type
func VarIntSerializeSize(val uint64) int {
	// The value is small enough to be represented by itself, so it's
	// just 1 byte.
	if val < 0xfd {
		return 1
	}

	// Discriminant 1 byte plus 2 bytes for the uint16.
	if val <= math.MaxUint16 {
		return 3
	}

	// Discriminant 1 byte plus 4 bytes for the uint32.
	if val <= math.MaxUint32 {
		return 5
	}

	// Discriminant 1 byte plus 8 bytes for the uint64.
	return 9
}
