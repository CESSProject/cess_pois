package tree

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"math"
	"sync"
)

type LightMHT []byte

type PathProof struct {
	Locs []byte
	Path [][]byte
}

var pool *sync.Pool

func InitMhtPool(eLen, hashSize int) {
	if pool != nil {
		return
	}
	pool = &sync.Pool{
		New: func() interface{} {
			mht := make(LightMHT, eLen*hashSize)
			return &mht
		},
	}
}

// CalcLightMhtWithBytes calc light weight mht whit fixed size elements data
func CalcLightMhtWithBytes(data []byte, size int, usePool bool) *LightMHT {
	mht := new(LightMHT)
	lens := len(data)
	if lens%size != 0 {
		return mht
	}
	if usePool && pool != nil {
		mht = pool.Get().(*LightMHT)
		if len(*mht) != lens {
			*mht = make(LightMHT, lens)
		}
	} else {
		*mht = make(LightMHT, lens)
	}
	hash := NewHash(size)
	for i := 0; i < lens/size; i++ {
		hash.Reset()
		hash.Write(data[i*size : (i+1)*size])
		copy((*mht)[i*size:(i+1)*size], hash.Sum(nil))
	}
	return calcLightMht(*mht, size)
}

func CalcLightMhtWitElements(elems [][]byte, size int, usePool bool) *LightMHT {
	mht := new(LightMHT)
	lens := len(elems)
	if lens%size != 0 {
		return mht
	}
	if usePool && pool != nil {
		mht = pool.Get().(*LightMHT)
		if len(*mht) != lens*size {
			*mht = make(LightMHT, lens*size)
		}
	} else {
		*mht = make(LightMHT, lens*size)
	}
	hash := NewHash(size)
	for i := 0; i < lens; i++ {
		hash.Reset()
		hash.Write(elems[i])
		copy((*mht)[i*size:(i+1)*size], hash.Sum(nil))
	}
	return calcLightMht(*mht, size)
}

func calcLightMht(mht LightMHT, size int) *LightMHT {
	lens := len(mht)
	p := lens / 2
	src := mht[:]
	hash := NewHash(size)
	for i := 0; i < int(math.Log2(float64(lens/size)))+1; i++ {
		num := lens / (1 << (i + 1))
		target := mht[p : p+num]
		for j, k := num/size-1, num*2/size-2; j >= 0 && k >= 0; j, k = j-1, k-2 {
			hash.Reset()
			hash.Write(src[k*size : (k+2)*size])
			copy(target[j*size:(j+1)*size], hash.Sum(nil))
		}
		p = p / 2
		src = target
	}
	return &mht
}

func RecycleMht(mht *LightMHT) {
	if pool != nil {
		pool.Put(mht)
	}
}

func (mht LightMHT) GetRoot(size int) []byte {
	if len(mht) < size*2 {
		return nil
	}
	root := make([]byte, size)
	copy(root, mht[size:size*2])
	return root
}

func (mht LightMHT) GetPathProof(data []byte, index, size int) (PathProof, error) {
	if len(mht) != len(data) {
		return PathProof{}, errors.New("error data")
	}
	lens := int(math.Log2(float64(len(data) / size)))
	proof := PathProof{
		Locs: make([]byte, lens),
		Path: make([][]byte, lens),
	}
	var (
		loc byte
		d   []byte
	)
	hash := NewHash(size)
	num, p := len(data), len(mht)
	for i := 0; i < lens; i++ {
		if (index+1)%2 == 0 {
			loc = 0
			d = data[(index-1)*size : index*size]
		} else {
			loc = 1
			d = data[(index+1)*size : (index+2)*size]
		}
		if i == 0 {
			hash.Reset()
			hash.Write(d)
			proof.Path[i] = hash.Sum(nil)
		} else {
			proof.Path[i] = make([]byte, size)
			copy(proof.Path[i], d)
		}
		proof.Locs[i] = loc
		num, index = num/2, index/2
		p -= num
		data = mht[p : p+num]
	}
	return proof, nil
}

func VerifyPathProof(root, data []byte, proof PathProof) bool {
	if len(proof.Locs) != len(proof.Path) {
		return false
	}
	hash := NewHash(len(root))
	hash.Write(data)
	data = hash.Sum(nil)
	if len(data) != len(root) {
		return false
	}
	for i := 0; i < len(proof.Path); i++ {
		hash.Reset()
		if proof.Locs[i] == 0 {
			hash.Write(append(proof.Path[i][:], data...))
		} else {
			hash.Write(append(data, proof.Path[i]...))
		}
		data = hash.Sum(nil)
	}
	return bytes.Equal(root, data)
}

func CheckIndexPath(index int64, locs []byte) bool {
	for i := 0; i < len(locs); i++ {
		if (index+1)%2 == 0 {
			if locs[i] != 0 {
				return false
			}
		} else if locs[i] != 1 {
			return false
		}
		index /= 2
	}
	return true
}

func NewHash(size int) hash.Hash {
	switch size {
	case 32:
		return sha256.New()
	case 64:
		return sha512.New()
	default:
		return sha512.New()
	}
}
