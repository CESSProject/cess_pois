package tree

import (
	"bytes"
	"crypto/sha256"
	"math"
	"sync"
)

type LightMHT []byte

type PathProof struct {
	Locs []byte
	Path [][]byte
}

const (
	DEFAULT_HASH_SIZE = 32
	DEFAULT_THREAD    = 4
)

var pool *sync.Pool

func InitMhtPool(eLen int) {
	if pool != nil {
		return
	}
	pool = &sync.Pool{
		New: func() interface{} {
			mht := make(LightMHT, eLen*DEFAULT_HASH_SIZE)
			return &mht
		},
	}
}

func GetLightMhtFromPool() *LightMHT {
	mht := pool.Get().(*LightMHT)
	return mht
}

func PutLightMhtToPool(mht *LightMHT) {
	if pool != nil {
		pool.Put(mht)
	}
}

// CalcLightMhtWithBytes calc light weight mht whit fixed size elements data
func (mht *LightMHT) CalcLightMhtWithBytes(data []byte, size int) {
	hash := sha256.New()
	for i := 0; i < len(data)/size; i++ {
		hash.Reset()
		hash.Write(data[i*size : (i+1)*size])
		copy((*mht)[i*DEFAULT_HASH_SIZE:(i+1)*DEFAULT_HASH_SIZE], hash.Sum(nil))
	}
	calcLightMht(mht)
}

func calcLightMht(mht *LightMHT) *LightMHT {
	lens := len(*mht)
	p := lens / 2
	src := (*mht)[:]
	hash := sha256.New()
	size := DEFAULT_HASH_SIZE
	for i := 0; i < int(math.Log2(float64(lens/size)))+1; i++ {
		num := lens / (1 << (i + 1))
		target := (*mht)[p : p+num]
		for j, k := num/size-1, num*2/size-2; j >= 0 && k >= 0; j, k = j-1, k-2 {
			hash.Reset()
			hash.Write(src[k*size : (k+2)*size])
			copy(target[j*size:(j+1)*size], hash.Sum(nil))
		}
		p = p / 2
		src = target
	}
	return mht
}

func (mht LightMHT) GetRoot() []byte {
	if len(mht) < DEFAULT_HASH_SIZE*2 {
		return nil
	}
	root := make([]byte, DEFAULT_HASH_SIZE)
	copy(root, mht[DEFAULT_HASH_SIZE:DEFAULT_HASH_SIZE*2])
	return root
}

func (mht LightMHT) GetPathProof(data []byte, index, size int) (PathProof, error) {
	return mht.getPathProof(data, index, size, false)
}

func (mht LightMHT) getPathProof(data []byte, index, size int, hashed bool) (PathProof, error) {
	deep := int(math.Log2(float64(len(data) / size)))
	proof := PathProof{
		Locs: make([]byte, deep),
		Path: make([][]byte, deep),
	}
	var (
		loc byte
		d   []byte
	)

	num, p := len(mht), len(mht)
	for i := 0; i < deep; i++ {
		if (index+1)%2 == 0 {
			loc = 0
			d = data[(index-1)*size : index*size]
		} else {
			loc = 1
			d = data[(index+1)*size : (index+2)*size]
		}
		if i == 0 && (size != DEFAULT_HASH_SIZE || !hashed) {
			hash := sha256.New()
			hash.Write(d)
			proof.Path[i] = hash.Sum(nil)
			size = DEFAULT_HASH_SIZE
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

func GetPathProofWithAux(data, aux []byte, index, size int) (PathProof, error) {
	proof := PathProof{}
	auxSize := (len(aux) / DEFAULT_HASH_SIZE)
	plateSize := len(data) / size / auxSize
	mht := make(LightMHT, plateSize*DEFAULT_HASH_SIZE)
	left := index / plateSize
	data = data[left*plateSize*size : (left+1)*plateSize*size]
	hash := sha256.New()
	for i := 0; i < plateSize; i++ {
		hash.Reset()
		hash.Write(data[i*size : (i+1)*size])
		copy(mht[i*DEFAULT_HASH_SIZE:(i+1)*DEFAULT_HASH_SIZE], hash.Sum(nil))
	}
	calcLightMht(&mht)

	subProof, err := mht.getPathProof(data, index%plateSize, size, false)
	if err != nil {
		return proof, err
	}
	mht = make(LightMHT, len(aux))
	copy(mht, aux)
	calcLightMht(&mht)
	topProof, err := mht.getPathProof(aux, left, DEFAULT_HASH_SIZE, true)
	if err != nil {
		return proof, err
	}
	proof.Locs = append(subProof.Locs, topProof.Locs...)
	proof.Path = append(subProof.Path, topProof.Path...)
	return proof, nil
}

func VerifyPathProof(root, data []byte, proof PathProof) bool {
	if len(proof.Locs) != len(proof.Path) {
		return false
	}
	hash := sha256.New()
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
