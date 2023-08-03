package expanders

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"sync"
)

const DEFAULT_HASH_SIZE = 64

type NodeType int32

type Expanders struct {
	K, N, D   int64
	Size      int64      `json:"size"`
	HashSize  int64      `json:"hash_szie"`
	FilePool  *sync.Pool `json:"-"`
	NodesPool *sync.Pool `json:"-"`
}

type Node struct {
	Index   NodeType   `json:"index"`
	Parents []NodeType `json:"parents"`
}

func NewExpanders(k, n, d, hashSize int64) *Expanders {
	expanders := &Expanders{
		Size: (k + 1) * n,
		K:    k, N: n, D: d,
		HashSize: hashSize,
	}
	if hashSize <= 0 {
		expanders.HashSize = DEFAULT_HASH_SIZE
	}

	expanders.FilePool = &sync.Pool{
		New: func() any {
			buf := make([]byte, n*expanders.HashSize)
			return &buf
		},
	}
	expanders.NodesPool = &sync.Pool{
		New: func() any {
			buf := make([]Node, n)
			for i := int64(0); i < n; i++ {
				buf[i].Parents = make([]NodeType, 0, d+1)
			}
			return &buf
		},
	}
	return expanders
}

func NewNode(idx NodeType) *Node {
	return &Node{Index: idx}
}

func (node *Node) AddParent(parent NodeType) bool {
	if node.Index == parent {
		return false
	}
	if node.Parents == nil ||
		len(node.Parents) >= cap(node.Parents) {
		return false
	}
	i, ok := node.ParentInList(parent)
	if ok {
		return false
	}
	node.Parents = append(node.Parents, 0)
	lens := len(node.Parents)
	if lens == 1 || i == lens-1 {
		node.Parents[i] = parent
		return true
	}
	copy(node.Parents[i+1:], node.Parents[i:lens-1])
	node.Parents[i] = parent
	return true
}

func (node *Node) NoParents() bool {
	return len(node.Parents) <= 0
}

func (node *Node) ParentInList(parent NodeType) (int, bool) {
	if node.NoParents() {
		return 0, false
	}
	lens := len(node.Parents)
	l, r := 0, lens-1
	for l <= r {
		mid := (l + r) / 2
		if node.Parents[mid] == parent {
			return 0, true
		}
		if node.Parents[mid] > parent {
			r = mid - 1
		} else {
			l = mid + 1
		}
	}
	i := (l + r) / 2
	if node.Parents[i] < parent {
		i++
	}
	return i, false
}

func (expanders Expanders) NewHash() hash.Hash {
	switch expanders.HashSize {
	case 32:
		return sha256.New()
	case 64:
		return sha512.New()
	default:
		return sha512.New()
	}
}

func (expanders Expanders) GetHash(data []byte) []byte {
	h := expanders.NewHash()
	if data == nil {
		data = []byte("none")
	}
	h.Write(data)
	return h.Sum(nil)
}

func GetBytes(v any) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, v)
	return bytesBuffer.Bytes()
}

func BytesToNodeValue(data []byte, Max int64) NodeType {
	v, _ := binary.Varint(data)
	if v < 0 {
		v = -v
	}
	v %= Max
	return NodeType(v)
}
