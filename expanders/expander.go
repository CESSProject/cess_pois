package expanders

import (
	"bytes"
	"cess_pois/util"
	"encoding/binary"
	"encoding/json"
	"sync"

	"github.com/pkg/errors"
)

type NodeType int32

type Expanders struct {
	K, N, D  int64
	Size     int64      `json:"size"`
	HashSize int64      `json:"hash_szie"`
	FilePool *sync.Pool `json:"-"`
	NodePool *sync.Pool `json:"-"`
}

type Node struct {
	Index   NodeType   `json:"index"`
	Parents []NodeType `json:"parents"`
}

func (expanders *Expanders) MarshalAndSave(path string) error {
	data, err := json.Marshal(expanders)
	if err != nil {
		return errors.Wrap(err, "marshal and save expanders error")
	}
	err = util.SaveFile(path, data)
	return errors.Wrap(err, "marshal and save expanders error")
}

func ReadAndUnmarshalExpanders(path string) (*Expanders, error) {
	data, err := util.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "read and unmarshal expanders error")
	}
	expander := new(Expanders)
	err = json.Unmarshal(data, expander)
	return expander, errors.Wrap(err, "read and unmarshal expanders error")
}

func NewExpanders(k, n, d int64) *Expanders {
	expanders := &Expanders{
		Size: (k + 1) * n,
		K:    k, N: n, D: d,
		HashSize: 64,
	}
	expanders.FilePool = &sync.Pool{
		New: func() any {
			buf := make([]byte, n*int64(HashSize))
			return &buf
		},
	}

	expanders.NodePool = &sync.Pool{
		New: func() any {
			node := NewNode(0)
			node.Parents = make([]NodeType, 0, expanders.D+1)
			return node
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