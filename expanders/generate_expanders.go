package expanders

import (
	"crypto/sha512"
)

func ConstructStackedExpanders(k, n, d int64) *Expanders {
	return NewExpanders(k, n, d)
}

func CalcNodeParents(expanders *Expanders, node *Node, MinerID []byte, Count, rlayer int64) {
	if node == nil || expanders == nil ||
		cap(node.Parents) != int(expanders.D+1) {
		return
	}
	layer := int64(node.Index) / expanders.N
	if layer == 0 {
		return
	}
	groupSize := expanders.N / expanders.D
	offset := groupSize / 256

	if offset <= 0 {
		offset = 1
	}

	hash := sha512.New()
	hash.Write(MinerID)
	hash.Write(GetBytes(Count))
	hash.Write(GetBytes(rlayer)) //add real layer
	hash.Write(GetBytes(int64(node.Index)))
	res := hash.Sum(nil)
	if expanders.D > 64 {
		hash.Reset()
		hash.Write(res)
		res = append(res, hash.Sum(nil)...)
	}
	res = res[:expanders.D]

	parent := node.Index - NodeType(expanders.N)
	node.AddParent(parent)
	for i := int64(0); i < int64(len(res)); i++ {
		index := NodeType((layer-1)*expanders.N + i*groupSize + int64(res[i])*offset + int64(res[i])%offset)
		if index == parent {
			node.AddParent(index + 1)
		} else if index < parent {
			node.AddParent(index + NodeType(expanders.N))
		} else {
			node.AddParent(index)
		}
	}
}
