package expanders

import (
	"cess_pois/util"
)

func ConstructStackedExpanders(k, n, d int64) *Expanders {
	return NewExpanders(k, n, d)
}

func CalcParents(expanders *Expanders, node *Node, MinerID []byte, Count int64) {

	if node == nil || expanders == nil ||
		cap(node.Parents) != int(expanders.D+1) {
		return
	}
	layer := int64(node.Index) / expanders.N
	baseParent := NodeType((layer - 1) * expanders.N)

	if layer == 0 {
		return
	}

	lens := len(MinerID) + 8*18
	content := make([]byte, lens)
	util.CopyData(content, MinerID, GetBytes(Count), GetBytes(layer))
	node.AddParent(node.Index - NodeType(expanders.N))

	plate := make([][]byte, 16)
	for i := int64(0); i < expanders.D; i += 16 {
		//add index to conent
		for j := int64(0); j < 16; j++ {
			plate[j] = GetBytes(i + j)
		}
		util.CopyData(content[lens-8*16:], plate...)
		hash := GetHash(content)
		s, p := 0, NodeType(0)
		for j := 0; j < 16; {
			if s < 4 && j < 15 {
				p = BytesToNodeValue(hash[j*4+s:(j+1)*4+s], expanders.N)
				p = p%NodeType(expanders.N) + baseParent
			} else {
				s = 0
				for {
					p = (p+1)%NodeType(expanders.N) + baseParent
					if p <= node.Index-NodeType(expanders.N) {
						_, ok := node.ParentInList(p + NodeType(expanders.N))
						if !ok && p != node.Index-NodeType(expanders.N) {
							break
						}
					} else if _, ok := node.ParentInList(p); !ok {
						break
					}
				}
			}
			if p < node.Index-NodeType(expanders.N) {
				p += NodeType(expanders.N)
			}
			if node.AddParent(p) {
				j++
				s = 0
				continue
			}
			s++
		}
	}
}

func (expanders *Expanders) RunRelationalMapServer(MinerID []byte, Count int64) <-chan *Node {

	out := make(chan *Node, (expanders.N/1024)*4)

	go func() {
		for l := int64(0); l <= expanders.K; l++ {
			for index := int64(0); index < expanders.N; index++ {
				node := expanders.NodePool.Get().(*Node)
				node.Index = NodeType(index + expanders.N*l)
				node.Parents = node.Parents[:0]
				CalcParents(expanders, node, MinerID, Count)
				out <- node
			}
		}
	}()
	return out
}
