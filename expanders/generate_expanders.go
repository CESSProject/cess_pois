package expanders

import (
	"github.com/CESSProject/cess_pois/util"
)

func ConstructStackedExpanders(k, n, d int64) *Expanders {
	return NewExpanders(k, n, d, DEFAULT_HASH_SIZE)
}

// CalcParents calculate all parent nodes of a node using pseudo-random numbers
func CalcParents(expanders *Expanders, node *Node, MinerID []byte, Count ...int64) {

	if node == nil || expanders == nil ||
		cap(node.Parents) != int(expanders.D+1) {
		return
	}
	layer := int64(node.Index) / expanders.N
	if layer == 0 { // if layer is 0, no dependencies required
		return
	}
	baseParent := NodeType((layer - 1) * expanders.N)

	// int64 byte size is 8, lens=len(minerID)+16*(parent index length)+(layer index length)+len(Count)*(cluster index length)
	lens := len(MinerID) + 8*17 + len(Count)*8
	content := make([]byte, lens)
	util.CopyData(content, MinerID, GetBytes(Count), GetBytes(layer)) // populate basic data

	directParent := node.Index - NodeType(expanders.N)
	node.AddParent(directParent) // add first parent(direct parent)

	plate := make([][]byte, 16)                   //the 64-byte hash result can calculate 16 4-byte parent node indexes
	for i := int64(0); i < expanders.D; i += 16 { //ask expanders.D%16==0
		//add index to conent
		for j := int64(0); j < 16; j++ {
			plate[j] = GetBytes(i + j)
		}
		util.CopyData(content[lens-8*16:], plate...) //populate the relative index of the parent node
		hash := expanders.GetHash(content)
		p := NodeType(0)
		for j := 0; j < 16; {
			p = BytesToNodeValue(hash[j*4:(j+1)*4], expanders.N)
			p = p%NodeType(expanders.N) + baseParent //calculate pseudo-random parent node index
			for {
				if p < directParent { //is it necessary to localize
					if _, ok := node.ParentInList(p + NodeType(expanders.N)); !ok {
						break
					}
				} else if _, ok := node.ParentInList(p); !ok {
					break
				}
				p = (p+1)%NodeType(expanders.N) + baseParent
			}
			if p < directParent { //localization
				p += NodeType(expanders.N)
			}
			if node.AddParent(p) {
				j++
			}
		}
	}
}
