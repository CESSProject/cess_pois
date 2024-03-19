package test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/CESSProject/cess_pois/expanders"
)

func TestAddNode(t *testing.T) {
	node := expanders.NewNode(1)
	node.Parents = make([]expanders.NodeType, 0, 100)
	for i := 0; i < 100; i++ {
		p, _ := rand.Int(rand.Reader, big.NewInt(1024))
		if node.AddParent(expanders.NodeType(p.Int64() + 1)) {
			t.Log("add parent success", p.Int64()+1)
			t.Log("parent:", node.Parents)
		}
	}
	t.Log(len(node.Parents), node.Parents)
}

func TestAddNode2(t *testing.T) {
	node := expanders.NewNode(0)
	node.Parents = make([]expanders.NodeType, 0, 100)
	for i := 0; i < 100; i++ {
		if node.AddParent(expanders.NodeType(i + 1)) {
			t.Log("add parent success", i+1)
			t.Log("parent:", node.Parents)
		}
	}
	t.Log(len(node.Parents), node.Parents)
}
