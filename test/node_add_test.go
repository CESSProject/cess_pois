package test

import (
	"cess_pois/expanders"
	"crypto/rand"
	"math/big"
	"testing"
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

func TestCalcParent(t *testing.T) {
	graph := expanders.NewExpanders(3, 1024, 64)
	node := expanders.NewNode(3097)
	node.Parents = make([]expanders.NodeType, 0, graph.D+1)
	expanders.CalcParents(graph, node, []byte("test miner id"), 1)
	t.Log("node:", node)
}

func TestGetBytes(t *testing.T) {
	for i := 0; i < 4096; i++ {
		b := expanders.GetBytes(expanders.NodeType(i))
		if len(b) != 4 {
			t.Log("error length", len(b), b)
			break
		}
	}
}
