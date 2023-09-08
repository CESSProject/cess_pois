package test

import (
	"sync"
	"testing"
	"time"

	"github.com/CESSProject/cess_pois/expanders"
	"github.com/CESSProject/cess_pois/tree"
	"github.com/panjf2000/ants/v2"
)

func TestIdleFileSetGeneration(t *testing.T) {
	ts := time.Now()
	tree.InitMhtPool(1024*1024, expanders.HashSize)
	graph := expanders.ConstructStackedExpanders(8, 1024*1024, 64)
	t.Log("construct stacked expanders time", time.Since(ts))
	ts = time.Now()
	err := graph.GenerateIdleFileSet([]byte("test miner id"), 1, 32, expanders.DEFAULT_IDLE_FILES_PATH)
	if err != nil {
		t.Log("generate idle file set", err)
	}
	t.Log("generate idle file set time", time.Since(ts))
}

func TestIdleFilesSetGenerationParallely(t *testing.T) {
	ts := time.Now()
	tree.InitMhtPool(1024*1024, expanders.HashSize)
	graph := expanders.ConstructStackedExpanders(7, 1024*1024, 64)
	t.Log("construct stacked expanders time", time.Since(ts))
	ts = time.Now()
	wg := sync.WaitGroup{}
	for i := int64(0); i < 4; i++ {
		wg.Add(1)
		go func(count int64) {
			defer wg.Done()
			err := graph.GenerateIdleFileSet([]byte("test miner id"), 1+count*64, 64, expanders.DEFAULT_IDLE_FILES_PATH)
			if err != nil {
				t.Log("generate idle file set", err)
			}
		}(i)
	}
	wg.Wait()
	t.Log("generate idle file set time", time.Since(ts))
}

func TestRealationshipGeneration(t *testing.T) {
	graph := expanders.ConstructStackedExpanders(7, 1024*1024*4, 64)
	node := expanders.NewNode(0)
	node.Parents = make([]expanders.NodeType, 0, graph.D+1)
	st := time.Now()
	for i := 0; i < 1024*1024*8; i++ {
		node.Index = expanders.NodeType(i)
		node.Parents = node.Parents[:0]
		expanders.CalcParents(graph, node, []byte("test miner id"), 1)
	}
	t.Log("calc parents time", time.Since(st))
	t.Log("node parents:", node.Parents)
}

func TestChannel(t *testing.T) {
	ch := make(chan int64, 256)
	ts := time.Now()
	for i := int64(0); i < 256; i++ {
		ch <- i
	}
	t.Log("send data to channel time", time.Since(ts))
	close(ch)
	thread := 4
	wg := sync.WaitGroup{}
	wg.Add(thread)
	ts = time.Now()
	for i := 0; i < thread; i++ {
		ants.Submit(func() {
			wg.Done()
			for v := range ch {
				t.Log("value", v)
			}
		})
	}
	wg.Wait()
	t.Log("get data from channel time", time.Since(ts))
}
