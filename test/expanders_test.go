package test

import (
	"cess_pois/expanders"
	"cess_pois/tree"
	_ "net/http/pprof"
	"sync"
	"testing"
	"time"
)

func TestIdleFileGeneration(t *testing.T) {
	ts := time.Now()
	tree.InitMhtPool(1024*1024, expanders.HashSize)
	graph := expanders.ConstructStackedExpanders(7, 1024*1024*4, 64)
	t.Log("construct stacked expanders time", time.Since(ts))
	ts = time.Now()
	wg := sync.WaitGroup{}
	wg.Add(4)
	for i := 0; i < 4; i++ {
		go func(count int) {
			defer wg.Done()
			err := graph.GenerateIdleFile([]byte("test miner id"), int64(count+1), expanders.DEFAULT_IDLE_FILES_PATH)
			if err != nil {
				t.Log("generate idle file", err)
			}
		}(i)
	}
	wg.Wait()
	t.Log("generate idle file time", time.Since(ts))
}

func TestRealationMap(t *testing.T) {
	graph := expanders.ConstructStackedExpanders(7, 1024*1024*4, 64)
	ch := graph.RunRelationalMapServer([]byte("test id"), 1)
	ts := time.Now()
	count := 1
	for range ch {
		if count >= int((graph.K+1)*graph.N) {
			break
		}
		count++
	}
	t.Log("time", time.Since(ts))
}
