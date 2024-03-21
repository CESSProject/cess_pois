package test

import (
	"sync"
	"testing"
	"time"

	"github.com/CESSProject/cess_pois/expanders"
	"github.com/CESSProject/cess_pois/tree"
)

func TestIdleFileSetGeneration(t *testing.T) {
	ts := time.Now()
	tree.InitMhtPool(1024 * 1024)
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
	tree.InitMhtPool(1024 * 1024)
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
