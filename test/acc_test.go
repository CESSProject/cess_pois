package test

import (
	"testing"
	"time"

	"github.com/CESSProject/cess_pois/acc"
	"github.com/CESSProject/cess_pois/util"
)

func TestACC(t *testing.T) {
	data := make([][]byte, 1024)
	for i := 0; i < len(data); i++ {
		data[i] = []byte(util.RandString(256))
	}
	key := acc.RsaKeygen(2048)
	ts := time.Now()
	acc.GenerateWitness(key.G, key.N, data)
	t.Log("test acc success", time.Since(ts))
}

func TestAppend(t *testing.T) {
	a := make([]int, 0, 10)
	b := append(a, 10)
	t.Log(a, b)
}
