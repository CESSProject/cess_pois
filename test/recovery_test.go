package test

import (
	"testing"

	"github.com/CESSProject/cess_pois/acc"
	"github.com/CESSProject/cess_pois/pois"
)

func TestRestoreRowIdleFile(t *testing.T) {
	k, n, d := int64(8), int64(1024*16), int64(64)
	key := acc.RsaKeygen(2048)
	prover, err := pois.NewProver(k, n, d, []byte("test miner id"), 256*64*2, 32)
	if err != nil {
		t.Fatal("new prover error", err)
	}
	err = prover.Init(key, pois.Config{})
	if err != nil {
		t.Fatal("init prover error", err)
	}
	err = prover.RestoreRawIdleFiles(3)
	if err != nil {
		t.Fatal("restore raw idle files error", err)
	}
}

func TestRestoreIdleFile(t *testing.T) {
	k, n, d := int64(8), int64(1024*16), int64(64)
	key := acc.RsaKeygen(2048)
	prover, err := pois.NewProver(k, n, d, []byte("test miner id"), 256*64*2, 32)
	if err != nil {
		t.Fatal("new prover error", err)
	}
	err = prover.Init(key, pois.Config{})
	if err != nil {
		t.Fatal("init prover error", err)
	}
	err = prover.RestoreIdleFiles(7)
	if err != nil {
		t.Fatal("restore idle files error", err)
	}
}

func TestRestoreSubAccFile(t *testing.T) {
	k, n, d := int64(8), int64(1024*16), int64(64)
	key := acc.RsaKeygen(2048)
	prover, err := pois.NewProver(k, n, d, []byte("test miner id"), 256*64*2, 32)
	if err != nil {
		t.Fatal("new prover error", err)
	}
	err = prover.Recovery(key, 0, 256, pois.Config{})
	if err != nil {
		t.Log("init prover error", err)
	}
	err = prover.CheckAndRestoreSubAccFiles(0, 256)
	if err != nil {
		t.Fatal("restore sub acc file error", err)
	}
}
