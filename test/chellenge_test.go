package test

import (
	"fmt"
	"log"
	"testing"

	"github.com/CESSProject/cess_pois/acc"
	"github.com/CESSProject/cess_pois/pois"
)

func TestChellenges(t *testing.T) {
	k, n, d := int64(8), int64(1024*1024), int64(64)
	key := acc.RsaKeygen(2048)
	err := SaveKey("./key", key)
	if err != nil {
		t.Fatal("save key error", err)
	}
	prover, err := pois.NewProver(k, n, d, []byte("test miner id"), 256*64*2*4, 32)
	if err != nil {
		t.Fatal("new prover error", err)
	}
	verifier := pois.NewVerifier(k, n, d)
	spaceChals, err := verifier.SpaceChallenges(8)
	if err != nil {
		t.Fatal("generate space chals error", err)
	}
	prover.SetChallengeStateForTest(279, 32768)
	proofHandle := prover.NewChallengeHandle([]byte("test tee id"), spaceChals)
	t.Log(279 % 256)
	verifyHandle := pois.NewChallengeHandle([]byte("test miner id"), []byte("test tee id"), spaceChals, 279, 32768, 7)
	if verifyHandle == nil {
		t.Log("error proof number")
		return
	}
	var prior []byte
	for {
		left, right := proofHandle(prior)
		if left == right {
			break
		}
		log.Println("left", left, "right", right)
		log.Println("test result", verifyHandle(prior, left, right))
		prior = []byte(fmt.Sprintln(left, right))
	}
}
