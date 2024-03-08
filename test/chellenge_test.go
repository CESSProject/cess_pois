package test

import (
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/CESSProject/cess_pois/acc"
	"github.com/CESSProject/cess_pois/expanders"
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
	spaceChals := []int64{9263791, 8785184, 8430062, 9266903, 8693449, 9054566, 8878802, 9038905}
	prover.SetChallengeStateForTest(279, 32768)
	proofHandle := prover.NewChallengeHandle([]byte("test tee id"), spaceChals)

	log.Println("miner id:", []byte("test miner id"))
	log.Println("tee id:", []byte("test tee id"))
	log.Println("challenges:", spaceChals)
	log.Println("front:", 279, "rear:", 32768, "proof num:", 7)

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
		t.Log(verifyHandle(prior, left, right))
		prior = expanders.GetHash([]byte(fmt.Sprintln(left, right)))
	}
}

func TestChange(t *testing.T) {
	data := []byte{36, 54, 193, 23, 107, 2, 54, 61, 245, 167, 147, 116, 249, 242, 164, 126, 212, 107, 40, 47, 231, 4, 16, 78, 82, 49, 87, 150, 137, 190, 180, 25, 163, 193, 25, 179, 162, 146, 151, 251, 255, 196, 160, 3, 115, 180, 173, 58, 0, 55, 186, 112, 231, 5, 114, 82, 10, 162, 120, 145, 93, 150, 54, 78}
	log.Println("value", expanders.BytesToInt64(data, 15))
}

func TestFuncGetBytes(t *testing.T) {
	chal := []int64{9263791, 8785184, 8430062, 9266903, 8693449, 9054566, 8878802, 9038905}
	//var data int64 = 10
	bytes := expanders.GetBytes(chal)
	log.Println(bytes)
}

func TestHexString(t *testing.T) {
	hash := []byte{232, 48, 44, 108, 119, 129, 206, 230, 197, 99, 68, 187, 59, 202, 175, 159, 104, 171, 230, 86, 225, 77, 55, 75, 181, 33, 195, 253, 16, 156, 235, 136}
	t.Log(hex.EncodeToString(hash))
}
