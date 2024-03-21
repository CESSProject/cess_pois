package test

import (
	"crypto/sha256"
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
	mienrId := []byte{172, 72, 249, 160, 225, 118, 111, 74, 205, 240, 162, 201, 102, 196, 178, 76, 7, 50, 162, 126, 116, 46, 247, 232, 181, 119, 46, 203, 110, 186, 78, 53}
	prover, err := pois.NewProver(k, n, d, mienrId, 256*64*2*4, 32)
	if err != nil {
		t.Fatal("new prover error", err)
	}

	teeId := make([]byte, 32)
	//teeId:=[]byte("test tee id")
	spaceChals := []int64{1313468, 1324540, 1315686, 1324882, 1314250, 1315972, 1311902, 1319999}
	prover.SetChallengeStateForTest(0, 4864)
	proofHandle := prover.NewChallengeHandle(teeId, spaceChals)

	log.Println("miner id:", mienrId)
	log.Println("tee id:", teeId)
	log.Println("challenges:", spaceChals)
	log.Println("front:", 0, "rear:", 4864, "proof num:", 8)
	verifyHandle := pois.NewChallengeHandle(mienrId, teeId, spaceChals, 0, 4864, 2)
	if verifyHandle == nil {
		t.Log("error proof number")
		return
	}
	var prior []byte
	var lefts, rights []int64
	for {
		left, right := proofHandle(prior)
		if left == right {
			break
		}
		lefts = append(lefts, left)
		rights = append(rights, right)
		t.Log(verifyHandle(prior, left, right))
		t.Log("prior", prior)
		prior = expanders.GetHash([]byte(fmt.Sprintln(left, right)))
	}
	t.Log("lefts", lefts)
	t.Log("rights", rights)
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

func TestCalcHash(t *testing.T) {
	data := []byte{}
	hash := sha256.New()
	hash.Write(data)
	t.Log(hash.Sum(nil))
}
