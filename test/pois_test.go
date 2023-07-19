package test

import (
	"bytes"
	"cess_pois/acc"
	"cess_pois/pois"
	"cess_pois/util"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

func TestPois(t *testing.T) {
	//Initialize the execution environment
	k, n, d := int64(7), int64(1024*1024), int64(64)
	// key, err := ParseKey("./key")
	// if err != nil {
	// 	t.Fatal("parse key error", err)
	// }
	key := acc.RsaKeygen(2048)
	err := SaveKey("./key", key)
	if err != nil {
		t.Fatal("save key error", err)
	}
	prover, err := pois.NewProver(k, n, d, []byte("test miner id"), 64*64*8, 64)
	if err != nil {
		t.Fatal("new prover error", err)
	}
	//err = prover.Recovery(key, 32, 64)
	err = prover.Init(key)
	if err != nil {
		t.Fatal("recovery prover error", err)
	}
	verifier := pois.NewVerifier(k, n, d)

	ts := time.Now()
	err = prover.GenerateIdleFileSet()
	if err != nil {
		t.Fatal("generate idle file set error", err)
	}
	t.Log("generate idle file set time", time.Since(ts))

	//get commits
	ts = time.Now()
	commits, err := prover.GetIdleFileSetCommits()
	if err != nil {
		t.Fatal("get commits error", err)
	}
	t.Log("get commits time", time.Since(ts))

	//register prover
	verifier.RegisterProverNode(prover.ID, key, prover.AccManager.GetSnapshot().Accs.Value, 0, 0)

	//verifier receive commits
	ts = time.Now()
	if !verifier.ReceiveCommits(prover.ID, commits) {
		t.Fatal("receive commits error", err)
	}
	t.Log("verifier receive commits time", time.Since(ts))

	//generate commits challenges
	ts = time.Now()
	chals, err := verifier.CommitChallenges(prover.ID)
	if err != nil {
		t.Fatal("generate commit challenges error", err)
	}
	t.Log("generate commit challenges time", time.Since(ts))

	//prove commit and acc
	ts = time.Now()
	commitProofs, accProof, err := prover.ProveCommitAndAcc(chals)
	if err != nil {
		t.Fatal("prove commit error", err)
	}
	if err == nil && commitProofs == nil && accProof == nil {
		t.Log("update or delete task is already running")
	}
	t.Log("prove commit time", time.Since(ts))

	//verify commit proof
	ts = time.Now()
	err = verifier.VerifyCommitProofs(prover.ID, chals, commitProofs)
	if err != nil {
		t.Fatal("verify commit proof error", err)
	}
	t.Log("verify commit proof time", time.Since(ts))

	//verify acc proof
	ts = time.Now()
	err = verifier.VerifyAcc(prover.ID, chals, accProof)
	if err != nil {
		t.Fatal("verify acc proof error", err)
	}
	t.Log("verify acc proof time", time.Since(ts))

	//add file to count
	ts = time.Now()
	err = prover.UpdateStatus(int64(len(chals)), false)
	if err != nil {
		t.Fatal("update status error", err)
	}
	prover.UpdateChainState()
	t.Log("update prover status time", time.Since(ts))
	//generate space challenges
	ts = time.Now()
	spaceChals, err := verifier.SpaceChallenges(22)
	if err != nil {
		t.Fatal("generate space chals error", err)
	}
	t.Log("generate space chals time", time.Since(ts))

	//prove space
	ts = time.Now()
	spaceProof, err := prover.ProveSpace(spaceChals, 1, 65)
	if err != nil {
		t.Fatal("prove space error", err)
	}
	t.Log("prove space time", time.Since(ts))

	//verify space proof
	ts = time.Now()
	err = verifier.VerifySpace(verifier.GetNode(prover.ID), spaceChals, spaceProof)
	if err != nil {
		t.Fatal("verify space proof error", err)
	}
	t.Log("verify space proof time", time.Since(ts))

	//deletion proof
	ts = time.Now()
	chProof, Err := prover.ProveDeletion(32)
	var delProof *pois.DeletionProof
	select {
	case err = <-Err:
		t.Fatal("prove deletion proof error", err)
	case delProof = <-chProof:
		break
	}
	t.Log("prove deletion proof time", time.Since(ts))

	if delProof == nil && err == nil {
		t.Log("no need to prove deletion proof.")
		return
	} else if err != nil {
		t.Fatal("prove deletion proof error", err)
	}

	//verify deletion proof
	ts = time.Now()
	err = verifier.VerifyDeletion(prover.ID, delProof)
	if err != nil {
		t.Fatal("verify deletion proof error", err)
	}
	t.Log("verify deletion proof time", time.Since(ts))
	//add file to count
	ts = time.Now()
	err = prover.UpdateStatus(int64(len(delProof.Roots)), true)
	if err != nil {
		t.Fatal("update count error", err)
	}
	t.Log("update prover status time", time.Since(ts))
}

func ToBytes(key acc.RsaKey) []byte {

	n, g := key.N.Bytes(), key.G.Bytes()
	nl, gl := int64(len(n)), int64(len(g))
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, nl)
	binary.Write(buf, binary.BigEndian, gl)
	data := make([]byte, buf.Len()+int(nl+gl))
	copy(data[:16], buf.Bytes())
	copy(data[16:16+nl], n)
	copy(data[16+nl:], g)
	return data
}

func GetKeyFromBytes(data []byte) acc.RsaKey {
	if len(data) < 8 {
		return acc.RsaKeygen(2048)
	}
	nl := binary.BigEndian.Uint64(data[:8])
	gl := binary.BigEndian.Uint64(data[8:16])
	if nl <= 0 || gl <= 0 || len(data)-16 != int(nl+gl) {
		return acc.RsaKeygen(2048)
	}
	key := acc.RsaKey{
		N: *(big.NewInt(0).SetBytes(data[16 : 16+nl])),
		G: *(big.NewInt(0).SetBytes(data[16+nl:])),
	}
	return key
}

func SaveKey(path string, key acc.RsaKey) error {
	bytes := ToBytes(key)
	return util.SaveFile(path, bytes)
}

func ParseKey(path string) (acc.RsaKey, error) {
	bytes, err := util.ReadFile(path)
	if err != nil {
		return acc.RsaKeygen(2048), err
	}
	return GetKeyFromBytes(bytes), nil
}
