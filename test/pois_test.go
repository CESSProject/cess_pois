package test

import (
	"cess_pois/acc"
	"cess_pois/pois"
	"testing"
	"time"
)

func TestPois(t *testing.T) {
	//Initialize the execution environment
	k, n, d := int64(7), int64(1024*1024*4), int64(64)
	key := acc.RsaKeygen(2048)
	prover, err := pois.NewProver(k, n, d, []byte("test miner id"), key, 8192)
	if err != nil {
		t.Fatal("init prover error", err)
	}
	verifier := pois.NewVerifier(key, k, n, d)

	//run idle file generation server
	prover.RunIdleFileGenerationServer(pois.MaxCommitProofThread)

	//add file to generate
	ok := prover.GenerateFile(4)
	if !ok {
		t.Fatal("generate file error")
	}
	//wait 8 minutes for file generate
	time.Sleep(time.Minute * 12)
	ts := time.Now()

	//get commits
	commits, err := prover.GetCommits(4)
	if err != nil {
		t.Fatal("get commits error", err)
	}
	t.Log("get commits time", time.Since(ts))

	//register prover
	verifier.RegisterProverNode(prover.ID, key.G.Bytes(), 0)

	//verifier receive commits
	ts = time.Now()
	if !verifier.ReceiveCommits(prover.ID, commits) {
		t.Fatal("receive commits error", err)
	}
	t.Log("verifier receive commits time", time.Since(ts))

	//generate commits challenges
	ts = time.Now()
	chals, err := verifier.CommitChallenges(prover.ID, 0, 4)
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
	t.Log("update prover status time", time.Since(ts))
	//generate space challenges
	ts = time.Now()
	spaceChals, err := verifier.SpaceChallenges(prover.ID, int64(len(chals)))
	if err != nil {
		t.Fatal("generate space chals error", err)
	}
	t.Log("generate space chals time", time.Since(ts))

	//prove space
	ts = time.Now()
	spaceProof, err := prover.ProveSpace(spaceChals)
	if err != nil {
		t.Fatal("prove space error", err)
	}
	t.Log("prove space time", time.Since(ts))

	//verify space proof
	ts = time.Now()
	err = verifier.VerifySpace(prover.ID, spaceChals, spaceProof)
	if err != nil {
		t.Fatal("verify space proof error", err)
	}
	t.Log("verify space proof time", time.Since(ts))

	//deletion proof
	ts = time.Now()
	chProof, Err := prover.ProveDeletion(4 * 8)
	var delProof *pois.DeletionProof
	select {
	case err = <-Err:
		t.Fatal("prove deletion proof error", err)
	case delProof = <-chProof:
		break
	}
	t.Log("prove deletion proof time", time.Since(ts))

	if delProof == nil {
		t.Log("no need to prove deletion proof.")
		return
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
