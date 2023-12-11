package test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"log"
	"math/big"
	_ "net/http/pprof"
	"testing"
	"time"

	"github.com/CESSProject/cess_pois/acc"
	"github.com/CESSProject/cess_pois/pois"
	"github.com/CESSProject/cess_pois/util"
)

func TestPois(t *testing.T) {

	//Initialize the execution environment
	k, n, d := int64(8), int64(1024*16), int64(64)
	// key, err := ParseKey("./key")
	// if err != nil {
	// 	t.Fatal("parse key error", err)
	// }
	key := acc.RsaKeygen(2048)
	err := SaveKey("./key", key)
	if err != nil {
		t.Fatal("save key error", err)
	}
	prover, err := pois.NewProver(k, n, d, []byte("test miner id"), 256*64*2, 32)
	if err != nil {
		t.Fatal("new prover error", err)
	}
	err = prover.Recovery(key, 0, 0, pois.Config{})
	//err = prover.Init(key, pois.Config{})
	if err != nil {
		t.Fatal("recovery prover error", err)
	}
	verifier := pois.NewVerifier(k, n, d)
	nodes := pois.CreateNewNodes()

	ts := time.Now()
	err = prover.GenerateIdleFileSet()
	if err != nil {
		t.Fatal("generate idle file set error", err)
	}
	t.Log("generate idle file set time", time.Since(ts))

	// get commits
	ts = time.Now()
	commits, err := prover.GetIdleFileSetCommits()
	if err != nil {
		t.Fatal("get commits error", err)
	}
	t.Log("get commits time", time.Since(ts))

	//register prover

	nodes.RegisterProverNode(prover.ID, key, prover.AccManager.GetSnapshot().Accs.Value, 0, 0)

	//verifier receive commits
	ts = time.Now()
	pNode := nodes.GetNode(prover.ID)
	if !verifier.ReceiveCommits(&pNode, commits) {
		t.Fatal("receive commits error")
	}
	t.Log("verifier receive commits time", time.Since(ts))
	nodes.UpdateNode(pNode)
	//generate commits challenges
	ts = time.Now()
	chals, err := verifier.CommitChallenges(pNode)
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

	jdata1, err := json.Marshal(commitProofs)
	if err != nil {
		t.Fatal("data converted to json error", err)
	}
	jdata2, err := json.Marshal(accProof)
	if err != nil {
		t.Fatal("data converted to json error", err)
	}
	t.Log("commit and acc proof data length", len(jdata1), len(jdata2))
	//verify commit proof
	ts = time.Now()
	err = verifier.VerifyCommitProofs(nodes.GetNode(prover.ID), chals, commitProofs)
	if err != nil {
		t.Fatal("verify commit proof error", err)
	}
	t.Log("verify commit proof time", time.Since(ts))

	//verify acc proof
	ts = time.Now()
	pNode = nodes.GetNode(prover.ID)
	err = verifier.VerifyAcc(&pNode, chals, accProof)
	if err != nil {
		t.Fatal("verify acc proof error", err)
	}
	t.Log("verify acc proof time", time.Since(ts))

	nodes.UpdateNode(pNode)
	//add file to count
	ts = time.Now()
	err = prover.UpdateStatus(256, false)
	if err != nil {
		t.Fatal("update status error", err)
	}
	t.Log("update prover status time", time.Since(ts))

	t.Log("commit proof updated data:", prover.GetFront(), prover.GetRear())

	//deletion proof
	ts = time.Now()
	delProof, err := prover.ProveDeletion(8)

	if err != nil {
		t.Fatal("prove deletion proof error", err)
	}
	t.Log("prove deletion proof time", time.Since(ts))

	jdata, err := json.Marshal(delProof)
	if err != nil {
		t.Fatal("data converted to json error", err)
	}
	t.Log("deletion proof data length", len(jdata))

	ts = time.Now()
	//set space challenge state
	//err = prover.SetChallengeState(key, prover.AccManager.GetSnapshot().Accs.Value, 8, 256)
	err = prover.SetChallengeState(key, nodes.GetNode(prover.ID).Acc, 0, 256)
	if err != nil {
		t.Fatal("set challenge state error", err)
	}
	t.Log("set challenge state time", time.Since(ts))

	ts = time.Now()
	spaceChals, err := verifier.SpaceChallenges(8)
	if err != nil {
		t.Fatal("generate space chals error", err)
	}
	t.Log("generate space chals time", time.Since(ts))

	//prove space
	ts = time.Now()
	spaceProof, err := prover.ProveSpace(spaceChals, 1, 256+1)
	//spaceProof, err := prover.ProveSpace(spaceChals, 1, 257)
	if err != nil {
		t.Fatal("prove space error", err)
	}
	t.Log("prove space time", time.Since(ts))

	jdata, err = json.Marshal(spaceProof)
	if err != nil {
		t.Fatal("data converted to json error", err)
	}
	t.Log("space proof data length", len(jdata))

	//verify space proof
	ts = time.Now()
	err = verifier.VerifySpace(nodes.GetNode(prover.ID), spaceChals, spaceProof)
	if err != nil {
		t.Fatal("verify space proof error", err)
	}
	t.Log("verify space proof time", time.Since(ts))
	prover.RestChallengeState()

	//verify deletion proof
	ts = time.Now()
	pNode = nodes.GetNode(prover.ID)
	err = verifier.VerifyDeletion(&pNode, delProof)
	if err != nil {
		t.Fatal("verify deletion proof error", err)
	}
	t.Log("verify deletion proof time", time.Since(ts))
	nodes.UpdateNode(pNode)

	//add file to count
	// ts = time.Now()
	// err = prover.UpdateStatus(int64(len(delProof.Roots)), true)
	// if err != nil {
	// 	t.Fatal("update count error", err)
	// }
	// t.Log("update prover status time", time.Since(ts))
	// ts = time.Now()
	// err = prover.DeleteFiles()
	// if err != nil {
	// 	t.Fatal("delete files error", err)
	// }
	// t.Log("delete files time", time.Since(ts))
}

func TestGenPoisKey(t *testing.T) {
	st := time.Now()
	acc.RsaKeygen(2048)
	t.Log("gen pois key time ", time.Since(st))
}

func TestConcurrently(t *testing.T) {
	//Initialize the execution environment
	k, n, d := int64(8), int64(1024*1024), int64(64)
	// key, err := ParseKey("./key")
	// if err != nil {
	// 	t.Fatal("parse key error", err)
	// }
	key := acc.RsaKeygen(2048)
	err := SaveKey("./key", key)
	if err != nil {
		t.Fatal("save key error", err)
	}
	prover, err := pois.NewProver(k, n, d, []byte("test miner id"), 256*64*8, 32)
	if err != nil {
		t.Fatal("new prover error", err)
	}
	err = prover.Recovery(key, 0, 0, pois.Config{})
	//err = prover.Init(key, pois.Config{})
	if err != nil {
		t.Fatal("recovery prover error", err)
	}
	verifier := pois.NewVerifier(k, n, d)
	nodes := pois.CreateNewNodes()
	log.Println("prove acc", prover.AccManager.GetSnapshot().Accs.Value)
	nodes.RegisterProverNode(prover.ID, key, prover.AccManager.GetSnapshot().Accs.Value, 0, 0)
	start, ok, wt := make(chan struct{}), make(chan struct{}, 1), make(chan struct{})

	var (
		chals        [][]int64
		commitProofs [][]pois.CommitProof
		accProof     *pois.AccProof
	)

	go func() {
		for i := 0; i < 6; i++ {
			err := prover.GenerateIdleFileSet()
			if err != nil {
				log.Println("generate idle file set error", err)
				return
			}
			time.Sleep(3 * time.Second)
		}
	}()

	go func() {
		for {
			if !prover.CommitDataIsReady() {
				continue
			}
			commits, err := prover.GetIdleFileSetCommits()
			if err != nil {
				log.Println("get commits error", err)
				return
			}
			pNode := nodes.GetNode(prover.ID)
			if !verifier.ReceiveCommits(&pNode, commits) {
				log.Println("receive commits error")
				return
			}
			nodes.UpdateNode(pNode)
			chals, err = verifier.CommitChallenges(pNode)
			if err != nil {
				log.Println("generate commit challenges error", err)
				return
			}

			//prove commit and acc
			commitProofs, accProof, err = prover.ProveCommitAndAcc(chals)
			if err != nil {
				log.Println("prove commit error", err)
				return
			}
			if err == nil && commitProofs == nil && accProof == nil {
				log.Println("update or delete task is already running")
				return
			}
			ok <- struct{}{}
			start <- struct{}{}
			err = prover.UpdateStatus(int64(len(chals))*8, false)
			if err != nil {
				log.Println("update status error", err)
				return
			}
			log.Println("prove commit proofs success")
			log.Println(prover.AccManager.GetSnapshot().Accs.Value)
		}
	}()

	go func() {
		for {
			<-ok
			pNode := nodes.GetNode(prover.ID)
			err := verifier.VerifyCommitProofs(pNode, chals, commitProofs)
			if err != nil {
				log.Println("verify commit proof error", err)
				return
			}
			err = verifier.VerifyAcc(&pNode, chals, accProof)
			if err != nil {
				log.Println("verify acc proof error", err)
				return
			}
			nodes.UpdateNode(pNode)
			<-start
		}
	}()

	<-wt
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
