package pois

import (
	"bytes"
	"cess_pois/acc"
	"cess_pois/expanders"
	"cess_pois/tree"
	"cess_pois/util"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"unsafe"

	"github.com/pkg/errors"
)

var (
	MaxBufSize = 1 * 16
	verifier   *Verifier
	SpaceChals = 1
	Pick       = 1
)

// ProverNode denote Prover
type ProverNode struct {
	ID         []byte   // Prover ID(generally, use AccountID)
	CommitsBuf []Commit //buffer for all layer MHT proofs of one commit
	BufSize    int
	Acc        []byte //Prover's accumulator
	Count      int64  // Idle file proofs' counter
}

type Verifier struct {
	Key       acc.RsaKey
	Expanders expanders.Expanders
	Nodes     map[string]*ProverNode
}

func NewVerifier(key acc.RsaKey, k, n, d int64) *Verifier {
	verifier = &Verifier{
		Key:       key,
		Expanders: *expanders.NewExpanders(k, n, d),
		Nodes:     make(map[string]*ProverNode),
	}
	return verifier
}

func GetVerifier() *Verifier {
	return verifier
}

func (v *Verifier) RegisterProverNode(ID []byte, acc []byte, Count int64) error {
	id := hex.EncodeToString(ID)
	if _, ok := v.Nodes[id]; ok {
		err := errors.New("prover node already exist")
		return errors.Wrap(err, "register prover node error")
	}
	v.Nodes[id] = &ProverNode{
		ID:         ID,
		CommitsBuf: make([]Commit, MaxBufSize),
		Acc:        acc,
		Count:      Count,
	}
	return nil
}

func (v *Verifier) ReceiveCommits(ID []byte, commits []Commit) bool {
	id := hex.EncodeToString(ID)
	pNode, ok := v.Nodes[id]
	if !ok {
		return false
	} else if !bytes.Equal(pNode.ID, ID) {
		return false
	}
	if len(commits) > MaxBufSize-pNode.BufSize {
		commits = commits[:MaxBufSize-pNode.BufSize]
	}
	hash := expanders.NewHash()
	for i := 0; i < len(commits); i++ {
		if len(commits[i].Roots) != int(v.Expanders.K+2) {
			return false
		}
		hash.Reset()
		for j := 0; j < len(commits[i].Roots)-1; j++ {
			hash.Write(commits[i].Roots[j])
		}
		if !bytes.Equal(commits[i].Roots[v.Expanders.K+1],
			hash.Sum(nil)) {
			return false
		}
		pNode.CommitsBuf[pNode.BufSize] = commits[i]
		pNode.BufSize += 1
	}
	return true
}

func (v *Verifier) CommitChallenges(ID []byte, left, right int) ([][]int64, error) {
	id := hex.EncodeToString(ID)
	pNode, ok := v.Nodes[id]
	if !ok {
		err := errors.New("prover node not found")
		return nil, errors.Wrap(err, "generate commit challenges error")
	}
	if right-left <= 0 || right > pNode.BufSize || left < 0 {
		err := errors.New("bad file number")
		return nil, errors.Wrap(err, "generate commit challenges error")
	}
	challenges := make([][]int64, right-left)
	for i := left; i < right; i++ {
		idx := i - left
		challenges[idx] = make([]int64, v.Expanders.K+2)
		challenges[idx][0] = pNode.CommitsBuf[i].FileIndex
		r, err := rand.Int(rand.Reader, new(big.Int).SetInt64(v.Expanders.N))
		if err != nil {
			return nil, errors.Wrap(err, "generate commit challenges error")
		}
		r.Add(r, new(big.Int).SetInt64(v.Expanders.N*v.Expanders.K))
		challenges[idx][1] = r.Int64()
		for j := 2; j < int(v.Expanders.K+2); j++ {
			r, err := rand.Int(rand.Reader, new(big.Int).SetInt64(v.Expanders.D+1))
			if err != nil {
				return nil, errors.Wrap(err, "generate commit challenges error")
			}
			challenges[idx][j] = r.Int64()
		}
	}
	return challenges, nil
}

func (v *Verifier) SpaceChallenges(ID []byte, param int64) ([][]int64, error) {
	//Randomly select several nodes from idle files as random challenges
	id := hex.EncodeToString(ID)
	pNode, ok := v.Nodes[id]
	if !ok {
		err := errors.New("prover node not found")
		return nil, errors.Wrap(err, "generate commit challenges error")
	}
	if pNode.Count < param {
		param = pNode.Count
	}
	challenges := make([][]int64, param)
	mp := make(map[int64]struct{})
	for i := int64(0); i < param; i++ {
		for {
			r1, err := rand.Int(rand.Reader, new(big.Int).SetInt64(pNode.Count))
			if err != nil {
				return nil, errors.Wrap(err, "generate commit challenges error")
			}
			//range [1,Count]
			r1 = r1.Add(r1, big.NewInt(1))
			if _, ok := mp[r1.Int64()]; ok {
				continue
			}
			challenges[i] = make([]int64, SpaceChals+1)
			challenges[i][0] = r1.Int64()
			r2, err := rand.Int(rand.Reader, new(big.Int).SetInt64(v.Expanders.N))
			if err != nil {
				return nil, errors.Wrap(err, "generate commit challenges error")
			}
			r2.Add(r2, new(big.Int).SetInt64(v.Expanders.N*v.Expanders.K))
			challenges[i][1] = r2.Int64()
			break
		}
	}
	return challenges, nil
}

func (v *Verifier) VerifyCommitProofs(ID []byte, chals [][]int64, proofs [][]CommitProof) error {
	id := hex.EncodeToString(ID)
	pNode, ok := v.Nodes[id]
	if !ok {
		err := errors.New("prover node not found")
		return errors.Wrap(err, "verify commit proofs error")
	}
	if len(chals) != len(proofs) || len(chals) > pNode.BufSize {
		err := errors.New("bad proof data")
		return errors.Wrap(err, "verify commit proofs error")
	}

	if err := v.VerifyNodeDependencies(ID, chals, proofs, Pick); err != nil {
		return errors.Wrap(err, "verify commit proofs error")
	}

	index := 0
	for i := 0; i < pNode.BufSize; i++ {
		if chals[0][0] == pNode.CommitsBuf[i].FileIndex {
			index = i
			break
		}
	}
	frontSize := int(unsafe.Sizeof(expanders.NodeType(0))) + len(ID) + 8
	hashSize := expanders.HashSize
	label := make([]byte, frontSize+int(v.Expanders.D+1)*hashSize)
	for i := 0; i < len(proofs); i++ {

		if chals[i][1] != int64(proofs[i][0].Node.Index) {
			err := errors.New("bad expanders node index")
			return errors.Wrap(err, "verify commit proofs error")
		}

		var idx expanders.NodeType
		for j := 1; j < len(chals[i]); j++ {
			if j == 1 {
				idx = expanders.NodeType(chals[i][1])
			} else {
				idx = expanders.NodeType(proofs[i][j-2].Parents[chals[i][j]].Index)
			}

			layer := int64(idx) / v.Expanders.N
			root := pNode.CommitsBuf[index+i].Roots[layer]
			pathProof := tree.PathProof{
				Locs: proofs[i][j-1].Node.Locs,
				Path: proofs[i][j-1].Node.Paths,
			}
			if !tree.VerifyPathProof(root, proofs[i][j-1].Node.Label, pathProof) {
				err := errors.New("verify path proof error")
				return errors.Wrap(err, "verify commit proofs error")
			}
			if len(proofs[i][j-1].Parents) <= 0 {
				continue
			}
			util.CopyData(
				label, ID,
				expanders.GetBytes(int64(chals[i][0])),
				expanders.GetBytes(idx),
			)
			size := frontSize
			for _, p := range proofs[i][j-1].Parents {
				if int64(p.Index) >= layer*v.Expanders.N {
					root = pNode.CommitsBuf[index+i].Roots[layer]
				} else {
					root = pNode.CommitsBuf[index+i].Roots[layer-1]
				}
				pathProof := tree.PathProof{
					Locs: p.Locs,
					Path: p.Paths,
				}
				if !tree.VerifyPathProof(root, p.Label, pathProof) {
					err := errors.New("verify parent path proof error")
					return errors.Wrap(err, "verify commit proofs error")
				}
				copy(label[size:size+hashSize], p.Label)
				size += hashSize
			}
			if !bytes.Equal(expanders.GetHash(label), proofs[i][j-1].Node.Label) {
				err := errors.New("verify label error")
				return errors.Wrap(err, "verify commit proofs error")
			}
		}
	}

	return nil
}

func (v *Verifier) VerifyNodeDependencies(ID []byte, chals [][]int64, proofs [][]CommitProof, pick int) error {
	if pick > len(proofs) {
		pick = len(proofs)
	}
	for i := 0; i < pick; i++ {
		r1, err := rand.Int(rand.Reader, new(big.Int).SetInt64(int64(len(proofs))))
		if err != nil {
			return errors.Wrap(err, "verify node dependencies error")
		}
		r2, err := rand.Int(rand.Reader, new(big.Int).SetInt64(int64(len(proofs[r1.Int64()])-1)))
		if err != nil {
			return errors.Wrap(err, "verify node dependencies error")
		}
		proof := proofs[r1.Int64()][r2.Int64()]
		node := expanders.NewNode(proof.Node.Index)
		node.Parents = make([]expanders.NodeType, 0, v.Expanders.D+1)
		expanders.CalcParents(&v.Expanders, node, ID, chals[r1.Int64()][0])
		for j := 0; j < len(node.Parents); j++ {
			if node.Parents[j] != proof.Parents[j].Index {
				err = errors.New("node relationship mismatch")
				return errors.Wrap(err, "verify node dependencies error")
			}
		}
	}
	return nil
}

func (v *Verifier) VerifyAcc(ID []byte, chals [][]int64, proof *AccProof) error {
	id := hex.EncodeToString(ID)
	pNode, ok := v.Nodes[id]
	if !ok {
		err := errors.New("prover node not found")
		return errors.Wrap(err, "verify acc proofs error")
	}
	if len(chals) != len(proof.Indexs) || len(chals) > pNode.BufSize {
		err := errors.New("bad proof data")
		return errors.Wrap(err, "verify acc proofs error")
	}
	index := 0
	for i := 0; i < pNode.BufSize; i++ {
		if chals[0][0] == pNode.CommitsBuf[i].FileIndex {
			index = i
			break
		}
	}
	label := make([]byte, len(ID)+8+expanders.HashSize)
	for i := 0; i < len(chals); i++ {
		if chals[i][0] != proof.Indexs[i] && chals[i][0] != pNode.Count+int64(i)+1 {
			err := errors.New("bad file index")
			return errors.Wrap(err, "verify acc proofs error")
		}
		util.CopyData(label, ID, expanders.GetBytes(chals[i][0]),
			pNode.CommitsBuf[i+index].Roots[v.Expanders.K])
		if !bytes.Equal(expanders.GetHash(label), proof.Labels[i]) {
			err := errors.New("verify file label error")
			return errors.Wrap(err, "verify acc proofs error")
		}
	}
	if !acc.VerifyInsertUpdate(v.Key, proof.WitChains,
		proof.Labels, proof.AccPath, pNode.Acc) {
		err := errors.New("verify muti-level acc error")
		return errors.Wrap(err, "verify acc proofs error")
	}
	pNode.Acc = proof.AccPath[len(proof.AccPath)-1]
	pNode.CommitsBuf = append(pNode.CommitsBuf[:index],
		pNode.CommitsBuf[index+len(chals):]...)
	pNode.BufSize -= len(chals)
	pNode.Count += int64(len(chals))
	return nil
}

func (v *Verifier) VerifySpace(ID []byte, chals [][]int64, proof *SpaceProof) error {
	id := hex.EncodeToString(ID)
	pNode, ok := v.Nodes[id]
	if !ok {
		err := errors.New("prover node not found")
		return errors.Wrap(err, "verify space proofs error")
	}
	if len(chals) != len(proof.Roots) {
		err := errors.New("bad proof data")
		return errors.Wrap(err, "verify space proofs error")
	}
	label := make([]byte, len(ID)+8+expanders.HashSize)
	for i := 0; i < len(chals); i++ {
		if chals[i][1] != int64(proof.Proofs[i].Index) {
			err := errors.New("bad file index")
			return errors.Wrap(err, "verify space proofs error")
		}
		pathProof := tree.PathProof{
			Locs: proof.Proofs[i].Locs,
			Path: proof.Proofs[i].Paths,
		}
		if !tree.VerifyPathProof(proof.Roots[i], proof.Proofs[i].Label, pathProof) {
			err := errors.New("verify path proof error")
			return errors.Wrap(err, "verify space proofs error")
		}
		util.CopyData(label, ID, expanders.GetBytes(chals[i][0]), proof.Roots[i])
		if !bytes.Equal(expanders.GetHash(label), proof.WitChains[i].Elem) {
			err := errors.New("verify file label error")
			return errors.Wrap(err, "verify space proofs error")
		}
		if !acc.VerifyMutilevelAcc(v.Key, proof.WitChains[i], pNode.Acc) {
			err := errors.New("verify acc proof error")
			return errors.Wrap(err, "verify space proofs error")
		}
	}
	return nil
}

func (v *Verifier) VerifyDeletion(ID []byte, proof *DeletionProof) error {
	id := hex.EncodeToString(ID)
	pNode, ok := v.Nodes[id]
	if !ok {
		err := errors.New("prover node not found")
		return errors.Wrap(err, "verify deletion proofs error")
	}
	if pNode.BufSize > 0 {
		err := errors.New("commit proof not finished")
		return errors.Wrap(err, "verify deletion proofs error")
	}
	lens := len(proof.Roots)
	if int64(lens) > pNode.Count {
		err := errors.New("file number out of range")
		return errors.Wrap(err, "verify deletion proofs error")
	}
	labels := make([][]byte, lens)
	for i := 0; i < lens; i++ {
		label := make([]byte, len(ID)+8+expanders.HashSize)
		util.CopyData(label, ID,
			expanders.GetBytes(pNode.Count-int64(lens-i-1)), proof.Roots[i])
		labels[i] = expanders.GetHash(label)
	}
	if !acc.VerifyDeleteUpdate(v.Key, proof.WitChain,
		labels, proof.AccPath, pNode.Acc) {
		err := errors.New("verify acc proof error")
		return errors.Wrap(err, "verify deletion proofs error")
	}
	return nil
}
