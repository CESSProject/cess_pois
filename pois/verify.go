package pois

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math"
	"math/big"
	"unsafe"

	"github.com/CESSProject/cess_pois/acc"
	"github.com/CESSProject/cess_pois/expanders"
	"github.com/CESSProject/cess_pois/tree"
	"github.com/CESSProject/cess_pois/util"

	"github.com/pkg/errors"
)

var (
	MaxBufSize = 1 * 16
	verifier   *Verifier
	SpaceChals int64 = 22
	Pick             = 1
)

type Record struct {
	Key    acc.RsaKey
	Acc    []byte
	Front  int64
	Rear   int64
	record int64
}

// ProverNode denote Prover
type ProverNode struct {
	ID         []byte   // Prover ID(generally, use AccountID)
	CommitsBuf []Commit //buffer for all layer MHT proofs of one commit
	BufSize    int
	*Record
}

type Verifier struct {
	Expanders expanders.Expanders
	Nodes     map[string]*ProverNode
}

func NewVerifier(k, n, d int64) *Verifier {
	verifier = &Verifier{
		Expanders: *expanders.NewExpanders(k, n, d),
		Nodes:     make(map[string]*ProverNode),
	}
	SpaceChals = int64(math.Log2(float64(n)))
	tree.InitMhtPool(int(n), expanders.HashSize)
	return verifier
}

func GetVerifier() *Verifier {
	return verifier
}

func (v *Verifier) RegisterProverNode(ID []byte, key acc.RsaKey, acc []byte, front, rear int64) {
	id := hex.EncodeToString(ID)
	node := NewProverNode(ID, key, acc, front, rear)
	node.CommitsBuf = make([]Commit, MaxBufSize)
	v.Nodes[id] = node
}

func NewProverNode(ID []byte, key acc.RsaKey, acc []byte, front, rear int64) *ProverNode {
	return &ProverNode{
		ID: ID,
		Record: &Record{
			Acc:    acc,
			Front:  front,
			Rear:   rear,
			Key:    key,
			record: front,
		},
	}
}

func (v *Verifier) GetNode(ID []byte) *ProverNode {
	id := hex.EncodeToString(ID)
	return v.Nodes[id]
}

func (v *Verifier) IsLogout(ID []byte) bool {
	id := hex.EncodeToString(ID)
	_, ok := v.Nodes[id]
	return !ok
}

func (v *Verifier) LogoutProverNode(ID []byte) ([]byte, int64, int64) {
	id := hex.EncodeToString(ID)
	node, ok := v.Nodes[id]
	if !ok {
		return nil, 0, 0
	}
	acc := node.Acc
	front := node.Front
	rear := node.Rear
	delete(v.Nodes, id)
	return acc, front, rear
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

		if commits[i].FileIndex <= pNode.Front {
			return false
		}

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

func (v *Verifier) SpaceChallenges(param int64) ([]int64, error) {
	//Randomly select several nodes from idle files as random challenges
	challenges := make([]int64, param)
	mp := make(map[int64]struct{})
	for i := int64(0); i < param; i++ {
		for {
			r, err := rand.Int(rand.Reader, new(big.Int).SetInt64(v.Expanders.N))
			if err != nil {
				return nil, errors.Wrap(err, "generate commit challenges error")
			}
			if _, ok := mp[r.Int64()]; ok {
				continue
			}
			mp[r.Int64()] = struct{}{}
			r.Add(r, new(big.Int).SetInt64(v.Expanders.N*v.Expanders.K))
			challenges[i] = r.Int64()
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
		if chals[i][0] != proof.Indexs[i] || chals[i][0] != pNode.Rear+int64(i)+1 {
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
	if !acc.VerifyInsertUpdate(pNode.Key, proof.WitChains,
		proof.Labels, proof.AccPath, pNode.Acc) {
		err := errors.New("verify muti-level acc error")
		return errors.Wrap(err, "verify acc proofs error")
	}
	pNode.Acc = proof.AccPath[len(proof.AccPath)-1]
	pNode.CommitsBuf = append(pNode.CommitsBuf[:index],
		pNode.CommitsBuf[index+len(chals):]...)
	pNode.BufSize -= len(chals)
	pNode.Rear += int64(len(chals))
	return nil
}

func (v *Verifier) VerifySpace(pNode *ProverNode, chals []int64, proof *SpaceProof) error {
	if len(chals) <= 0 || pNode.record+1 != proof.Left || pNode.Rear+1 < proof.Right {
		err := errors.New("bad proof data")
		return errors.Wrap(err, "verify space proofs error")
	}
	label := make([]byte, len(pNode.ID)+8+expanders.HashSize)
	for i := 0; i < len(proof.Roots); i++ {
		for j := 0; j < len(chals); j++ {
			if chals[j] != int64(proof.Proofs[i][j].Index) {
				err := errors.New("bad file index")
				return errors.Wrap(err, "verify space proofs error")
			}
			pathProof := tree.PathProof{
				Locs: proof.Proofs[i][j].Locs,
				Path: proof.Proofs[i][j].Paths,
			}
			//check index
			if !tree.CheckIndexPath(chals[j], pathProof.Locs) {
				err := errors.New("verify index path error")
				return errors.Wrap(err, "verify space proofs error")
			}
			//check path proof
			if !tree.VerifyPathProof(proof.Roots[i], proof.Proofs[i][j].Label, pathProof) {
				err := errors.New("verify path proof error")
				return errors.Wrap(err, "verify space proofs error")
			}
		}
		util.CopyData(label, pNode.ID, expanders.GetBytes(proof.Left+int64(i)), proof.Roots[i])
		if !bytes.Equal(expanders.GetHash(label), proof.WitChains[i].Elem) {
			err := errors.New("verify file label error")
			return errors.Wrap(err, "verify space proofs error")
		}
		if !acc.VerifyMutilevelAcc(pNode.Key, proof.WitChains[i], pNode.Acc) {
			err := errors.New("verify acc proof error")
			return errors.Wrap(err, "verify space proofs error")
		}
	}
	return nil
}

func (v Verifier) SpaceVerificationHandle(ID []byte, key acc.RsaKey, acc []byte, front, rear int64) func(chals []int64, proof *SpaceProof) (bool, error) {
	pNode := NewProverNode(ID, key, acc, front, rear)
	return func(chals []int64, proof *SpaceProof) (bool, error) {
		err := v.VerifySpace(pNode, chals, proof)
		if err != nil {
			return false, err
		}
		pNode.record = proof.Right - 1
		if pNode.record == pNode.Rear {
			return true, nil
		}
		return false, nil
	}
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
	if int64(lens) > pNode.Rear-pNode.Front {
		err := errors.New("file number out of range")
		return errors.Wrap(err, "verify deletion proofs error")
	}
	labels := make([][]byte, lens)
	for i := 0; i < lens; i++ {
		label := make([]byte, len(ID)+8+expanders.HashSize)
		util.CopyData(label, ID,
			expanders.GetBytes(pNode.Front+int64(i)+1), proof.Roots[i])
		labels[i] = expanders.GetHash(label)
	}
	if !acc.VerifyDeleteUpdate(pNode.Key, proof.WitChain,
		labels, proof.AccPath, pNode.Acc) {
		err := errors.New("verify acc proof error")
		return errors.Wrap(err, "verify deletion proofs error")
	}
	pNode.Front += int64(lens)
	return nil
}
