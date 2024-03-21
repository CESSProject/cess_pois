package pois

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"unsafe"

	"github.com/CESSProject/cess_pois/acc"
	"github.com/CESSProject/cess_pois/expanders"
	"github.com/CESSProject/cess_pois/tree"
	"github.com/CESSProject/cess_pois/util"

	"github.com/pkg/errors"
)

var (
	IdleSetLen  int64 = 32
	ClusterSize int64 = 8
	verifier    *Verifier
	SpaceChals  int64 = 8
	Pick              = 4
)

type Record struct {
	Key   acc.RsaKey
	Acc   []byte
	Front int64
	Rear  int64
}

// ProverNode denote Prover
type ProverNode struct {
	ID         []byte // Prover ID(generally, use AccountID)
	CommitsBuf Commits
	Record
}

type Verifier struct {
	Expanders expanders.Expanders
}

type Nodes map[string]ProverNode

func NewVerifier(k, n, d int64) *Verifier {
	verifier = &Verifier{
		Expanders: *expanders.NewExpanders(k, n, d),
	}
	SpaceChals = k
	ClusterSize = k
	tree.InitMhtPool(int(n))
	return verifier
}

func CreateNewNodes() Nodes {
	nodes := make(Nodes)
	return nodes
}

func GetVerifier() *Verifier {
	return verifier
}

func (n Nodes) RegisterProverNode(ID []byte, key acc.RsaKey, acc []byte, front, rear int64) {
	id := hex.EncodeToString(ID)
	node := NewProverNode(ID, key, acc, front, rear)
	n[id] = node
}

func NewProverNode(ID []byte, key acc.RsaKey, acc []byte, front, rear int64) ProverNode {
	return ProverNode{
		ID: ID,
		Record: Record{
			Acc:   acc,
			Front: front,
			Rear:  rear,
			Key:   key,
		},
	}
}

func (n Nodes) GetNode(ID []byte) ProverNode {
	id := hex.EncodeToString(ID)
	return n[id]
}

func (n Nodes) UpdateNode(node ProverNode) {
	id := hex.EncodeToString(node.ID)
	n[id] = node
}

func (n Nodes) IsLogout(ID []byte) bool {
	id := hex.EncodeToString(ID)
	_, ok := n[id]
	return !ok
}

func (n Nodes) LogoutProverNode(ID []byte) ([]byte, int64, int64) {
	id := hex.EncodeToString(ID)
	node, ok := n[id]
	if !ok {
		return nil, 0, 0
	}
	acc := node.Acc
	front := node.Front
	rear := node.Rear
	delete(n, id)
	return acc, front, rear
}

func (n Nodes) LogoutProverNodeGently(ID []byte) ([]byte, int64, int64) {
	id := hex.EncodeToString(ID)
	node, ok := n[id]
	if !ok {
		return nil, 0, 0
	}
	acc := node.Acc
	front := node.Front
	rear := node.Rear
	//clear state
	node = ProverNode{
		Record: Record{
			Front: front,
			Rear:  rear,
		},
	}
	n[id] = node
	return acc, front, rear
}

func (v *Verifier) ReceiveCommits(pNode *ProverNode, commits Commits) bool {

	rootNum := int((ClusterSize+v.Expanders.K)*IdleSetLen + 1)
	if len(commits.Roots) != rootNum {
		return false
	}
	//
	hash := sha256.New()
	for j := 0; j < len(commits.Roots)-1; j++ {
		hash.Write(commits.Roots[j])
	}
	if !bytes.Equal(commits.Roots[len(commits.Roots)-1], hash.Sum(nil)) {
		return false
	}
	pNode.CommitsBuf = commits
	return true
}

func (v *Verifier) VerifyCommitProofs(pNode ProverNode, chals [][]int64, proofs [][]CommitProof) error {

	if len(chals) != len(proofs) || len(chals) != int(IdleSetLen) ||
		len(pNode.CommitsBuf.FileIndexs) != int(ClusterSize*IdleSetLen) ||
		len(pNode.CommitsBuf.Roots) != int((v.Expanders.K+ClusterSize)*IdleSetLen+1) {
		err := errors.New("bad proof data")
		return errors.Wrap(err, "verify commit proofs error")
	}

	if err := v.VerifyNodeDependencies(pNode.ID, chals, proofs, Pick); err != nil {
		return errors.Wrap(err, "verify commit proofs error")
	}

	frontSize := int(unsafe.Sizeof(expanders.NodeType(0))) + len(pNode.ID) + 8 + 8
	hashSize := expanders.HashSize
	label := make([]byte, frontSize+2*hashSize)
	zero := make([]byte, 2*hashSize)

	var (
		idx  expanders.NodeType
		fidx int64
		hash []byte
	)

	for i := 0; i < len(proofs); i++ {

		for j := 1; j <= int(ClusterSize)+1; j++ {
			if chals[i][j] != int64(proofs[i][j-1].Node.Index) {
				err := errors.New("bad expanders node index")
				return errors.Wrap(err, "verify commit proofs error")
			}
		}

		for j := int64(1); j < int64(len(chals[i])); j++ {
			if j <= ClusterSize+1 {
				idx = expanders.NodeType(chals[i][j])
			} else {
				idx = expanders.NodeType(proofs[i][j-2].Parents[chals[i][j]].Index)
			}

			layer := int64(0)
			if j <= ClusterSize {
				layer = v.Expanders.K + j - 1
			} else {
				layer = int64(idx) / v.Expanders.N
			}

			root := pNode.CommitsBuf.Roots[layer*IdleSetLen+(chals[i][0]-1)%IdleSetLen]
			pathProof := tree.PathProof{
				Locs: proofs[i][j-1].Node.Locs,
				Path: proofs[i][j-1].Node.Paths,
			}
			if !tree.VerifyPathProof(root, proofs[i][j-1].Node.Label, pathProof) {
				err := errors.New("verify path proof error")
				return errors.Wrap(err, "verify commit proofs error")
			}
			//verify node label
			if fidx = 0; layer >= v.Expanders.K {
				fidx = (chals[i][0]-1)*ClusterSize + int64(j)
			}
			util.CopyData(label, pNode.ID, expanders.GetBytes(chals[i][0]), expanders.GetBytes(fidx),
				expanders.GetBytes(idx), zero)

			if layer > 0 {
				logicalLayer := layer
				if logicalLayer > v.Expanders.K {
					logicalLayer = v.Expanders.K
				}
				for _, p := range proofs[i][j-1].Parents {
					if int64(p.Index) >= logicalLayer*v.Expanders.N {
						root = pNode.CommitsBuf.Roots[layer*IdleSetLen+(chals[i][0]-1)%IdleSetLen]
					} else {
						root = pNode.CommitsBuf.Roots[(logicalLayer-1)*IdleSetLen+(chals[i][0]-1)%IdleSetLen]
					}
					if p.Index%6 == 0 {
						pathProof := tree.PathProof{
							Locs: p.Locs,
							Path: p.Paths,
						}
						if !tree.VerifyPathProof(root, p.Label, pathProof) {
							err := errors.New("verify parent path proof error")
							return errors.Wrap(err, "verify commit proofs error")
						}
					}
					util.AddData(label[frontSize:frontSize+hashSize], p.Label)
				}
				// add file dependencies
				//util.CopyData(label[size:], pNode.CommitsBuf.Roots[(layer-1)*IdleSetLen:layer*IdleSetLen]...)
				for l := 1; layer >= v.Expanders.K && l < len(proofs[i][j-1].Elders); l++ {
					pathProof := tree.PathProof{
						Locs: proofs[i][j-1].Elders[l].Locs,
						Path: proofs[i][j-1].Elders[l].Paths,
					}
					ridx := ((layer-v.Expanders.K/2)/v.Expanders.K+2*int64(l-1))*IdleSetLen + (chals[i][0]-1)%IdleSetLen
					if !tree.VerifyPathProof(pNode.CommitsBuf.Roots[ridx], proofs[i][j-1].Elders[l].Label, pathProof) {
						err := errors.New("verify elder node path proof error")
						return errors.Wrap(err, "verify commit proofs error")
					}
					util.AddData(label[frontSize+hashSize:frontSize+2*hashSize], proofs[i][j-1].Elders[l].Label)
				}
			}

			if (chals[i][0]-1)%IdleSetLen+layer > 0 {
				pathProof := tree.PathProof{
					Locs: proofs[i][j-1].Elders[0].Locs,
					Path: proofs[i][j-1].Elders[0].Paths,
				}
				ridx := layer*IdleSetLen + (chals[i][0]-1)%IdleSetLen - 1
				if !tree.VerifyPathProof(pNode.CommitsBuf.Roots[ridx], proofs[i][j-1].Elders[0].Label, pathProof) {
					err := errors.New("verify neighbor node path proof error")
					return errors.Wrap(err, "verify commit proofs error")
				}
				hash = expanders.GetHash(append(label, proofs[i][j-1].Elders[0].Label...))
			} else {
				hash = expanders.GetHash(label)
			}
			if !bytes.Equal(hash, proofs[i][j-1].Node.Label) {
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
		index := r2.Int64()
		proof := proofs[r1.Int64()][index]
		node := expanders.NewNode(proof.Node.Index)
		node.Parents = make([]expanders.NodeType, 0, v.Expanders.D+1)
		layer := int64(proof.Node.Index) / v.Expanders.N
		//
		if index < ClusterSize {
			expanders.CalcNodeParents(&v.Expanders, node, ID, chals[r1.Int64()][0], v.Expanders.K+index)
		} else {
			expanders.CalcNodeParents(&v.Expanders, node, ID, chals[r1.Int64()][0], layer)
		}
		for j := 0; j < len(node.Parents); j++ {
			if node.Parents[j] != proof.Parents[j].Index {
				err = errors.New("node relationship mismatch")
				return errors.Wrap(err, "verify node dependencies error")
			}
		}
	}
	return nil
}

func (v *Verifier) VerifyAcc(pNode *ProverNode, chals [][]int64, proof *AccProof) error {

	if len(chals) != len(proof.Indexs)/int(ClusterSize) || len(chals) != int(IdleSetLen) {
		err := errors.New("bad proof data")
		return errors.Wrap(err, "verify acc proofs error")
	}
	label := make([]byte, len(pNode.ID)+8+tree.DEFAULT_HASH_SIZE)
	for i := int64(0); i < int64(len(chals)); i++ {
		for j := int64(0); j < ClusterSize; j++ {
			if proof.Indexs[i*ClusterSize+j] != (chals[i][0]-1)*ClusterSize+j+1 ||
				pNode.Rear+i*ClusterSize+j+1 != (chals[i][0]-1)*ClusterSize+j+1 {
				err := errors.New("bad file index")
				return errors.Wrap(err, "verify acc proofs error")
			}
			util.CopyData(label, pNode.ID, expanders.GetBytes((chals[i][0]-1)*ClusterSize+j+1),
				pNode.CommitsBuf.Roots[(v.Expanders.K+j)*IdleSetLen+i])
			if !bytes.Equal(expanders.GetHash(label), proof.Labels[i*ClusterSize+j]) {
				err := errors.New("verify file label error")
				return errors.Wrap(err, "verify acc proofs error")
			}
		}
	}
	if !acc.VerifyInsertUpdate(pNode.Key, proof.WitChains,
		proof.Labels, proof.AccPath, pNode.Acc) {
		err := errors.New("verify muti-level acc error")
		return errors.Wrap(err, "verify acc proofs error")
	}
	pNode.Acc = proof.AccPath[len(proof.AccPath)-1]
	pNode.CommitsBuf = Commits{}
	pNode.Rear += int64(len(chals)) * ClusterSize
	return nil
}

func (v *Verifier) VerifySpace(pNode ProverNode, chals []int64, proof *SpaceProof) error {
	if len(chals) <= 0 || proof.Left <= pNode.Front || pNode.Rear+1 < proof.Right { //
		err := errors.New("bad proof data")
		return errors.Wrap(err, "verify space proofs error")
	}
	label := make([]byte, len(pNode.ID)+8+tree.DEFAULT_HASH_SIZE)
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
	}
	if !acc.VerifyMutilevelAccForBatch(pNode.Key, proof.Left, proof.WitChains, pNode.Acc) {
		err := errors.New("verify acc proof error")
		return errors.Wrap(err, "verify space proofs error")
	}
	return nil
}

func (v *Verifier) VerifyDeletion(pNode *ProverNode, proof *DeletionProof) error {

	lens := len(proof.Roots)
	if int64(lens) > pNode.Rear-pNode.Front {
		err := errors.New("file number out of range")
		return errors.Wrap(err, "verify deletion proofs error")
	}
	labels := make([][]byte, lens)
	for i := 0; i < lens; i++ {
		label := make([]byte, len(pNode.ID)+8+tree.DEFAULT_HASH_SIZE)
		util.CopyData(label, pNode.ID,
			expanders.GetBytes(pNode.Front+int64(i)+1), proof.Roots[i])
		labels[i] = expanders.GetHash(label)
	}
	if !acc.VerifyDeleteUpdate(pNode.Key, proof.WitChain,
		labels, proof.AccPath, pNode.Acc) {
		err := errors.New("verify acc proof error")
		return errors.Wrap(err, "verify deletion proofs error")
	}
	pNode.Front += int64(lens)
	pNode.Acc = proof.AccPath[len(proof.AccPath)-1]
	return nil
}
