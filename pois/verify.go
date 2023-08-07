package pois

import (
	"bytes"
	"crypto/rand"
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
	IdleSetLen  int64     = 32 // indicates the number of clusters owned by an idle file collection
	ClusterSize int64     = 8  // indicates how many idle files a cluster has
	verifier    *Verifier      // a globally unique validator object
	SpaceChals  int64     = 8  // during the space challenge, SpaceChals is the number of labels randomly selected for each idle file
	Pick                  = 4  // indicates the number of nodes randomly selected when verifying expanders node dependencies
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
	*Record
}

type Verifier struct {
	Expanders expanders.Expanders
	Nodes     map[string]*ProverNode
}

// NewVerifier create a verifier object, it only needs to be created once in the lifetime of the program
func NewVerifier(k, n, d int64) *Verifier {
	verifier = &Verifier{
		Expanders: *expanders.NewExpanders(k, n, d, expanders.DEFAULT_HASH_SIZE),
		Nodes:     make(map[string]*ProverNode),
	}
	SpaceChals = k
	ClusterSize = k
	tree.InitMhtPool(int(n), int(verifier.Expanders.HashSize))
	return verifier
}

func GetVerifier() *Verifier {
	return verifier
}

// RegisterProverNode registers a storage node prover data for state maintenance during commit proof verification and deletion proof verification
func (v *Verifier) RegisterProverNode(ID []byte, key acc.RsaKey, acc []byte, front, rear int64) {
	id := hex.EncodeToString(ID)
	node := NewProverNode(ID, key, acc, front, rear)
	v.Nodes[id] = node
}

// NewProverNode is used to create a new prover data object for state maintenance, incoming information should come from the blockchain
func NewProverNode(ID []byte, key acc.RsaKey, acc []byte, front, rear int64) *ProverNode {
	return &ProverNode{
		ID: ID,
		Record: &Record{
			Acc:   acc,
			Front: front,
			Rear:  rear,
			Key:   key,
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

// LogoutProverNode delete the prover object with the specified ID, and return its latest state information
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

// ReceiveCommits receives commits data from the specified prover for subsequent proof verification.
func (v *Verifier) ReceiveCommits(ID []byte, commits Commits) bool {
	id := hex.EncodeToString(ID)
	pNode, ok := v.Nodes[id]
	if !ok {
		return false
	} else if !bytes.Equal(pNode.ID, ID) {
		return false
	}
	hash := v.Expanders.NewHash()
	for i := 0; i < len(commits.FileIndexs); i++ {
		if commits.FileIndexs[i] <= pNode.Rear { //
			return false
		}
	}
	//
	rootNum := int((ClusterSize+v.Expanders.K)*IdleSetLen + 1)
	if len(commits.Roots) != rootNum {
		return false
	}
	//
	hash.Reset()
	for j := 0; j < len(commits.Roots)-1; j++ {
		hash.Write(commits.Roots[j])
	}
	if !bytes.Equal(commits.Roots[len(commits.Roots)-1], hash.Sum(nil)) {
		return false
	}
	pNode.CommitsBuf = commits
	return true
}

// CommitChallenges is used to calculate random challenges for previously received commits from the specified prover.
func (v *Verifier) CommitChallenges(ID []byte) ([][]int64, error) {
	id := hex.EncodeToString(ID)
	pNode, ok := v.Nodes[id]
	if !ok {
		err := errors.New("prover node not found")
		return nil, errors.Wrap(err, "generate commit challenges error")
	}
	challenges := make([][]int64, IdleSetLen)                   // generate random challenges in units of file clusters
	start := (pNode.CommitsBuf.FileIndexs[0] - 1) / ClusterSize // compute the first file cluster index
	for i := int64(0); i < IdleSetLen; i++ {
		challenges[i] = make([]int64, v.Expanders.K+ClusterSize+1) // each file cluster contains a cluster index, clusterSize+expanders.K random node indexes (one for each layer)
		challenges[i][0] = start + i + 1                           // calculate file cluster index
		//
		for j := 1; j <= int(ClusterSize); j++ { // generate a random challenge for each idle file in the file cluster
			r, err := rand.Int(rand.Reader, new(big.Int).SetInt64(v.Expanders.N))
			if err != nil {
				return nil, errors.Wrap(err, "generate commit challenges error")
			}
			r.Add(r, new(big.Int).SetInt64(v.Expanders.N*v.Expanders.K))
			challenges[i][j] = r.Int64()
		}

		// generate random challenges for K-th layer nodes
		r, err := rand.Int(rand.Reader, new(big.Int).SetInt64(v.Expanders.N))
		if err != nil {
			return nil, errors.Wrap(err, "generate commit challenges error")
		}
		r.Add(r, new(big.Int).SetInt64(v.Expanders.N*(v.Expanders.K-1)))
		challenges[i][ClusterSize+1] = r.Int64()

		for j := int(ClusterSize + 2); j < len(challenges[i]); j++ { // generate random challenge relative indices for layers [0,k-1]
			r, err := rand.Int(rand.Reader, new(big.Int).SetInt64(v.Expanders.D+1))
			if err != nil {
				return nil, errors.Wrap(err, "generate commit challenges error")
			}
			challenges[i][j] = r.Int64()
		}
	}
	return challenges, nil
}

func (v *Verifier) SpaceChallenges(param int64) ([]int64, error) {
	//Randomly select several nodes from idle files as random challenges
	if param < SpaceChals {
		param = SpaceChals
	}
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
	if len(chals) != len(proofs) || len(chals) != int(IdleSetLen) {
		err := errors.New("bad proof data")
		return errors.Wrap(err, "verify commit proofs error")
	}

	if err := v.VerifyNodeDependencies(ID, chals, proofs, Pick); err != nil {
		return errors.Wrap(err, "verify commit proofs error")
	}

	frontSize := int(unsafe.Sizeof(expanders.NodeType(0))) + len(ID) + 8 + 8
	hashSize := int(v.Expanders.HashSize)
	label := make([]byte, frontSize+int(v.Expanders.D+1)*hashSize+int(IdleSetLen)*hashSize)
	zero := make([]byte, int(v.Expanders.D+1)*hashSize+int(IdleSetLen)*hashSize)

	var (
		idx  expanders.NodeType
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
			if layer >= v.Expanders.K {
				util.CopyData(label, ID,
					expanders.GetBytes(chals[i][0]),
					expanders.GetBytes((chals[i][0]-1)*ClusterSize+int64(j)),
					expanders.GetBytes(idx),
				)
			} else {
				util.CopyData(label, ID,
					expanders.GetBytes(chals[i][0]),
					expanders.GetBytes(int64(0)),
					expanders.GetBytes(idx),
				)
			}
			if layer > 0 {
				size := frontSize
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
				// add file dependencies
				util.CopyData(label[size:], pNode.CommitsBuf.Roots[(layer-1)*IdleSetLen:layer*IdleSetLen]...)
			} else {
				util.CopyData(label[frontSize:], zero) //clean label rear
			}

			if (chals[i][0]-1)%IdleSetLen > 0 {
				hash = v.Expanders.GetHash(append(label, pNode.CommitsBuf.Roots[layer*IdleSetLen+(chals[i][0]-1)%IdleSetLen-1]...))
			} else {
				hash = v.Expanders.GetHash(label)
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

	clusters := make([]int64, len(chals))
	for i := 0; i < len(chals); i++ {
		clusters[i] = chals[i][0]
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
		//
		if index < ClusterSize {
			expanders.CalcParents(&v.Expanders, node, ID, append(clusters, index+1)...)
		} else {
			expanders.CalcParents(&v.Expanders, node, ID, clusters...)
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

func (v *Verifier) VerifyAcc(ID []byte, chals [][]int64, proof *AccProof) error {
	id := hex.EncodeToString(ID)
	pNode, ok := v.Nodes[id]
	if !ok {
		err := errors.New("prover node not found")
		return errors.Wrap(err, "verify acc proofs error")
	}
	if len(chals) != len(proof.Indexs)/int(ClusterSize) || len(chals) != int(IdleSetLen) {
		err := errors.New("bad proof data")
		return errors.Wrap(err, "verify acc proofs error")
	}
	label := make([]byte, len(ID)+8+int(v.Expanders.HashSize))
	for i := int64(0); i < int64(len(chals)); i++ {
		for j := int64(0); j < ClusterSize; j++ {
			if proof.Indexs[i*ClusterSize+j] != (chals[i][0]-1)*ClusterSize+j+1 ||
				pNode.Rear+i*ClusterSize+j+1 != (chals[i][0]-1)*ClusterSize+j+1 {
				err := errors.New("bad file index")
				return errors.Wrap(err, "verify acc proofs error")
			}
			util.CopyData(label, ID, expanders.GetBytes((chals[i][0]-1)*ClusterSize+j+1),
				pNode.CommitsBuf.Roots[(v.Expanders.K+j)*IdleSetLen+i])
			if !bytes.Equal(v.Expanders.GetHash(label), proof.Labels[i*ClusterSize+j]) {
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

func (v *Verifier) VerifySpace(pNode *ProverNode, chals []int64, proof *SpaceProof) error {
	if len(chals) <= 0 || proof.Left <= pNode.Front || pNode.Rear+1 < proof.Right { //
		err := errors.New("bad proof data")
		return errors.Wrap(err, "verify space proofs error")
	}
	label := make([]byte, len(pNode.ID)+8+int(v.Expanders.HashSize))

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
		if !bytes.Equal(v.Expanders.GetHash(label), proof.WitChains[i].Elem) {
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

func (v *Verifier) VerifyDeletion(ID []byte, proof *DeletionProof) error {
	id := hex.EncodeToString(ID)
	pNode, ok := v.Nodes[id]
	if !ok {
		err := errors.New("prover node not found")
		return errors.Wrap(err, "verify deletion proofs error")
	}
	lens := len(proof.Roots)
	if int64(lens) > pNode.Rear-pNode.Front {
		err := errors.New("file number out of range")
		return errors.Wrap(err, "verify deletion proofs error")
	}
	labels := make([][]byte, lens)
	for i := 0; i < lens; i++ {
		label := make([]byte, len(ID)+8+int(v.Expanders.HashSize))
		util.CopyData(label, ID,
			expanders.GetBytes(pNode.Front+int64(i)+1), proof.Roots[i])
		labels[i] = v.Expanders.GetHash(label)
	}
	if !acc.VerifyDeleteUpdate(pNode.Key, proof.WitChain,
		labels, proof.AccPath, pNode.Acc) {
		err := errors.New("verify acc proof error")
		return errors.Wrap(err, "verify deletion proofs error")
	}
	pNode.Front += int64(lens)
	return nil
}
