package expanders

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"
	"path"
	"unsafe"

	"github.com/CESSProject/cess_pois/tree"
	"github.com/CESSProject/cess_pois/util"

	"github.com/pkg/errors"
)

const (
	DEFAULT_IDLE_FILES_PATH = "./proofs"
	FILE_NAME               = "sub-file"
	COMMIT_FILE             = "file-roots"
	CLUSTER_DIR_NAME        = "file-cluster"
	SET_DIR_NAME            = "idle-files"
)

var (
	HashSize = 64
)

func MakeProofDir(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		return os.MkdirAll(dir, 0777)
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return os.MkdirAll(dir, 0777)
}

func NewHash() hash.Hash {
	switch HashSize {
	case 32:
		return sha256.New()
	case 64:
		return sha512.New()
	default:
		return sha512.New()
	}
}

func GetHash(data []byte) []byte {
	h := NewHash()
	if data == nil {
		data = []byte("none")
	}
	h.Write(data)
	return h.Sum(nil)
}

func (expanders *Expanders) GenerateIdleFileSet(minerID []byte, start, size int64, rootDir string) error {
	//make dir
	clusters := make([]int64, size)
	setDir := path.Join(rootDir, fmt.Sprintf("%s-%d", SET_DIR_NAME, (start+size)/size))
	for i := start; i < start+size; i++ {
		dir := path.Join(setDir, fmt.Sprintf("%s-%d", CLUSTER_DIR_NAME, i))
		if err := MakeProofDir(dir); err != nil {
			errors.Wrap(err, "generate idle file error")
		}
		clusters[i-start] = i
	}
	//number of idle files in each file cluster
	fileNum := expanders.K
	//create aux slices
	roots := make([][]byte, (expanders.K+fileNum)*size+1)
	elder := make([]*[]byte, expanders.K/2)

	//calc node labels
	hash := NewHash()
	frontSize := len(minerID) + int(unsafe.Sizeof(NodeType(0))) + 8 + 8
	label := make([]byte, frontSize+int(expanders.K/2)*HashSize+int(expanders.D+1)*HashSize)
	zero := make([]byte, int(expanders.K/2)*HashSize+int(expanders.D+1)*HashSize)
	util.CopyData(label, minerID)

	for i := int64(0); i < expanders.K+fileNum; i++ {
		parents := expanders.FilePool.Get().(*[]byte)
		labels := expanders.FilePool.Get().(*[]byte)
		logicalLayer := i
		//calc nodes relationship
		readBuf := expanders.NodesPool.Get().(*[]Node)
		calcNodesParents(expanders, i, size, readBuf, minerID, clusters...)

		for j := int64(0); j < size; j++ {
			util.CopyData(label[len(minerID):], GetBytes(clusters[j]), GetBytes(int64(0)))
			//read parents' label of file j, and fill elder node labels to add files relationship
			if i >= expanders.K {
				logicalLayer = expanders.K
				//When the last level is reached, join the file index
				util.CopyData(label[len(minerID)+8:], GetBytes((clusters[j]-1)*fileNum+i-expanders.K+1))
				readEldersData(expanders, setDir, i, j, elder, clusters)
			}
			if i > 0 {
				if err := util.ReadFileToBuf(path.Join(setDir,
					fmt.Sprintf("%s-%d", CLUSTER_DIR_NAME, clusters[j]),
					fmt.Sprintf("%s-%d", FILE_NAME, logicalLayer-1)), *parents); err != nil {
					return errors.Wrap(err, "generate idle file error")
				}
			}
			for k := int64(0); k < expanders.N; k++ {
				node := &(*readBuf)[k]
				util.CopyData(label[len(minerID)+8+8:], GetBytes(node.Index)) //label=[minerID||clusterID||fileID||nodeID||parent labels||file dependencies]
				copy(label[frontSize:], zero)

				if i > 0 && !node.NoParents() {
					bcount := frontSize
					for _, p := range node.Parents {
						idx := int64(p) % expanders.N
						l, r := idx*int64(HashSize), (idx+1)*int64(HashSize)
						if int64(p) < logicalLayer*expanders.N {
							copy(label[bcount:bcount+HashSize], (*parents)[l:r])
						} else {
							copy(label[bcount:bcount+HashSize], (*labels)[l:r])
						}
						bcount += HashSize
					}
					// //add files relationship
					for l := 0; i >= expanders.K && l < int(expanders.K/2); l++ {
						copy(label[bcount:bcount+HashSize], (*elder[l])[k*int64(HashSize):(k+1)*int64(HashSize)])
						bcount += HashSize
					}
				}
				hash.Reset()
				hash.Write(label)
				if i+j > 0 { //add same layer dependency relationship
					hash.Write((*labels)[k*int64(HashSize) : (k+1)*int64(HashSize)])
				}
				copy((*labels)[k*int64(HashSize):(k+1)*int64(HashSize)], hash.Sum(nil))
			}

			//calc merkel tree root hash
			mht := tree.GetLightMhtFromPool()
			mht.CalcLightMhtWithBytes((*labels), HashSize)
			roots[i*size+j] = mht.GetRoot()
			tree.PutLightMhtToPool(mht)

			//save one layer labels of one file
			if err := util.SaveFile(path.Join(
				setDir, fmt.Sprintf("%s-%d", CLUSTER_DIR_NAME, clusters[j]),
				fmt.Sprintf("%s-%d", FILE_NAME, i)), *labels); err != nil {
				return errors.Wrap(err, "generate idle file error")
			}
		}
		expanders.FilePool.Put(parents)
		expanders.FilePool.Put(labels)
		expanders.NodesPool.Put(readBuf)
	}

	//return memory space
	for i := 0; i < int(expanders.K/2); i++ {
		expanders.FilePool.Put(elder[i])
	}
	//calculate new dir name
	hash = sha256.New()
	for i := 0; i < len(roots)-1; i++ {
		hash.Write(roots[i])
	}
	roots[(expanders.K+fileNum)*size] = hash.Sum(nil)

	if err := util.SaveProofFile(path.Join(setDir, COMMIT_FILE), roots); err != nil {
		return errors.Wrap(err, "generate idle file error")
	}

	return nil
}

func calcNodesParents(expanders *Expanders, layer, size int64, nodes *[]Node, minerID []byte, Count ...int64) {
	logicalLayer := layer
	if logicalLayer >= expanders.K {
		logicalLayer = expanders.K
		Count = append(Count[:size], layer-logicalLayer+1)
	}
	for j := int64(0); j < expanders.N; j++ {
		(*nodes)[j].Index = NodeType(j + logicalLayer*expanders.N)
		(*nodes)[j].Parents = (*nodes)[j].Parents[:0]
		CalcParents(expanders, &(*nodes)[j], minerID, Count...)
	}
}

func readEldersData(expanders *Expanders, setDir string, layer, cidx int64, elder []*[]byte, clusters []int64) error {
	baseLayer := int((layer - expanders.K/2) / expanders.K)
	for l := 0; l < int(expanders.K/2); l++ {
		if elder[l] == nil {
			elder[l] = expanders.FilePool.Get().(*[]byte)
		}
		if err := util.ReadFileToBuf(path.Join(setDir,
			fmt.Sprintf("%s-%d", CLUSTER_DIR_NAME, clusters[cidx]),
			fmt.Sprintf("%s-%d", FILE_NAME, baseLayer+2*l)), *(elder[l])); err != nil {
			return errors.Wrap(err, "read elders' data error")
		}
	}
	return nil
}
