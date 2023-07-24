package expanders

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"log"
	"os"
	"path"
	"unsafe"

	"github.com/CESSProject/cess_pois/tree"
	"github.com/CESSProject/cess_pois/util"

	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
)

const (
	DEFAULT_IDLE_FILES_PATH = "./Proofs"
	LAYER_NAME              = "layer"
	COMMIT_FILE             = "roots"
	IDLE_DIR_NAME           = "idlefile"
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

func (expanders *Expanders) GenerateIdleFile(minerID []byte, Count int64, rootDir string) error {
	//generate tmp dir name
	dir := path.Join(rootDir, fmt.Sprintf("%s-%d", IDLE_DIR_NAME, Count))
	if err := MakeProofDir(dir); err != nil {
		errors.Wrap(err, "generate idle file error")
	}

	ch := expanders.RunRelationalMapServer(minerID, Count)
	hash := NewHash()

	//create aux slices
	roots := make([][]byte, expanders.K+2)
	parents := expanders.FilePool.Get().(*[]byte)
	labels := expanders.FilePool.Get().(*[]byte)

	labelLeftSize := len(minerID) + int(unsafe.Sizeof(NodeType(0))) + 8
	label := make([]byte, labelLeftSize+int(expanders.D+1)*HashSize)
	//calculate labels layer by layer
	for i := int64(0); i <= expanders.K; i++ {
		for j := int64(0); j < expanders.N; j++ {
			node := <-ch
			util.CopyData(label, minerID,
				GetBytes(Count), GetBytes(node.Index))
			bytesCount := labelLeftSize
			if i > 0 && !node.NoParents() {
				for _, p := range node.Parents {
					idx := int64(p) % expanders.N
					l, r := idx*int64(HashSize), (idx+1)*int64(HashSize)
					if int64(p) < i*expanders.N {
						copy(label[bytesCount:bytesCount+HashSize], (*parents)[l:r])
					} else {
						copy(label[bytesCount:bytesCount+HashSize], (*labels)[l:r])
					}
					bytesCount += HashSize
				}
			}
			hash.Reset()
			hash.Write(label)
			copy((*labels)[j*int64(HashSize):(j+1)*int64(HashSize)], hash.Sum(nil))
			expanders.NodePool.Put(node)
		}
		//calculate merkel tree root hash for each layer
		ltree := tree.CalcLightMhtWithBytes((*labels), HashSize, true)
		roots[i] = ltree.GetRoot(HashSize)
		tree.RecoveryMht(ltree)

		//save one layer labels
		if err := util.SaveFile(path.Join(dir, fmt.Sprintf("%s-%d", LAYER_NAME, i)), (*labels)); err != nil {
			return errors.Wrap(err, "generate idle file error")
		}
		parents, labels = labels, parents
	}

	expanders.FilePool.Put(parents)
	expanders.FilePool.Put(labels)
	//calculate new dir name
	hash.Reset()
	for i := 0; i < len(roots); i++ {
		hash.Write(roots[i])
	}
	roots[expanders.K+1] = hash.Sum(nil)

	if err := util.SaveProofFile(path.Join(dir, COMMIT_FILE), roots); err != nil {
		return errors.Wrap(err, "generate idle file error")
	}

	return nil
}

func IdleFileGenerationServer(expanders *Expanders, minerID []byte, rootDir string, tNum int) (chan<- int64, <-chan bool) {
	in, out := make(chan int64, tNum), make(chan bool, tNum)
	for i := 0; i < tNum; i++ {
		ants.Submit(func() {
			for count := range in {
				if count <= 0 {
					close(out)
					return
				}
				err := expanders.GenerateIdleFile(minerID, count, rootDir)
				if err != nil {
					log.Println(err)
				}
				out <- true
			}
		})
	}
	return in, out
}
