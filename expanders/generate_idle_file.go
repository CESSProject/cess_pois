package expanders

import (
	"cess_pois/tree"
	"cess_pois/util"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"
	"path"
	"unsafe"

	"github.com/pkg/errors"
)

const (
	DEFAULT_IDLE_FILES_PATH = "./Proofs"
	LAYER_NAME              = "layer"
	COMMIT_FILE             = "roots"
	IDLE_DIR_NAME           = "idlefile"
	SET_DIR_NAME            = "files"
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
	counts := make([]int64, size)
	setDir := path.Join(rootDir, fmt.Sprintf("%s-%d", SET_DIR_NAME, (start+size)/size))
	for i := start; i < start+size; i++ {
		dir := path.Join(setDir, fmt.Sprintf("%s-%d", IDLE_DIR_NAME, i))
		if err := MakeProofDir(dir); err != nil {
			errors.Wrap(err, "generate idle file error")
		}
		counts[i-start] = i
	}
	//create aux slices
	roots := make([][]byte, (expanders.K+2)*size)
	parents := expanders.FilePool.Get().(*[]byte)
	labels := expanders.FilePool.Get().(*[]byte)
	readBuf := expanders.NodesPool.Get().(*[]Node)
	writeBuf := expanders.NodesPool.Get().(*[]Node)
	rsignal, wsignal := make(chan struct{}, 1), make(chan struct{}, 1)

	//calc nodes relationship
	go func() {
		for i := int64(0); i <= expanders.K; i++ {
			for j := int64(0); j < expanders.N; j++ {
				(*writeBuf)[j].Index = NodeType(j + i*expanders.N)
				(*writeBuf)[j].Parents = (*writeBuf)[j].Parents[:0]
				CalcParents(expanders, &(*writeBuf)[j], minerID, counts...)
			}
			<-rsignal
			readBuf, writeBuf = writeBuf, readBuf
			wsignal <- struct{}{}
		}
	}()

	//calc node labels
	hash := NewHash()
	frontSize := len(minerID) + int(unsafe.Sizeof(NodeType(0))) + 8
	label := make([]byte, frontSize+int(size)*HashSize+int(expanders.D+1)*HashSize)
	util.CopyData(label, minerID)

	for i := int64(0); i <= expanders.K; i++ {
		rsignal <- struct{}{}
		<-wsignal
		for j := int64(0); j < size; j++ {
			util.CopyData(label[len(minerID):], GetBytes(counts[j]))
			//read parents' label of file j
			if i > 0 {
				if err := util.ReadFileToBuf(path.Join(setDir,
					fmt.Sprintf("%s-%d", IDLE_DIR_NAME, counts[j]),
					fmt.Sprintf("%s-%d", LAYER_NAME, i-1)), *parents); err != nil {
					return errors.Wrap(err, "generate idle file error")
				}
			}
			for k := int64(0); k < expanders.N; k++ {
				node := &(*writeBuf)[k]
				util.CopyData(label[len(minerID)+8:], GetBytes(node.Index))
				if i > 0 && !node.NoParents() {
					bcount := frontSize
					for _, p := range node.Parents {
						idx := int64(p) % expanders.N
						l, r := idx*int64(HashSize), (idx+1)*int64(HashSize)
						if int64(p) < i*expanders.N {
							copy(label[bcount:bcount+HashSize], (*parents)[l:r])
						} else {
							copy(label[bcount:bcount+HashSize], (*labels)[l:r])
						}
						bcount += HashSize
					}
					//add files relationship
					util.CopyData(label[bcount:], roots[(i-1)*size:i*size]...)
				}
				hash.Reset()
				if j > 0 { //add same layer dependency relationship
					hash.Write(append(label, roots[i*size+j]...))
				} else {
					hash.Write(label)
				}
				copy((*labels)[k*int64(HashSize):(k+1)*int64(HashSize)], hash.Sum(nil))
			}
			//calc merkel tree root hash
			ltree := tree.CalcLightMhtWithBytes((*labels), HashSize, true)
			roots[i*size+j] = ltree.GetRoot(HashSize)
			tree.RecoveryMht(ltree)
			//save one layer labels of one file
			if err := util.SaveFile(path.Join(
				setDir, fmt.Sprintf("%s-%d", IDLE_DIR_NAME, counts[j]),
				fmt.Sprintf("%s-%d", LAYER_NAME, i)), *labels); err != nil {
				return errors.Wrap(err, "generate idle file error")
			}
		}
	}

	expanders.FilePool.Put(parents)
	expanders.FilePool.Put(labels)
	//calculate new dir name
	hash.Reset()
	for i := 0; i < len(roots); i++ {
		hash.Write(roots[i])
	}
	roots[expanders.K+1] = hash.Sum(nil)

	if err := util.SaveProofFile(path.Join(setDir, COMMIT_FILE), roots); err != nil {
		return errors.Wrap(err, "generate idle file error")
	}

	return nil
}
