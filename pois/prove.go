package pois

import (
	"bytes"
	"cess_pois/acc"
	"cess_pois/expanders"
	"cess_pois/tree"
	"cess_pois/util"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
)

var (
	FileSize       int64  = int64(expanders.HashSize)
	AccPath        string = acc.DEFAULT_PATH
	AccBackupPath  string = fmt.Sprintf("%s.backup", AccPath)
	IdleFilePath   string = expanders.DEFAULT_IDLE_FILES_PATH
	MaxProofThread        = 4 //please set according to the number of cores
)

type Prover struct {
	Expanders   *expanders.Expanders
	rear        int64
	front       int64
	space       int64
	setLen      int64
	clusterSize int64
	context
	rw         sync.RWMutex
	delete     atomic.Bool
	update     atomic.Bool
	generate   atomic.Bool
	ID         []byte
	chainState *ChainState
	AccManager acc.AccHandle
}

type context struct {
	commited  int64
	added     int64
	generated int64
	proofed   int64
}

type ChainState struct {
	Acc         acc.AccHandle
	challenging bool
	Rear        int64
	Front       int64
}

type MhtProof struct {
	Index expanders.NodeType `json:"index"`
	Label []byte             `json:"label"`
	Paths [][]byte           `json:"paths"`
	Locs  []byte             `json:"locs"`
}

type Commits struct {
	FileIndexs []int64  `json:"file_indexs"`
	Roots      [][]byte `json:"roots"`
}

type CommitProof struct {
	Node    *MhtProof   `json:"node"`
	Parents []*MhtProof `json:"parents"`
}

type AccProof struct {
	Indexs    []int64          `json:"indexs"`
	Labels    [][]byte         `json:"labels"`
	WitChains *acc.WitnessNode `json:"wit_chains"`
	AccPath   [][]byte         `json:"acc_path"`
}

type SpaceProof struct {
	Left      int64              `json:"left"`
	Right     int64              `json:"right"`
	Proofs    [][]*MhtProof      `json:"proofs"`
	Roots     [][]byte           `json:"roots"`
	WitChains []*acc.WitnessNode `json:"wit_chains"`
}

type DeletionProof struct {
	Roots    [][]byte         `json:"roots"`
	WitChain *acc.WitnessNode `json:"wit_chain"`
	AccPath  [][]byte         `json:"acc_path"`
}

func NewProver(k, n, d int64, ID []byte, space, setLen int64) (*Prover, error) {
	if k <= 0 || n <= 0 || d <= 0 || space <= 0 || len(ID) == 0 {
		return nil, errors.New("bad params")
	}
	prover := &Prover{
		ID: ID,
	}
	FileSize = int64(expanders.HashSize) * n / (1024 * 1024)
	prover.Expanders = expanders.ConstructStackedExpanders(k, n, d)
	prover.space = space
	prover.setLen = setLen
	prover.clusterSize = k
	tree.InitMhtPool(int(n), expanders.HashSize)
	return prover, nil
}

func (p *Prover) Init(key acc.RsaKey) error {
	if key.G.BitLen() == 0 || key.N.BitLen() == 0 {
		return errors.New("bad init params")
	}
	var err error
	p.AccManager, err = acc.NewMutiLevelAcc(AccPath, key)
	if err != nil {
		return errors.Wrap(err, "init prover error")
	}
	p.chainState = &ChainState{
		Acc:   p.AccManager.GetSnapshot(),
		Rear:  0,
		Front: 0,
	}
	return nil
}

func (p *Prover) Recovery(key acc.RsaKey, front, rear int64) error {
	if key.G.BitLen() == 0 || key.N.BitLen() == 0 ||
		front < 0 || rear < 0 || front > rear {
		return errors.New("bad recovery params")
	}
	var err error
	//recovery acc
	p.AccManager, err = acc.Recovery(AccPath, key, front, rear)
	if err != nil {
		return errors.Wrap(err, "recovery prover error")
	}
	//recovery front and rear
	p.front = front
	p.rear = rear
	//recovery context

	generated, err := p.calcGeneratedFile(IdleFilePath)
	if err != nil {
		return errors.Wrap(err, "recovery prover error")
	}
	p.generated = rear + generated
	p.added = rear + generated
	p.commited = rear
	p.space -= (p.rear - p.front) * FileSize                //calc proved space
	p.space -= generated * (FileSize * (p.Expanders.K + 1)) //calc generated space
	return nil
}

func (p *Prover) RecoveryChainState(key acc.RsaKey, accSnp []byte, front, rear int64) error {
	p.chainState = &ChainState{
		Rear:  rear,
		Front: front,
	}
	var err error
	p.chainState.Acc, err = acc.Recovery(AccBackupPath, key, front, rear)
	if err != nil {
		return errors.Wrap(err, "recovery chain state error")
	}
	if !bytes.Equal(accSnp, p.chainState.Acc.GetSnapshot().Accs.Value) {
		err = errors.New("the restored acc value is not equal to the snapshot value")
		return errors.Wrap(err, "recovery chain state error")
	}
	return nil
}

// GenerateIdleFileSet generate num idle files, num must be consistent with the data given by CESS, otherwise it cannot pass the verification
func (p *Prover) GenerateIdleFileSet() error {
	fileNum := p.setLen * p.clusterSize
	if p.space < (fileNum+p.setLen*p.Expanders.K)*FileSize {
		return errors.New("generate idle file set error: bad element number")
	}
	if !p.generate.CompareAndSwap(false, true) {
		return errors.New("generate idle file set error: lock is occupied")
	}
	p.added += fileNum
	p.space -= (fileNum + p.setLen*p.Expanders.K) * FileSize
	p.generate.Store(false)
	start := (p.added-fileNum)/p.clusterSize + 1
	if err := p.Expanders.GenerateIdleFileSet(
		p.ID, start, p.setLen, IdleFilePath); err != nil {
		// clean files
		p.space += (fileNum + p.setLen*p.Expanders.K) * FileSize
		return errors.Wrap(err, "generate idle file set error")
	}
	p.generated += fileNum
	return nil
}

// CommitRollback need to be invoked when submit commits to verifier failure
func (p *Prover) CommitRollback() bool {
	if !p.update.CompareAndSwap(true, false) {
		p.commited -= p.setLen * p.clusterSize
		return true
	}
	return false
}

// AccRollback need to be invoked when submit or verify acc proof failure,
// the update of the accumulator is serial and blocking, you need to update or roll back in time.
func (p *Prover) AccRollback(isDel bool) bool {
	if isDel {
		if !p.delete.CompareAndSwap(true, false) {
			return false
		}
	} else if !p.update.CompareAndSwap(true, false) {
		return false
	}
	return p.AccManager.RollBack()
}

// UpdateStatus need to be invoked after verify commit proof and acc proof success,
// the update of the accumulator is serial and blocking, you need to update or roll back in time.
func (p *Prover) UpdateStatus(num int64, isDelete bool) error {
	var err error
	p.rw.Lock()
	defer p.rw.Unlock()
	if num < 0 {
		err = errors.New("bad files number")
		return errors.Wrap(err, "updat prover status error")
	}

	if isDelete {
		if !p.delete.CompareAndSwap(true, false) {
			err = errors.New("no delete task pending update")
			return errors.Wrap(err, "updat prover status error")
		}
		if p.proofed > 0 && p.proofed < p.front+num {
			err = errors.New("proving space proofs is not complete")
			return errors.Wrap(err, "updat prover status error")
		}

		if err = p.deleteFiles(num, false); err != nil {
			return errors.Wrap(err, "updat prover status error")
		}
		p.front += num
	} else {
		if !p.update.CompareAndSwap(true, false) {
			err = errors.New("no update task pending update")
			return errors.Wrap(err, "updat prover status error")
		}

		if err = p.organizeFiles(num); err != nil {
			return errors.Wrap(err, "updat prover status error")
		}
		p.rear += num
	}
	p.AccManager.UpdateSnapshot()
	return nil
}

func (p *Prover) GetSpace() int64 {
	return p.space
}

func (p *Prover) ReturnSpace(size int64) {
	p.rw.Lock()
	p.space += size
	p.rw.Unlock()
}

// GetCount get Count Safely
func (p *Prover) GetRear() int64 {
	p.rw.RLock()
	defer p.rw.RUnlock()
	return p.rear
}

func (p *Prover) GetFront() int64 {
	p.rw.RLock()
	defer p.rw.RUnlock()
	return p.front
}

// RestProofedCounter must be called when space proof is finished
func (p *Prover) RestProofedCounter() {
	p.rw.Lock()
	defer p.rw.Unlock()
	p.proofed = 0
}

func (p *Prover) RestChallengeState() {
	p.rw.Lock()
	defer p.rw.Unlock()
	p.proofed = 0
	p.chainState.challenging = false
}

func (p *Prover) SetChallengeState(challenging bool) error {
	p.rw.Lock()
	defer p.rw.Unlock()
	if !challenging && !p.chainState.challenging {
		p.chainState.Acc = p.AccManager.GetSnapshot()
		p.chainState.Rear = p.rear
		p.chainState.Front = p.front
		//backup acc file
		if err := util.CopyFiles(AccPath, AccBackupPath); err != nil {
			return err
		}
	}
	p.chainState.challenging = true
	return nil
}

// GetIdleFileSetCommits can not run concurrently! And num must be consistent with the data given by CESS.
func (p *Prover) GetIdleFileSetCommits() (Commits, error) {
	var (
		err     error
		commits Commits
	)
	if !p.update.CompareAndSwap(false, true) {
		err = errors.New("lock is occupied")
		return commits, errors.Wrap(err, "get commits error")
	}
	fileNum := p.generated
	commited := p.commited
	commitNum := p.setLen * p.clusterSize
	if fileNum-commited < commitNum {
		err = errors.New("bad commit data")
		return commits, errors.Wrap(err, "get commits error")
	}
	//read commit file of idle file set
	name := path.Join(
		IdleFilePath,
		fmt.Sprintf("%s-%d", expanders.SET_DIR_NAME, (commited+p.setLen)/p.setLen),
		expanders.COMMIT_FILE,
	)
	rootNum := int(commitNum + p.Expanders.K*p.setLen + 1)
	commits.Roots, err = util.ReadProofFile(name, rootNum, expanders.HashSize)
	if err != nil {
		return commits, errors.Wrap(err, "get commits error")
	}
	commits.FileIndexs = make([]int64, commitNum)
	for i := int64(0); i < commitNum; i++ {
		commits.FileIndexs[i] = commited + i + 1
	}
	p.commited += commitNum
	return commits, nil
}

func (p *Prover) ProveCommitAndAcc(challenges [][]int64) ([][]CommitProof, *AccProof, error) {
	if !p.update.Load() {
		return nil, nil, nil
	}
	commitProofs, err := p.proveCommits(challenges)
	if err != nil {
		return nil, nil, err
	}
	accProof, err := p.proveAcc(challenges)
	if err != nil {
		return nil, nil, err
	}
	return commitProofs, accProof, nil
}

// ProveCommit prove commits no more than MaxCommitProofThread
func (p *Prover) proveCommits(challenges [][]int64) ([][]CommitProof, error) {

	var err error
	lens := len(challenges)
	proofSet := make([][]CommitProof, lens)
	clusters := make([]int64, lens)
	ch := make(chan struct {
		idx   int
		chals []int64
	}, lens)

	for i := 0; i < lens; i++ {
		clusters[i] = challenges[i][0]
		ch <- struct {
			idx   int
			chals []int64
		}{i, challenges[i]}
	}
	close(ch)

	if lens > MaxProofThread {
		lens = MaxProofThread
	}
	wg := sync.WaitGroup{}
	wg.Add(lens)
	for i := 0; i < lens; i++ {
		ants.Submit(func() {
			defer wg.Done()
			for c := range ch {
				if c.chals == nil {
					return
				}
				proofs, e := p.proveCommit(c.chals, clusters)
				if e != nil {
					err = e
					return
				}
				proofSet[c.idx] = proofs
			}
		})
	}
	wg.Wait()
	if err != nil {
		return nil, errors.Wrap(err, "prove commits error")
	}
	return proofSet, errors.Wrap(err, "prove commits error")
}

func (p *Prover) proveAcc(challenges [][]int64) (*AccProof, error) {
	var err error
	if int64(len(challenges)) != p.setLen {
		err = errors.New("bad challenges data")
		return nil, errors.Wrap(err, "update acc error")
	}
	fileNum := p.setLen * p.clusterSize
	labels := make([][]byte, fileNum)
	proof := &AccProof{
		Indexs: make([]int64, fileNum),
	}
	//read commit roots file
	fname := path.Join(
		IdleFilePath,
		fmt.Sprintf("%s-%d", expanders.SET_DIR_NAME, (challenges[0][0]-1)/p.setLen+1),
		expanders.COMMIT_FILE,
	)
	roots, err := util.ReadProofFile(
		fname, int(p.Expanders.K+p.clusterSize)*int(p.setLen)+1, expanders.HashSize)
	if err != nil {
		return nil, errors.Wrap(err, "update acc error")
	}

	for i := int64(0); i < p.setLen; i++ {
		for j := int64(0); j < p.clusterSize; j++ {
			index := (challenges[i][0]-1)*p.clusterSize + j + 1
			proof.Indexs[i*p.clusterSize+j] = index
			root := roots[(p.Expanders.K+j)*p.setLen+i]
			label := append([]byte{}, p.ID...)
			label = append(label, expanders.GetBytes(index)...)
			labels[i*p.clusterSize+j] = expanders.GetHash(append(label, root...))
		}
	}
	proof.WitChains, proof.AccPath, err = p.AccManager.AddElementsAndProof(labels)
	if err != nil {
		return nil, errors.Wrap(err, "update acc error")
	}
	proof.Labels = labels
	return proof, nil
}

func (p *Prover) ReadFileLabels(cluster, fidx int64, buf []byte) error {
	name := path.Join(
		IdleFilePath,
		fmt.Sprintf("%s-%d", expanders.SET_DIR_NAME, (cluster-1)/p.setLen+1),
		fmt.Sprintf("%s-%d", expanders.CLUSTER_DIR_NAME, cluster),
		fmt.Sprintf("%s-%d", expanders.FILE_NAME, fidx+p.Expanders.K),
	)
	if err := util.ReadFileToBuf(name, buf); err != nil {
		return errors.Wrap(err, "read file labels error")
	}
	return nil
}

func (p *Prover) proveCommit(challenge []int64, clusters []int64) ([]CommitProof, error) {

	var err error
	proofs := make([]CommitProof, len(challenge)-1)
	fdir := path.Join(
		IdleFilePath,
		fmt.Sprintf("%s-%d", expanders.SET_DIR_NAME, (challenge[0]-1)/p.setLen+1),
		fmt.Sprintf("%s-%d", expanders.CLUSTER_DIR_NAME, challenge[0]),
	)
	for i := int64(1); i <= int64(len(proofs)); i++ {
		index := challenge[i]
		if i > p.clusterSize+1 {
			index = int64(proofs[i-2].Parents[challenge[i]].Index)
		}
		layer := index / p.Expanders.N
		if i < p.clusterSize+1 {
			layer = p.Expanders.K + i - 1
		}
		proofs[i-1], err = p.generateCommitProof(fdir, clusters, index, layer)
		if err != nil {
			return nil, errors.Wrap(err, "prove one file commit error")
		}
	}
	return proofs, nil
}

func (p *Prover) generateCommitProof(fdir string, counts []int64, c, subfile int64) (CommitProof, error) {

	if subfile < 0 || subfile > p.clusterSize+p.Expanders.K-1 {
		return CommitProof{}, errors.New("generate commit proof error: bad node index")
	}

	fpath := path.Join(fdir, fmt.Sprintf("%s-%d", expanders.FILE_NAME, subfile))
	data := p.Expanders.FilePool.Get().(*[]byte)
	defer p.Expanders.FilePool.Put(data)
	if err := util.ReadFileToBuf(fpath, *data); err != nil {
		return CommitProof{}, errors.Wrap(err, "generate commit proof error")
	}

	var nodeTree, parentTree *tree.LightMHT
	index := c % p.Expanders.N
	nodeTree = tree.CalcLightMhtWithBytes(*data, expanders.HashSize, true)
	defer tree.RecycleMht(nodeTree)
	pathProof, err := nodeTree.GetPathProof(*data, int(index), expanders.HashSize)
	if err != nil {
		return CommitProof{}, errors.Wrap(err, "generate commit proof error")
	}
	label := make([]byte, expanders.HashSize)
	copy(label, (*data)[index*int64(expanders.HashSize):(index+1)*int64(expanders.HashSize)])
	proof := CommitProof{
		Node: &MhtProof{
			Index: expanders.NodeType(c),
			Label: label,
			Paths: pathProof.Path,
			Locs:  pathProof.Locs,
		},
	}

	if subfile == 0 {
		return proof, nil
	}
	//file remapping
	if subfile >= p.Expanders.K {
		counts = append(counts, subfile-p.Expanders.K+1)
		subfile = p.Expanders.K
	}

	node := expanders.NewNode(expanders.NodeType(c))
	node.Parents = make([]expanders.NodeType, 0, p.Expanders.D+1)
	expanders.CalcParents(p.Expanders, node, p.ID, counts...)

	fpath = path.Join(fdir, fmt.Sprintf("%s-%d", expanders.FILE_NAME, subfile-1))
	pdata := p.Expanders.FilePool.Get().(*[]byte)
	defer p.Expanders.FilePool.Put(pdata)
	err = util.ReadFileToBuf(fpath, *pdata)
	if err != nil {
		return proof, errors.Wrap(err, "generate commit proof error")
	}

	parentTree = tree.CalcLightMhtWithBytes(*pdata, expanders.HashSize, true)
	defer tree.RecycleMht(parentTree)
	lens := len(node.Parents)
	parentProofs := make([]*MhtProof, lens)
	wg := sync.WaitGroup{}
	wg.Add(lens)
	for i := 0; i < lens; i++ {
		idx := i
		ants.Submit(func() {
			defer wg.Done()
			index := int64(node.Parents[idx]) % p.Expanders.N
			label := make([]byte, expanders.HashSize)
			var (
				pathProof tree.PathProof
				e         error
			)
			if int64(node.Parents[idx]) >= subfile*p.Expanders.N {
				copy(label, (*data)[index*int64(expanders.HashSize):(index+1)*int64(expanders.HashSize)])
				pathProof, e = nodeTree.GetPathProof(*data, int(index), expanders.HashSize)
			} else {
				copy(label, (*pdata)[index*int64(expanders.HashSize):(index+1)*int64(expanders.HashSize)])
				pathProof, e = parentTree.GetPathProof(*pdata, int(index), expanders.HashSize)
			}
			if e != nil {
				err = e
				return
			}
			parentProofs[idx] = &MhtProof{
				Index: node.Parents[idx],
				Label: label,
				Paths: pathProof.Path,
				Locs:  pathProof.Locs,
			}
		})
	}
	wg.Wait()
	if err != nil {
		return proof, err
	}
	proof.Parents = parentProofs
	return proof, nil
}

func (p *Prover) ProveSpace(challenges []int64, left, right int64) (*SpaceProof, error) {
	var err error
	if len(challenges) <= 0 || right-left <= 0 ||
		left <= p.chainState.Front || right > p.chainState.Rear+1 {
		err := errors.New("bad challenge range")
		return nil, errors.Wrap(err, "prove space error")
	}

	proof := &SpaceProof{
		Proofs:    make([][]*MhtProof, right-left),
		Roots:     make([][]byte, right-left),
		WitChains: make([]*acc.WitnessNode, right-left),
	}
	proof.Left = left
	proof.Right = right
	indexs := make([]int64, right-left)
	threads := MaxProofThread
	if right-left < int64(threads) {
		threads = int(right - left)
	}
	ch := make(chan int64, right-left)
	for i := left; i < right; i++ {
		ch <- i
	}
	close(ch)
	wg := sync.WaitGroup{}
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		ants.Submit(func() {
			defer wg.Done()
			data := p.Expanders.FilePool.Get().(*[]byte)
			defer p.Expanders.FilePool.Put(data)
			for fidx := range ch {
				if fidx == 0 {
					break
				}
				err = p.ReadFileLabels((fidx-1)/p.clusterSize+1, (fidx-1)%p.clusterSize, *data)
				if err != nil {
					return
				}
				mht := tree.CalcLightMhtWithBytes(*data, expanders.HashSize, true)
				indexs[fidx-left] = fidx
				proof.Roots[fidx-left] = mht.GetRoot(expanders.HashSize)
				proof.Proofs[fidx-left] = make([]*MhtProof, len(challenges))
				for j := 0; j < len(challenges); j++ {
					idx := int(challenges[j] % p.Expanders.N)
					pathProof, err := mht.GetPathProof(*data, idx, expanders.HashSize)
					if err != nil {
						if err != nil {
							return
						}
					}
					label := make([]byte, expanders.HashSize)
					copy(label, (*data)[idx*expanders.HashSize:(idx+1)*expanders.HashSize])
					proof.Proofs[fidx-left][j] = &MhtProof{
						Paths: pathProof.Path,
						Locs:  pathProof.Locs,
						Index: expanders.NodeType(challenges[j]),
						Label: label,
					}
				}
				tree.RecycleMht(mht)
			}
		})
	}
	wg.Wait()
	if err != nil {
		return nil, errors.Wrap(err, "prove space error")
	}
	proof.WitChains, err = p.chainState.Acc.GetWitnessChains(indexs)
	if err != nil {
		return nil, errors.Wrap(err, "prove space error")
	}
	p.rw.Lock()
	p.proofed = right - 1
	p.rw.Unlock()
	return proof, nil
}

// ProveDeletion sort out num*IdleFileSize(unit MiB) available space,
// it subtracts all unused and uncommitted space, and deletes enough idle files to make room,
// so the number of idle files actually deleted is the length of DeletionProof.Roots,
// you need to update prover status with this value rather than num after the verification is successful.
func (p *Prover) ProveDeletion(num int64) (chan *DeletionProof, chan error) {
	ch := make(chan *DeletionProof, 1)
	Err := make(chan error, 1)
	if num <= 0 {
		err := errors.New("bad file number")
		Err <- errors.Wrap(err, "prove deletion error")
		return ch, Err
	}
	go func() {
		p.delete.Store(true)
		p.rw.Lock()
		if p.rear-p.front < num {
			p.rw.Unlock()
			ch <- nil
			err := errors.New("insufficient operating space")
			Err <- errors.Wrap(err, "prove deletion error")
			return
		}
		p.rw.Unlock()
		data := p.Expanders.FilePool.Get().(*[]byte)
		defer p.Expanders.FilePool.Put(data)
		roots := make([][]byte, num)
		for i := int64(1); i <= num; i++ {
			cluster, subfile := (p.front+i-1)/p.clusterSize+1, (p.front+i-1)%p.clusterSize
			if err := p.ReadFileLabels(cluster, subfile, *data); err != nil {
				Err <- errors.Wrap(err, "prove deletion error")
				return
			}
			mht := tree.CalcLightMhtWithBytes(*data, expanders.HashSize, true)
			roots[i-1] = mht.GetRoot(expanders.HashSize)
			tree.RecycleMht(mht)
		}
		wits, accs, err := p.AccManager.DeleteElementsAndProof(int(num))
		if err != nil {
			Err <- errors.Wrap(err, "prove deletion error")
			return
		}
		proof := &DeletionProof{
			Roots:    roots,
			WitChain: wits,
			AccPath:  accs,
		}
		ch <- proof
	}()
	return ch, Err
}

func (p *Prover) organizeFiles(num int64) error {
	dir := path.Join(
		IdleFilePath,
		fmt.Sprintf("%s-%d", expanders.SET_DIR_NAME, p.rear/(p.clusterSize*p.setLen)+1),
	)
	for i := p.rear + 1; i <= p.rear+num; i += 8 {
		for j := 0; j < int(p.Expanders.K); j++ {
			name := path.Join(dir,
				fmt.Sprintf("%s-%d", expanders.CLUSTER_DIR_NAME, (i-1)/p.clusterSize+1),
				fmt.Sprintf("%s-%d", expanders.FILE_NAME, j))
			if err := util.DeleteFile(name); err != nil {
				return err
			}
		}
	}
	name := path.Join(dir, expanders.COMMIT_FILE)
	if err := util.DeleteFile(name); err != nil {
		return err
	}
	p.space += num * p.Expanders.K * FileSize
	return nil
}

func (p *Prover) deleteFiles(num int64, raw bool) error {
	for i := int64(1); i <= num; i++ {
		fpath := path.Join(
			IdleFilePath,
			fmt.Sprintf("%s-%d", expanders.SET_DIR_NAME, (p.front+i-1)/(p.setLen*p.clusterSize)+1),
			fmt.Sprintf("%s-%d", expanders.CLUSTER_DIR_NAME, (i-1)/p.clusterSize+1),
			fmt.Sprintf("%s-%d", expanders.FILE_NAME, (i-1)%p.clusterSize+p.Expanders.K),
		)
		if err := util.DeleteFile(fpath); err != nil {
			return errors.Wrap(err, "delete file error")
		}
	}
	if !raw {
		p.space += num * FileSize
	} else {
		p.space += num * FileSize * (p.Expanders.K + 1)
	}
	return nil
}

func (p *Prover) calcGeneratedFile(dir string) (int64, error) {

	count := int64(0)
	fileTotalSize := FileSize * (p.Expanders.K + p.clusterSize) * 1024 * 1024
	rootSize := (p.setLen*(p.Expanders.K+p.clusterSize) + 1) * int64(expanders.HashSize)
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return count, err
	}
	for _, entry := range entries {
		sidxs := strings.Split(entry.Name(), "-")
		if len(sidxs) < 2 {
			continue
		}
		if idx, err := strconv.ParseInt(sidxs[2], 10, 64); err != nil ||
			idx*p.setLen*p.clusterSize <= p.rear {
			continue
		}
		if !entry.IsDir() {
			continue
		}
		rootsFile, err := os.Stat(path.Join(dir, entry.Name(), expanders.COMMIT_FILE))
		if err != nil {
			continue
		}
		if rootsFile.Size() != rootSize {
			continue
		}
		clusters, err := ioutil.ReadDir(path.Join(dir, entry.Name()))
		if err != nil {
			return count, err
		}
		for _, cluster := range clusters {
			if !cluster.IsDir() {
				continue
			}
			size := int64(0)
			files, err := ioutil.ReadDir(path.Join(dir, entry.Name(), cluster.Name()))
			if err != nil {
				return count, err
			}
			for _, file := range files {
				if file.IsDir() {
					continue
				}
				size += file.Size()
			}
			if size == fileTotalSize {
				count++
			}
		}
	}
	return count, nil
}
