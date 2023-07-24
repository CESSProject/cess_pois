package pois

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/CESSProject/cess_pois/acc"
	"github.com/CESSProject/cess_pois/expanders"
	"github.com/CESSProject/cess_pois/tree"
	"github.com/CESSProject/cess_pois/util"

	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
)

var (
	FileSize       int64  = int64(expanders.HashSize)
	IdleFilePath   string = expanders.DEFAULT_IDLE_FILES_PATH
	AccPath        string = acc.DEFAULT_PATH
	AccBackupPath  string = fmt.Sprintf("%s.backup", AccPath)
	MaxProofThread        = 16
)

type Prover struct {
	Expanders *expanders.Expanders
	rear      int64
	front     int64
	space     int64
	context
	rw         sync.RWMutex
	delete     atomic.Bool
	update     atomic.Bool
	generate   atomic.Bool
	ID         []byte
	cmdCh      chan<- int64
	resCh      <-chan bool
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

type Commit struct {
	FileIndex int64    `json:"file_index"`
	Roots     [][]byte `json:"roots"`
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

func NewProver(k, n, d int64, ID []byte, space int64) (*Prover, error) {
	if k <= 0 || n <= 0 || d <= 0 || space <= 0 || len(ID) == 0 {
		return nil, errors.New("bad params")
	}
	prover := &Prover{
		ID: ID,
	}
	FileSize = int64(expanders.HashSize) * n / (1024 * 1024)
	prover.Expanders = expanders.ConstructStackedExpanders(k, n, d)
	prover.space = space
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
	total := FileSize*(p.Expanders.K+1)*1024*1024 +
		int64(expanders.HashSize)*(p.Expanders.K+2)
	generated, err := calcGeneratedFile(IdleFilePath, rear, total)
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

// GenerateFile notifies the idle file generation service to generate the specified number of files,
// if num>MaxCommitProofThread,it may be blocked
func (p *Prover) GenerateFile(num int64) bool {
	if num <= 0 ||
		p.space < num*FileSize*(p.Expanders.K+1) {
		return false
	}

	if !p.generate.CompareAndSwap(false, true) {
		return false
	}
	for i := p.added + 1; i <= p.added+num; i++ {
		p.cmdCh <- i
	}
	p.added += num
	p.space -= num * FileSize * (p.Expanders.K + 1)
	return p.generate.CompareAndSwap(true, false)
}

// CommitRollback need to be invoked when submit commits to verifier failure
func (p *Prover) CommitRollback(num int64) bool {
	if !p.update.CompareAndSwap(true, false) {
		p.commited -= num
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

// RunIdleFileGenerationServer be used to start idle file generation server
func (p *Prover) RunIdleFileGenerationServer(threadNum int) {
	tree.InitMhtPool(int(p.Expanders.N), expanders.HashSize)
	p.cmdCh, p.resCh = expanders.IdleFileGenerationServer(p.Expanders,
		p.ID, IdleFilePath, threadNum)
	go func() {
		for res := range p.resCh {
			if !res {
				return
			}
			p.generated++
		}
	}()
}

// GetCommits can not run concurrently!
func (p *Prover) GetCommits(num int64) ([]Commit, error) {
	var err error
	if !p.update.CompareAndSwap(false, true) {
		return nil, nil
	}
	fileNum := p.generated
	commited := p.commited
	if fileNum-commited <= 0 {
		err = errors.New("no idle file generated")
		return nil, errors.Wrap(err, "get commits error")
	}
	if fileNum-commited < num {
		num = fileNum - commited
	}
	commits := make([]Commit, num)
	for i := int64(1); i <= num; i++ {
		commits[i-1].FileIndex = commited + i
		name := path.Join(
			IdleFilePath,
			fmt.Sprintf("%s-%d", expanders.IDLE_DIR_NAME, commited+i),
			expanders.COMMIT_FILE,
		)
		commits[i-1].Roots, err = util.ReadProofFile(
			name, int(p.Expanders.K+2), expanders.HashSize)
		if err != nil {
			return nil, errors.Wrap(err, "get commits error")
		}
	}
	p.commited += num
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
	var (
		threads int
		err     error
	)
	lens := len(challenges)
	if lens < MaxProofThread {
		threads = lens
	} else {
		threads = MaxProofThread
	}
	proofSet := make([][]CommitProof, lens)

	wg := sync.WaitGroup{}
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		idx := i
		ants.Submit(func() {
			defer wg.Done()
			proofs, e := p.proveCommit(challenges[idx])
			if e != nil {
				err = e
				return
			}
			proofSet[idx] = proofs
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
	labels := make([][]byte, len(challenges))
	proof := &AccProof{
		Indexs: make([]int64, len(challenges)),
	}
	for i := 0; i < len(challenges); i++ {
		proof.Indexs[i] = challenges[i][0]
		labels[i], err = p.ReadAndCalcFileLabel(challenges[i][0])
		if err != nil {
			return nil, errors.Wrap(err, "update acc and Count error")
		}
	}
	proof.WitChains, proof.AccPath, err = p.AccManager.AddElementsAndProof(labels)
	if err != nil {
		return nil, errors.Wrap(err, "update acc and Count error")
	}
	proof.Labels = labels
	return proof, nil
}

func (p *Prover) ReadAndCalcFileLabel(Count int64) ([]byte, error) {
	name := path.Join(
		IdleFilePath,
		fmt.Sprintf("%s-%d", expanders.IDLE_DIR_NAME, Count),
		expanders.COMMIT_FILE,
	)
	roots, err := util.ReadProofFile(
		name, int(p.Expanders.K+2), expanders.HashSize)
	if err != nil {
		return nil, errors.Wrap(err, "read file root hashs error")
	}
	root := roots[p.Expanders.K]
	label := append([]byte{}, p.ID...)
	label = append(label, expanders.GetBytes(Count)...)
	return expanders.GetHash(append(label, root...)), nil
}

func (p *Prover) ReadFileLabels(Count int64, buf []byte) error {
	name := path.Join(
		IdleFilePath,
		fmt.Sprintf("%s-%d", expanders.IDLE_DIR_NAME, Count),
		fmt.Sprintf("%s-%d", expanders.LAYER_NAME, p.Expanders.K),
	)
	if err := util.ReadFileToBuf(name, buf); err != nil {
		return errors.Wrap(err, "read file labels error")
	}
	return nil
}

func (p *Prover) proveCommit(challenge []int64) ([]CommitProof, error) {
	var (
		err   error
		index expanders.NodeType
	)
	proofs := make([]CommitProof, len(challenge)-1)
	fdir := path.Join(IdleFilePath, fmt.Sprintf("%s-%d", expanders.IDLE_DIR_NAME, challenge[0]))
	proofs[0], err = p.generateCommitProof(fdir, challenge[0], challenge[1])
	if err != nil {
		return nil, errors.Wrap(err, "prove one file commit error")
	}
	for i := 2; i < len(challenge); i++ {
		index = proofs[i-2].Parents[challenge[i]].Index
		proofs[i-1], err = p.generateCommitProof(fdir, challenge[0], int64(index))
		if err != nil {
			return nil, errors.Wrap(err, "prove one file commit error")
		}
	}
	return proofs, nil
}

func (p *Prover) generateCommitProof(fdir string, count, c int64) (CommitProof, error) {
	layer := c / p.Expanders.N
	if layer < 0 || layer > p.Expanders.K {
		return CommitProof{}, errors.New("generate commit proof error: bad node index")
	}

	fpath := path.Join(fdir, fmt.Sprintf("%s-%d", expanders.LAYER_NAME, layer))
	data := p.Expanders.FilePool.Get().(*[]byte)
	defer p.Expanders.FilePool.Put(data)
	if err := util.ReadFileToBuf(fpath, *data); err != nil {
		return CommitProof{}, errors.Wrap(err, "generate commit proof error")
	}

	var nodeTree, parentTree *tree.LightMHT
	index := c % p.Expanders.N
	nodeTree = tree.CalcLightMhtWithBytes(*data, expanders.HashSize, true)
	defer tree.RecoveryMht(nodeTree)
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

	if layer == 0 {
		return proof, nil
	}
	node := expanders.NewNode(expanders.NodeType(c))
	node.Parents = make([]expanders.NodeType, 0, p.Expanders.D+1)
	expanders.CalcParents(p.Expanders, node, p.ID, count)
	fpath = path.Join(fdir, fmt.Sprintf("%s-%d", expanders.LAYER_NAME, layer-1))
	pdata := p.Expanders.FilePool.Get().(*[]byte)
	defer p.Expanders.FilePool.Put(pdata)
	err = util.ReadFileToBuf(fpath, *pdata)
	if err != nil {
		return proof, errors.Wrap(err, "generate commit proof error")
	}
	parentTree = tree.CalcLightMhtWithBytes(*pdata, expanders.HashSize, true)
	defer tree.RecoveryMht(parentTree)
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
			if int64(node.Parents[idx]) >= layer*p.Expanders.N {
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
				if err := p.ReadFileLabels(fidx, *data); err != nil {
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
				tree.RecoveryMht(mht)
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
			if err := p.ReadFileLabels(p.front+i, *data); err != nil {
				Err <- errors.Wrap(err, "prove deletion error")
				return
			}
			mht := tree.CalcLightMhtWithBytes(*data, expanders.HashSize, true)
			roots[i-1] = mht.GetRoot(expanders.HashSize)
			tree.RecoveryMht(mht)
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
	for i := p.rear + 1; i <= p.rear+num; i++ {
		dir := path.Join(IdleFilePath,
			fmt.Sprintf("%s-%d", expanders.IDLE_DIR_NAME, i))
		for j := 0; j < int(p.Expanders.K); j++ {
			name := path.Join(dir, fmt.Sprintf("%s-%d", expanders.LAYER_NAME, j))
			if err := util.DeleteFile(name); err != nil {
				return err
			}
		}
		name := path.Join(dir, expanders.COMMIT_FILE)
		if err := util.DeleteFile(name); err != nil {
			return err
		}
	}
	p.space += num * p.Expanders.K * FileSize
	return nil
}

func (p *Prover) deleteFiles(num int64, raw bool) error {
	for i := int64(1); i <= num; i++ {
		dir := path.Join(IdleFilePath,
			fmt.Sprintf("%s-%d", expanders.IDLE_DIR_NAME, p.front+i))
		if err := util.DeleteDir(dir); err != nil {
			return errors.Wrap(err, "delete files error")
		}
	}
	if !raw {
		p.space += num * FileSize
	} else {
		p.space += num * FileSize * (p.Expanders.K + 1)
	}
	return nil
}

func calcGeneratedFile(dir string, rear, total int64) (int64, error) {
	count := int64(0)
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return count, err
	}
	for _, entry := range entries {
		sidxs := strings.Split(entry.Name(), "-")
		if len(sidxs) < 2 {
			continue
		}
		if idx, err := strconv.ParseInt(sidxs[1], 10, 64); err != nil || idx <= rear {
			continue
		}
		if !entry.IsDir() {
			continue
		}
		files, err := ioutil.ReadDir(path.Join(dir, entry.Name()))
		if err != nil {
			return count, err
		}
		size := int64(0)
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			size += file.Size()
		}
		if size == total {
			count++
		}
	}
	return count, nil
}
