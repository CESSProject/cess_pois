package pois

import (
	"cess_pois/acc"
	"cess_pois/expanders"
	"cess_pois/tree"
	"cess_pois/util"
	"fmt"
	"path"
	"sync"
	"sync/atomic"

	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
)

var (
	FileSize             int64  = int64(expanders.HashSize)
	IdleFilePath         string = expanders.DEFAULT_IDLE_FILES_PATH
	AccPath              string = acc.DEFAULT_PATH
	MaxCommitProofThread        = 16
)

type Prover struct {
	Expanders  *expanders.Expanders
	count      int64
	commited   int64
	added      int64
	generated  int64
	space      int64
	rw         sync.RWMutex
	delete     atomic.Bool
	update     atomic.Bool
	generate   atomic.Bool
	ID         []byte
	cmdCh      chan<- int64
	resCh      <-chan bool
	AccManager acc.AccHandle
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
	Proofs    []*MhtProof        `json:"proofs"`
	Roots     [][]byte           `json:"roots"`
	WitChains []*acc.WitnessNode `json:"wit_chains"`
}

type DeletionProof struct {
	Roots    [][]byte         `json:"roots"`
	WitChain *acc.WitnessNode `json:"wit_chain"`
	AccPath  [][]byte         `json:"acc_path"`
}

func NewProver(k, n, d int64, ID []byte, key acc.RsaKey, space int64) (*Prover, error) {

	if k == 0 || n == 0 || d == 0 || space == 0 || len(ID) == 0 ||
		key.G.BitLen() == 0 || key.N.BitLen() == 0 {
		err := errors.New("bad init params")
		return nil, errors.Wrap(err, "init prover error")
	}
	prover := &Prover{
		ID: ID,
	}
	prover.Expanders = expanders.ConstructStackedExpanders(k, n, d)
	var err error
	prover.AccManager, err = acc.NewMutiLevelAcc(AccPath, key)
	prover.space = space
	return prover, errors.Wrap(err, "init prover error")
}

// GenerateFile notifies the idle file generation service to generate the specified number of files,
// if num>MaxCommitProofThread,it may be blocked
func (p *Prover) GenerateFile(num int64) bool {
	if num <= 0 ||
		p.space < num*FileSize*(p.Expanders.K+1) {
		return false
	}
	if p.delete.Load() {
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

// AccRollback need to be invoked when submit or verify acc proof failure
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

// UpdateCount need to be invoked after verify commit proof and acc proof success
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
		err = p.deleteFiles(num, false)
		num = -num
	} else {
		if !p.update.CompareAndSwap(true, false) {
			err = errors.New("no update task pending update")
			return errors.Wrap(err, "updat prover status error")
		}
		err = p.organizeFiles(num)
	}
	if err != nil {
		return errors.Wrap(err, "updat prover status error")
	}
	p.count += num
	p.AccManager.UpdateSnapshot()
	return nil
}

// AddSpace add size MiB space to available space, generally used to return user file space
func (p *Prover) AddSpace(size int64) {
	if size <= 0 {
		return
	}
	p.space += size
}

func (p *Prover) GetSpace() int64 {
	return p.space
}

// GetCount get Count Safely
func (p *Prover) GetCount() int64 {
	p.rw.RLock()
	defer p.rw.RUnlock()
	return p.count
}

// RunIdleFileGenerationServer start the specified number of goroutines to generate idle files
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
	if p.delete.Load() {
		return nil, nil
	}
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
	if lens < MaxCommitProofThread {
		threads = lens
	} else {
		threads = MaxCommitProofThread
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

func (p *Prover) ProveSpace(challenges [][]int64) (*SpaceProof, error) {
	var err error
	lens := len(challenges)
	if lens <= 0 {
		err := errors.New("bad challenge length")
		return nil, errors.Wrap(err, "prove space error")
	}
	proof := &SpaceProof{
		Proofs:    make([]*MhtProof, lens),
		Roots:     make([][]byte, lens),
		WitChains: make([]*acc.WitnessNode, lens),
	}
	indexs := make([]int64, lens)
	data := p.Expanders.FilePool.Get().(*[]byte)
	for i := 0; i < lens; i++ {
		if err := p.ReadFileLabels(challenges[i][0], *data); err != nil {
			return nil, errors.Wrap(err, "prove space error")
		}
		mht := tree.CalcLightMhtWithBytes(*data, expanders.HashSize, true)

		indexs[i] = challenges[i][0]
		proof.Roots[i] = mht.GetRoot(expanders.HashSize)

		idx := int(challenges[i][1]) % expanders.HashSize
		mhtProof, err := mht.GetPathProof(*data, idx, expanders.HashSize)
		if err != nil {
			return nil, errors.Wrap(err, "prove space error")
		}

		label := make([]byte, expanders.HashSize)
		copy(label, (*data)[idx*expanders.HashSize:(idx+1)*expanders.HashSize])

		proof.Proofs[i] = &MhtProof{
			Paths: mhtProof.Path,
			Locs:  mhtProof.Locs,
			Index: expanders.NodeType(challenges[i][1]),
			Label: label,
		}

		tree.RecoveryMht(mht)
	}
	p.Expanders.FilePool.Put(data)
	proof.WitChains, err = p.AccManager.GetWitnessChains(indexs)
	if err != nil {
		return nil, errors.Wrap(err, "prove space error")
	}
	return proof, nil
}

// ProveDeletion sort out num*IdleFileSize(unit MiB) available space,
// it subtracts all unused and uncommitted space, and deletes enough idle files to make room,
// so the number of idle files actually deleted is the length of DeletionProof.Roots,
// you need to update prover status with this value rather than num after the verification is successful.
// If the data read from the two channels returned by the method are empty,
// it means that enough space has been sorted out and no other operations are required
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
		var tmp int64
		roots := make([][]byte, num)

		for p.generate.Load() || p.update.Load() || p.added > p.generated {
			//wait for all updates to complete
		}
		//If the unauthenticated space is large enough, there is no need to delete idle files
		if size := FileSize * num; size < p.space {
			p.space -= size
			ch <- nil
			Err <- nil
			return
		}
		num -= p.space / FileSize
		p.space = 0
		//If the uncommitted space is large enough, delete num uncommitted idle files
		fnum := (p.generated - p.commited)
		if fnum*(p.Expanders.K+1) >= num {
			err := p.deleteFiles((num+p.Expanders.K)/(p.Expanders.K+1), true)
			if err != nil {
				Err <- errors.Wrap(err, "prove deletion error")
			}
			p.space -= num * FileSize
			ch <- nil
			return
		} else if fnum > 0 {
			num -= fnum * (p.Expanders.K + 1)
			err := p.deleteFiles(fnum, true)
			if err != nil {
				ch <- nil
				Err <- errors.Wrap(err, "prove deletion error")
				return
			}
			p.space -= fnum * (p.Expanders.K + 1) * FileSize
		}
		p.rw.Lock()
		if p.count < num {
			p.rw.Unlock()
			ch <- nil
			err := errors.New("insufficient operating space")
			Err <- errors.Wrap(err, "prove deletion error")
			return
		}
		tmp = p.count - num
		p.rw.Unlock()
		data := p.Expanders.FilePool.Get().(*[]byte)
		defer p.Expanders.FilePool.Put(data)
		for i := int64(1); i <= num; i++ {
			if err := p.ReadFileLabels(tmp+i, *data); err != nil {
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
	for i := p.count + 1; i <= p.count+num; i++ {
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
		p.space += num * p.Expanders.K * FileSize
	}
	return nil
}

func (p *Prover) deleteFiles(num int64, raw bool) error {
	index := p.count - num
	for i := int64(1); i <= num; i++ {
		dir := path.Join(IdleFilePath,
			fmt.Sprintf("%s-%d", expanders.IDLE_DIR_NAME, index+i))
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
