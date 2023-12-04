package pois

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
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
	AccPath        string = acc.DEFAULT_PATH
	ChallAccPath   string = "./chall_acc/" //Do not match AccPath
	IdleFilePath   string = expanders.DEFAULT_IDLE_FILES_PATH
	MaxProofThread        = 4 //please set according to the number of cores
	SpaceFullError        = errors.New("generate idle file set error: not enough space")
	MiniFileSize   int64  = 1024 * 1024
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
	sync       atomic.Bool
	generate   atomic.Bool
	ID         []byte
	chainState *ChainState
	AccManager acc.AccHandle
}

type Config struct {
	AccPath        string
	ChallAccPath   string
	IdleFilePath   string
	MaxProofThread int
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
	delCh       chan struct{}
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
	Elders  []*MhtProof `json:"elders"`
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
	FileSize = int64(expanders.HashSize) * n / (1024 * 1024) //file size must >=1M
	prover.Expanders = expanders.ConstructStackedExpanders(k, n, d)
	prover.space = space
	prover.setLen = setLen
	prover.clusterSize = k
	prover.chainState = &ChainState{}
	tree.InitMhtPool(int(n))
	return prover, nil
}

func (p *Prover) Init(key acc.RsaKey, config Config) error {
	if key.G.BitLen() == 0 || key.N.BitLen() == 0 {
		return errors.New("bad init params")
	}
	checkConfig(config)
	var err error
	p.AccManager, err = acc.NewMutiLevelAcc(AccPath, key)
	if err != nil {
		return errors.Wrap(err, "init prover error")
	}
	_, err = acc.NewMutiLevelAcc(ChallAccPath, key)
	if err != nil {
		return errors.Wrap(err, "init prover error")
	}
	return nil
}

func (p *Prover) Recovery(key acc.RsaKey, front, rear int64, config Config) error {

	if key.G.BitLen() == 0 || key.N.BitLen() == 0 || front < 0 ||
		rear < 0 || front > rear || rear%(p.setLen*p.clusterSize) != 0 {
		return errors.New("bad recovery params")
	}
	checkConfig(config)

	//recovery front and rear
	p.front = front
	p.rear = rear

	var err error
	//recovery acc
	p.AccManager, err = acc.Recovery(AccPath, key, front, rear)
	if err != nil {
		return errors.Wrap(err, "recovery prover error")
	}
	//recovery context

	generated, err := p.calcGeneratedFile(IdleFilePath)
	if err != nil {
		return errors.Wrap(err, "recovery prover error")
	}
	if generated%(p.setLen*p.clusterSize) != 0 { //restores must be performed in units of the number of files in a set
		generated -= generated % (p.setLen * p.clusterSize)
	}
	p.generated = rear + generated //generated files do not need to be generated again
	p.added = rear + generated     //the file index to be generated should be consistent with the generated file index firstly
	p.commited = rear
	p.space -= (p.rear - p.front) * FileSize                                          //calc proved space
	p.space -= generated / p.clusterSize * (p.clusterSize + p.Expanders.K) * FileSize //calc generated space

	//backup acc file for challenge
	err = util.CopyFiles(AccPath, ChallAccPath)
	if err != nil {
		return errors.Wrap(err, "recovery prover error")
	}

	return nil
}

func checkConfig(config Config) {
	if config.AccPath != "" {
		AccPath = config.AccPath
	}
	if config.IdleFilePath != "" {
		IdleFilePath = config.IdleFilePath
	}
	if config.MaxProofThread > 0 &&
		MaxProofThread != config.MaxProofThread {
		MaxProofThread = config.MaxProofThread
	}
	if config.ChallAccPath != "" && config.ChallAccPath != AccPath {
		ChallAccPath = config.ChallAccPath
	}
}

func (p *Prover) SetChallengeState(key acc.RsaKey, accSnp []byte, front, rear int64) error {

	p.rw.Lock()
	defer p.rw.Unlock()

	p.chainState = &ChainState{
		Rear:  rear,
		Front: front,
	}
	chainAcc := big.NewInt(0).SetBytes(accSnp)

	var err error
	p.chainState.Acc, err = acc.Recovery(ChallAccPath, key, front, rear)
	if err != nil {
		return errors.Wrap(err, "recovery chain state error")
	}

	localAcc := big.NewInt(0).SetBytes(p.chainState.Acc.GetSnapshot().Accs.Value)
	if chainAcc.Cmp(localAcc) != 0 {
		err = errors.New("the restored acc value is not equal to the snapshot value")
		return errors.Wrap(err, "recovery chain state error")
	}
	p.chainState.delCh = make(chan struct{})
	p.chainState.challenging = true
	return nil
}

// GenerateIdleFileSet generate num=(p.setLen*p.clusterSize(==k)) idle files, num must be consistent with the data given by CESS, otherwise it cannot pass the verification
// This method is not thread-safe, please do not use it concurrently!
func (p *Prover) GenerateIdleFileSet() error {

	fileNum := p.setLen * p.clusterSize
	freeSpace, err := util.GetDirFreeSpace(IdleFilePath)
	freeSpace /= 1024 * 1024
	var reserved int64 = 256
	if err != nil {
		return errors.Wrap(err, "generate idle file set error")
	}

	if p.space == fileNum*FileSize &&
		freeSpace > uint64(p.Expanders.K*FileSize+reserved) {
		p.space += p.Expanders.K * FileSize
	}

	if p.space < (fileNum+p.setLen*p.Expanders.K)*FileSize {
		return SpaceFullError
	}
	if !p.generate.CompareAndSwap(false, true) {
		return errors.New("generate idle file set error: lock is occupied")
	}
	defer p.generate.Store(false)
	p.added += fileNum
	p.space -= (fileNum + p.setLen*p.Expanders.K) * FileSize
	start := (p.added-fileNum)/p.clusterSize + 1
	if err := p.Expanders.GenerateIdleFileSet(
		p.ID, start, p.setLen, IdleFilePath); err != nil {
		// clean files
		p.added -= fileNum
		p.space += (fileNum + p.setLen*p.Expanders.K) * FileSize
		return errors.Wrap(err, "generate idle file set error")
	}
	p.generated += fileNum
	return nil
}

func (p *Prover) GenerateIdleFileSets(tNum int) error {

	if tNum <= 0 {
		return errors.New("generate idle file sets error bad thread number")
	}

	freeSpace, err := util.GetDirFreeSpace(IdleFilePath)
	freeSpace /= 1024 * 1024
	var reserved int64 = 256
	if err != nil {
		return errors.Wrap(err, "generate idle file sets error")
	}

	fileNum := p.setLen * p.clusterSize

	if p.space == fileNum*FileSize &&
		freeSpace > uint64(p.Expanders.K*FileSize+reserved) {
		p.space += p.Expanders.K * FileSize
	}

	if p.space < (fileNum+p.setLen*p.Expanders.K)*FileSize*int64(tNum) {
		if p.space >= (fileNum+p.setLen*p.Expanders.K)*FileSize {
			tNum = 1
		} else {
			return SpaceFullError
		}
	}
	if !p.generate.CompareAndSwap(false, true) {
		return errors.New("generate idle file sets error lock is occupied")
	}
	defer p.generate.Store(false)

	currIndex := p.added/p.clusterSize + 1
	p.added += fileNum * int64(tNum)
	p.space -= (fileNum + p.setLen*p.Expanders.K) * FileSize * int64(tNum)

	wg := sync.WaitGroup{}
	wg.Add(tNum)
	for i := 0; i < tNum; i++ {
		start := currIndex + int64(i)*p.setLen
		ants.Submit(func() {
			defer wg.Done()
			if tErr := p.Expanders.GenerateIdleFileSet(
				p.ID, start, p.setLen, IdleFilePath); tErr != nil {
				err = tErr
			}
		})
	}
	wg.Wait()
	if err != nil {
		p.added -= fileNum * int64(tNum)
		p.space += (fileNum + p.setLen*p.Expanders.K) * FileSize * int64(tNum)
		return errors.Wrap(err, "generate idle file sets error")
	}
	p.generated += fileNum * int64(tNum)
	return nil
}

// CommitRollback need to be invoked when submit commits to verifier failure
func (p *Prover) CommitRollback() bool {
	if p.update.CompareAndSwap(true, false) {
		p.commited -= p.setLen * p.clusterSize
		return true
	}
	return false
}

// AccRollback need to be invoked when submit or verify acc proof failure,
// the update of the accumulator is serial and blocking, you need to update or roll back in time.
func (p *Prover) AccRollback(isDel bool) bool {
	p.rw.Lock()
	defer p.rw.Unlock()
	if isDel {
		if !p.delete.CompareAndSwap(true, false) {
			return false
		}
	} else {
		if !p.update.CompareAndSwap(true, false) {
			return false
		}
		p.commited -= p.setLen * p.clusterSize
	}
	return p.AccManager.RollBack()
}

func (p *Prover) SyncChainPoisStatus(front, rear int64) error {
	p.rw.Lock()
	defer p.rw.Unlock()

	if p.front == front && p.rear == rear {
		return nil
	}
	p.sync.Store(true)
	defer p.sync.Store(false)
	for !p.update.Load() && !p.delete.Load() {
	}
	var err error
	p.AccManager, err = acc.Recovery(
		AccPath, p.AccManager.GetSnapshot().Key, front, rear)
	if err != nil {
		return errors.Wrap(err, "reflash acc error")
	}
	//recovery front and rear
	p.front = front
	p.rear = rear
	p.commited = rear
	return nil
}

// UpdateStatus need to be invoked after verify commit proof and acc proof success,
// the update of the accumulator is serial and blocking, you need to update or roll back in time.
func (p *Prover) UpdateStatus(num int64, isDelete bool) error {
	var err error
	if num < 0 {
		err = errors.New("bad files number")
		return errors.Wrap(err, "updat prover status error")
	}

	if isDelete {
		if !p.delete.CompareAndSwap(true, false) {
			err = errors.New("no delete task pending update")
			return errors.Wrap(err, "updat prover status error")
		}
		p.rw.Lock()
		p.front += num
		p.AccManager.UpdateSnapshot()
		p.rw.Unlock()

		err = acc.CleanBackup(AccPath, int((p.front-1)/acc.DEFAULT_ELEMS_NUM))
		if err != nil {
			return errors.Wrap(err, "delete idle files error")
		}
		return nil
	}

	if !p.update.CompareAndSwap(true, false) {
		err = errors.New("no update task pending update")
		return errors.Wrap(err, "updat prover status error")
	}
	p.rw.Lock()
	p.rear += num
	p.AccManager.UpdateSnapshot()
	p.rw.Unlock()
	if err := p.organizeFiles(p.rear-num, num); err != nil {
		return errors.Wrap(err, "updat prover status error")
	}
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

func (p *Prover) GetAccValue() []byte {
	keyLen := 256
	acc := p.AccManager.GetSnapshot().Accs.Value
	res := make([]byte, keyLen)
	if len(acc) > keyLen {
		copy(res, acc[len(acc)-256:])
		return res
	}
	copy(res[256-len(acc):], acc)
	return res
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

func (p *Prover) GetNumOfFileInSet() int64 {
	return p.setLen * p.clusterSize
}

func (p *Prover) CommitDataIsReady() bool {
	p.rw.RLock()
	defer p.rw.RUnlock()
	fileNum := p.generated
	commited := p.commited
	return fileNum-commited >= p.setLen*p.clusterSize
}

func (p *Prover) GetChainState() ChainState {
	p.rw.RLock()
	defer p.rw.RUnlock()
	state := ChainState{
		Rear:  p.chainState.Rear,
		Front: p.chainState.Front,
		Acc:   p.chainState.Acc,
	}
	return state
}

// RestChallengeState must be called when space proof is finished
func (p *Prover) RestChallengeState() {
	p.rw.Lock()
	defer p.rw.Unlock()
	p.proofed = 0
	p.chainState.delCh = nil
	p.chainState.challenging = false
	if p.chainState.Front >= acc.DEFAULT_ELEMS_NUM {
		index := (p.chainState.Front - acc.DEFAULT_ELEMS_NUM) / acc.DEFAULT_ELEMS_NUM
		acc.DeleteAccData(ChallAccPath, int(index))
	}
}

// GetIdleFileSetCommits can not run concurrently! And num must be consistent with the data given by CESS.
func (p *Prover) GetIdleFileSetCommits() (Commits, error) {
	var (
		err     error
		commits Commits
	)

	if p.sync.Load() {
		err := errors.New("syncing status, please try again")
		return commits, errors.Wrap(err, "get commits error")
	}

	if !p.update.CompareAndSwap(false, true) {
		err = errors.New("lock is occupied")
		return commits, errors.Wrap(err, "get commits error")
	}
	fileNum := p.generated
	commited := p.commited
	commitNum := p.setLen * p.clusterSize
	if fileNum-commited < commitNum {
		p.update.Store(false)
		err = errors.New("bad commit data")
		return commits, errors.Wrap(err, "get commits error")
	}
	//read commit file of idle file set
	name := path.Join(
		IdleFilePath,
		fmt.Sprintf("%s-%d", expanders.SET_DIR_NAME, (commited)/(p.setLen*p.clusterSize)+1),
		expanders.COMMIT_FILE,
	)
	rootNum := int(commitNum + p.Expanders.K*p.setLen + 1)
	commits.Roots, err = util.ReadProofFile(name, rootNum, tree.DEFAULT_HASH_SIZE)
	if err != nil {
		p.update.Store(false)
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

	//copy new acc data to challenging acc path
	index := int(p.rear) / acc.DEFAULT_ELEMS_NUM
	err = acc.BackupAccDataForChall(AccPath, ChallAccPath, index)
	if err != nil {
		return nil, nil, err
	}

	return commitProofs, accProof, nil
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
		fname, int(p.Expanders.K+p.clusterSize)*int(p.setLen)+1, tree.DEFAULT_HASH_SIZE)
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

func (p *Prover) ReadAuxData(cluster, fidx int64, buf []byte) error {
	name := path.Join(
		IdleFilePath,
		fmt.Sprintf("%s-%d", expanders.SET_DIR_NAME, (cluster-1)/p.setLen+1),
		fmt.Sprintf("%s-%d", expanders.CLUSTER_DIR_NAME, cluster),
		fmt.Sprintf("%s-%d", expanders.AUX_FILE, fidx+p.Expanders.K),
	)
	if err := util.ReadFileToBuf(name, buf); err != nil {
		return errors.Wrap(err, "read aux data error")
	}
	return nil
}

// ProveCommit prove commits no more than MaxCommitProofThread
func (p *Prover) proveCommits(challenges [][]int64) ([][]CommitProof, error) {

	var (
		err      error
		neighbor string
	)
	lens := len(challenges)
	proofSet := make([][]CommitProof, lens)
	clusters := make([]int64, lens)

	for i := 0; i < lens; i++ {
		clusters[i] = challenges[i][0]
	}

	for i := 0; i < lens; i++ {
		proofs := make([]CommitProof, len(challenges[i])-1)
		fdir := path.Join(
			IdleFilePath,
			fmt.Sprintf("%s-%d", expanders.SET_DIR_NAME, (challenges[i][0]-1)/p.setLen+1),
			fmt.Sprintf("%s-%d", expanders.CLUSTER_DIR_NAME, challenges[i][0]),
		)
		for j := int64(1); j <= int64(len(proofs)); j++ {

			index := challenges[i][j]
			if j > p.clusterSize+1 {
				// jb, _ := json.Marshal(proofs[j-2])
				// log.Println("proofs", j-2, string(jb))
				index = int64(proofs[j-2].Parents[challenges[i][j]].Index)
			}
			layer := index / p.Expanders.N
			if j < p.clusterSize+1 {
				layer = p.Expanders.K + j - 1
			}
			if layer != 0 || i != 0 {
				cid := challenges[i][0] - 1
				if cid%p.setLen == 0 {
					cid += p.setLen
				}
				neighbor = path.Join(
					IdleFilePath,
					fmt.Sprintf("%s-%d", expanders.SET_DIR_NAME, (challenges[i][0]-1)/p.setLen+1),
					fmt.Sprintf("%s-%d", expanders.CLUSTER_DIR_NAME, cid),
					fmt.Sprintf("%s-%d", expanders.FILE_NAME, layer-(p.setLen-int64(i))/p.setLen),
				)
			}
			proofs[j-1], err = p.generateCommitProof(fdir, neighbor, clusters, index, layer)
			if err != nil {
				return nil, errors.Wrap(err, "prove commits error")
			}
		}
		proofSet[i] = proofs
	}
	return proofSet, nil
}

func (p *Prover) generatePathProof(mht *tree.LightMHT, data *[]byte, index, nodeIdx int64) (*MhtProof, error) {

	mht.CalcLightMhtWithBytes(*data, expanders.HashSize)
	pathProof, err := mht.GetPathProof(*data, int(index), expanders.HashSize)
	if err != nil {
		return nil, errors.Wrap(err, "generate path proof error")
	}
	label := make([]byte, expanders.HashSize)
	copy(label, (*data)[index*int64(expanders.HashSize):(index+1)*int64(expanders.HashSize)])
	return &MhtProof{
		Index: expanders.NodeType(nodeIdx),
		Label: label,
		Paths: pathProof.Path,
		Locs:  pathProof.Locs,
	}, nil
}

func (p *Prover) getPathProofWithAux(aux []byte, data *[]byte, index, nodeIdx int64) (*MhtProof, error) {
	pathProof, err := tree.GetPathProofWithAux(*data, aux, int(index), expanders.HashSize)
	if err != nil {
		return nil, errors.Wrap(err, "get path proof with aux error")
	}
	label := make([]byte, expanders.HashSize)
	copy(label, (*data)[index*int64(expanders.HashSize):(index+1)*int64(expanders.HashSize)])
	return &MhtProof{
		Index: expanders.NodeType(nodeIdx),
		Label: label,
		Paths: pathProof.Path,
		Locs:  pathProof.Locs,
	}, nil
}

func (p *Prover) generateCommitProof(fdir, neighbor string, counts []int64, c, subfile int64) (CommitProof, error) {

	if subfile < 0 || subfile > p.clusterSize+p.Expanders.K-1 {
		return CommitProof{}, errors.New("generate commit proof error: bad node index")
	}

	data := p.Expanders.FilePool.Get().(*[]byte)
	defer p.Expanders.FilePool.Put(data)
	fpath := path.Join(fdir, fmt.Sprintf("%s-%d", expanders.FILE_NAME, subfile))
	if err := util.ReadFileToBuf(fpath, *data); err != nil {
		return CommitProof{}, errors.Wrap(err, "generate commit proof error")
	}

	nodeTree, parentTree := tree.GetLightMhtFromPool(), tree.GetLightMhtFromPool()
	defer tree.PutLightMhtToPool(nodeTree)
	defer tree.PutLightMhtToPool(parentTree)
	index := c % p.Expanders.N

	pathProof, err := p.generatePathProof(nodeTree, data, index, c)
	if err != nil {
		return CommitProof{}, errors.Wrap(err, "generate commit proof error")
	}

	proof := CommitProof{
		Node: pathProof,
	}

	pdata := p.Expanders.FilePool.Get().(*[]byte)
	defer p.Expanders.FilePool.Put(pdata)

	aux := make([]byte, expanders.DEFAULT_AUX_SIZE*tree.DEFAULT_HASH_SIZE)

	//add neighbor node dependency
	proof.Elders = make([]*MhtProof, subfile/p.Expanders.K*p.Expanders.K/2+1)
	if neighbor != "" {
		if err := util.ReadFileToBuf(neighbor, *pdata); err != nil {
			return CommitProof{}, errors.Wrap(err, "generate commit proof error")
		}
		if err := util.ReadFileToBuf(
			strings.Replace(neighbor, expanders.FILE_NAME, expanders.AUX_FILE, 1), aux,
		); err != nil {
			return CommitProof{}, errors.Wrap(err, "generate commit proof error")
		}

		proof.Elders[0], err = p.getPathProofWithAux(aux, pdata, index, index)
		if err != nil {
			return CommitProof{}, errors.Wrap(err, "generate commit proof error")
		}
	}

	if subfile == 0 {
		return proof, nil
	}

	//file remapping
	if subfile >= p.Expanders.K {

		counts = append(counts, subfile-p.Expanders.K+1)
		baseLayer := int((subfile - p.Expanders.K/2) / p.Expanders.K)
		subfile = p.Expanders.K

		//add elder node dependency
		for i := 0; i < int(p.Expanders.K/2); i++ {
			fpath := path.Join(fdir, fmt.Sprintf("%s-%d", expanders.FILE_NAME, baseLayer+i*2))
			aPath := path.Join(fdir, fmt.Sprintf("%s-%d", expanders.AUX_FILE, baseLayer+i*2))
			if err := util.ReadFileToBuf(fpath, *pdata); err != nil {
				return CommitProof{}, errors.Wrap(err, "generate commit proof error")
			}
			if err := util.ReadFileToBuf(aPath, aux); err != nil {
				return CommitProof{}, errors.Wrap(err, "generate commit proof error")
			}
			proof.Elders[i+1], err = p.getPathProofWithAux(aux, pdata, index, index+int64(baseLayer+i*2)*p.Expanders.N)
			if err != nil {
				return CommitProof{}, errors.Wrap(err, "generate commit proof error")
			}
		}
	}

	node := expanders.NewNode(expanders.NodeType(c))
	node.Parents = make([]expanders.NodeType, 0, p.Expanders.D+1)
	expanders.CalcParents(p.Expanders, node, p.ID, counts...)

	fpath = path.Join(fdir, fmt.Sprintf("%s-%d", expanders.FILE_NAME, subfile-1))

	err = util.ReadFileToBuf(fpath, *pdata)
	if err != nil {
		return proof, errors.Wrap(err, "generate commit proof error")
	}

	parentTree.CalcLightMhtWithBytes(*pdata, expanders.HashSize)
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
	if threads <= 0 {
		threads = 2
	}
	block := int(right-left) / threads
	for block*threads < int(right-left) {
		block++
	}
	wg := sync.WaitGroup{}
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		gl, gr := left+int64(i*block), left+int64((i+1)*block)
		if gr > right {
			gr = right
		}
		ants.Submit(func() {
			defer wg.Done()
			for fidx := gl; fidx < gr; fidx++ {
				data := p.Expanders.FilePool.Get().(*[]byte)
				err = p.ReadFileLabels((fidx-1)/p.clusterSize+1, (fidx-1)%p.clusterSize, *data)
				if err != nil {
					return
				}
				aux := make([]byte, expanders.DEFAULT_AUX_SIZE*tree.DEFAULT_HASH_SIZE)
				err = p.ReadAuxData((fidx-1)/p.clusterSize+1, (fidx-1)%p.clusterSize, aux)
				if err != nil {
					return
				}
				mht := make(tree.LightMHT, len(aux))
				mht.CalcLightMhtWithAux(aux)
				indexs[fidx-left] = fidx
				proof.Roots[fidx-left] = mht.GetRoot()
				proof.Proofs[fidx-left] = make([]*MhtProof, len(challenges))
				for j := 0; j < len(challenges); j++ {
					idx := int(challenges[j] % p.Expanders.N)
					pathProof, err := tree.GetPathProofWithAux(*data, aux, idx, expanders.HashSize)
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
				p.Expanders.FilePool.Put(data)
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
	select {
	case <-p.chainState.delCh:
	default:
	}
	return proof, nil
}

// ProveDeletion sort out num*IdleFileSize(unit MiB) available space,
// you need to update prover status with this value rather than num after the verification is successful.
func (p *Prover) ProveDeletion(num int64) (*DeletionProof, error) {

	if p.sync.Load() {
		err := errors.New("syncing status, please try again")
		return nil, errors.Wrap(err, "prove deletion error")
	}

	if num <= 0 {
		err := errors.New("bad file number")
		return nil, errors.Wrap(err, "prove deletion error")
	}
	p.delete.Store(true)
	p.rw.Lock()
	if p.rear-p.front < num {
		p.rw.Unlock()
		err := errors.New("insufficient operating space")
		return nil, errors.Wrap(err, "prove deletion error")
	}
	p.rw.Unlock()
	data := p.Expanders.FilePool.Get().(*[]byte)
	defer p.Expanders.FilePool.Put(data)
	roots := make([][]byte, num)
	aux := make([]byte, expanders.DEFAULT_AUX_SIZE*tree.DEFAULT_HASH_SIZE)
	mht := make(tree.LightMHT, len(aux))
	for i := int64(1); i <= num; i++ {
		cluster, subfile := (p.front+i-1)/p.clusterSize+1, (p.front+i-1)%p.clusterSize
		if err := p.ReadFileLabels(cluster, subfile, *data); err != nil {
			return nil, errors.Wrap(err, "prove deletion error")
		}
		if err := p.ReadAuxData(cluster, subfile, aux); err != nil {
			return nil, errors.Wrap(err, "prove deletion error")
		}
		mht.CalcLightMhtWithAux(aux)
		roots[i-1] = mht.GetRoot()
	}
	wits, accs, err := p.AccManager.DeleteElementsAndProof(int(num))
	if err != nil {
		return nil, errors.Wrap(err, "prove deletion error")
	}
	proof := &DeletionProof{
		Roots:    roots,
		WitChain: wits,
		AccPath:  accs,
	}
	return proof, nil
}

func (p *Prover) organizeFiles(idx, num int64) error {
	dir := path.Join(
		IdleFilePath,
		fmt.Sprintf("%s-%d", expanders.SET_DIR_NAME, idx/(p.clusterSize*p.setLen)+1),
	)
	for i := idx + 1; i <= idx+num; i += 8 {
		for j := 0; j < int(p.Expanders.K); j++ {
			// delete idle file
			name := path.Join(dir,
				fmt.Sprintf("%s-%d", expanders.CLUSTER_DIR_NAME, (i-1)/p.clusterSize+1),
				fmt.Sprintf("%s-%d", expanders.FILE_NAME, j))
			if err := util.DeleteFile(name); err != nil {
				return err
			}
			// delete aux file
			name = path.Join(dir,
				fmt.Sprintf("%s-%d", expanders.CLUSTER_DIR_NAME, (i-1)/p.clusterSize+1),
				fmt.Sprintf("%s-%d", expanders.AUX_FILE, j))
			if err := util.DeleteFile(name); err != nil {
				return err
			}
		}
	}
	name := path.Join(dir, expanders.COMMIT_FILE)
	if err := util.DeleteFile(name); err != nil {
		return err
	}
	p.space += num / p.clusterSize * p.Expanders.K * FileSize
	return nil
}

func (p *Prover) DeleteFiles() error {

	for p.chainState.challenging && p.proofed < p.front {
		p.chainState.delCh <- struct{}{}
	}

	// // delete all files before front
	indexs := []int64{
		(p.front-1)/(p.setLen*p.clusterSize) + 1,  //idle-files-i
		(p.front-1)/p.clusterSize + 1,             //file-cluster-i
		(p.front-1)%p.clusterSize + p.Expanders.K, //sub-file-i
	}

	err := deleter(IdleFilePath, indexs)
	if err != nil {
		return errors.Wrap(err, "delete idle files error")
	}
	return nil
}

func (p *Prover) calcGeneratedFile(dir string) (int64, error) {

	count := int64(0)
	fileTotalSize := FileSize * (p.Expanders.K + p.clusterSize) * 1024 * 1024
	rootSize := (p.setLen*(p.Expanders.K+p.clusterSize) + 1) * int64(tree.DEFAULT_HASH_SIZE)
	entries, err := ioutil.ReadDir(dir)
	next := int64(1)
	if err != nil {
		return count, err
	}
	for _, entry := range entries {
		sidxs := strings.Split(entry.Name(), "-")
		if len(sidxs) < 3 {
			continue
		}
		if idx, err := strconv.ParseInt(sidxs[2], 10, 64); err != nil ||
			idx != p.rear/(p.setLen*p.clusterSize)+next {
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

		i := 0
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
				if !file.IsDir() && file.Size() >= MiniFileSize {
					size += file.Size()
				}
			}
			if size == fileTotalSize {
				count += p.clusterSize
				i++
			}
		}
		if i == int(p.setLen) {
			next += 1
		}
	}
	return count, nil
}

func deleter(rootDir string, indexs []int64) error {
	if len(indexs) <= 0 {
		return nil
	}
	entrys, err := os.ReadDir(rootDir)
	if err != nil {
		return err
	}
	for _, entry := range entrys {
		names := strings.Split(entry.Name(), "-")
		idx, err := strconv.Atoi(names[len(names)-1])
		if err != nil {
			continue
		}
		if int64(idx) < indexs[0] || (int64(idx) == indexs[0] && !entry.IsDir()) {
			if err := util.DeleteDir(
				path.Join(rootDir, entry.Name())); err != nil {
				return err
			}
			continue
		}
		if int64(idx) != indexs[0] {
			continue
		}
		err = deleter(path.Join(rootDir, entry.Name()), indexs[1:])
		if err != nil {
			return err
		}
	}
	return nil
}
