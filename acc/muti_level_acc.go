package acc

import (
	"bytes"
	"math"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
)

const (
	DEFAULT_PATH        = "./acc/"
	DEFAULT_DIR_PERM    = 0777
	DEFAULT_ELEMS_NUM   = 256
	DEFAULT_LEVEL       = 3
	DEFAULT_NAME        = "sub-acc"
	DEFAULT_BACKUP_NAME = "backup-sub-acc"
	TIMEOUT             = time.Minute * 2
)

type AccHandle interface {
	//get muti-level acc snapshot
	GetSnapshot() *MutiLevelAcc
	//add elements to muti-level acc and create proof of added elements
	AddElementsAndProof([][]byte) (*WitnessNode, [][]byte, error)
	//delete elements from muti-level acc and create proof of deleted elements
	DeleteElementsAndProof(int) (*WitnessNode, [][]byte, error)
	//GetWithessChains return witness chains of specified element
	GetWitnessChains(indexs []int64) ([]*WitnessNode, error)
	//UpdateSnapshot will update acc's snapshot,this method should be called after acc updated
	UpdateSnapshot() bool
	//RollBack will roll back acc to snapshot version,please use with caution
	RollBack() bool
}

var _AccManager *MutiLevelAcc

type AccNode struct {
	Value    []byte
	Children []*AccNode
	Len      int
	Wit      []byte
}

type AccData struct {
	Values [][]byte `json:"values"`
	Wits   [][]byte `json:"wits"`
}

type WitnessNode struct {
	Elem []byte       `json:"elem"`
	Wit  []byte       `json:"wit"`
	Acc  *WitnessNode `json:"acc"`
}

type MutiLevelAcc struct {
	Accs      *AccNode
	Key       RsaKey
	ElemNums  int
	Deleted   int // Deleted field always points to the next element to be deleted
	CurrCount int
	Curr      *AccNode
	Parent    *AccNode
	rw        *sync.RWMutex
	isUpdate  bool         //whether to update the muti-acc
	stable    bool         // whether the accumulator is in steady state
	isDel     *atomic.Bool //is the element being removed now
	snapshot  *MutiLevelAcc
	FilePath  string
}

// Recovery function be used to recovery muti-acc when a storage node goes down unexpectedly
func Recovery(accPath string, key RsaKey, front, rear int64) (AccHandle, error) {
	if accPath == "" {
		accPath = DEFAULT_PATH
	}
	if _, err := os.Stat(accPath); err != nil {
		err := os.MkdirAll(accPath, DEFAULT_DIR_PERM)
		if err != nil {
			return nil, errors.Wrap(err, "recovery muti-acc error")
		}
	}
	acc := &AccNode{
		Value: key.G.Bytes(),
	}
	_AccManager = &MutiLevelAcc{
		Accs:     acc,
		Key:      key,
		rw:       new(sync.RWMutex),
		FilePath: accPath,
		stable:   true,
		isDel:    new(atomic.Bool),
		Deleted:  int(front), //front refers to the number of elements that have been deleted
	}
	if err := _AccManager.constructMutiAcc(rear); err != nil {
		return nil, errors.Wrap(err, "recovery muti-acc error")
	}
	return _AccManager, nil
}

// NewMutiLevelAcc function be used to create a globally unique acc handle
func NewMutiLevelAcc(path string, key RsaKey) (AccHandle, error) {
	if path == "" {
		path = DEFAULT_PATH
	}
	if _, err := os.Stat(path); err != nil {
		err := os.MkdirAll(path, DEFAULT_DIR_PERM)
		if err != nil {
			return nil, err
		}
	}
	acc := &AccNode{
		Value: key.G.Bytes(),
	}
	_AccManager = &MutiLevelAcc{
		Accs:     acc,
		Key:      key,
		rw:       new(sync.RWMutex),
		isDel:    new(atomic.Bool),
		FilePath: path,
		stable:   true,
	}
	return _AccManager, nil
}

func GetAccHandle() AccHandle {
	return _AccManager
}

// GetSnapshot be used to get muti-acc's snapshot, if it is nil, will create a new snapshot and return.
// muti-acc's snapshot is a backup of current state of muti-acc,snapshot is not null unless muti-acc has never updated.
func (acc *MutiLevelAcc) GetSnapshot() *MutiLevelAcc {
	acc.rw.RLock()
	defer acc.rw.RUnlock()
	if acc.snapshot == nil {
		acc.createSnapshot()
	}
	return acc.snapshot
}

// UpdateSnapshot recreate the snapshot, and set the acc to steady state.
// This method needs to be called to solidify the update every time an muti-acc update is completed, and then it cannot be rolled back.
// Snapshot cannot be updated if the current muti-acc update is not complete. Method will return the update result of snapshot.
func (acc *MutiLevelAcc) UpdateSnapshot() bool {
	acc.rw.Lock()
	defer acc.rw.Unlock()
	if acc.isUpdate {
		return false
	}
	acc.createSnapshot()
	acc.stable = true
	//delete buckup file
	index := acc.Deleted / DEFAULT_ELEMS_NUM
	cleanBackup(acc.FilePath, index)
	return true
}

// RollBack be used to roll back muti-acc state when insert or delete elements error/fail.
// Rollback requires the support of snapshots, so when the snapshot is empty, the rollback will fail
func (acc *MutiLevelAcc) RollBack() bool {
	acc.rw.Lock()
	defer acc.rw.Unlock()
	if acc.isUpdate || acc.snapshot == nil {
		return false
	}
	acc.copy(acc.snapshot)
	acc.stable = true
	return true
}

func (acc *MutiLevelAcc) copy(other *MutiLevelAcc) {
	if other == nil {
		return
	}
	accs := &AccNode{}
	copyAccNode(other.Accs, accs)
	acc.Accs = accs
	acc.Key = other.Key
	acc.ElemNums = other.ElemNums
	acc.CurrCount = other.CurrCount
	if acc.Accs.Len > 0 {
		acc.Parent = acc.Accs.Children[acc.Accs.Len-1]
	}
	if acc.Parent != nil && acc.Parent.Len > 0 {
		acc.Curr = acc.Parent.Children[acc.Parent.Len-1]
	}
	acc.rw = other.rw
	acc.stable = other.stable
	acc.Deleted = other.Deleted
	acc.isDel = other.isDel
	acc.FilePath = other.FilePath
}

func copyAccNode(src *AccNode, target *AccNode) {
	if src == nil || target == nil {
		return
	}
	target.Value = make([]byte, len(src.Value))
	copy(target.Value, src.Value)
	target.Children = make([]*AccNode, len(src.Children))
	target.Len = src.Len
	target.Wit = make([]byte, len(src.Wit))
	copy(target.Wit, src.Wit)
	for i := 0; i < len(src.Children); i++ {
		target.Children[i] = &AccNode{}
		copyAccNode(src.Children[i], target.Children[i])
	}
}

func (acc *MutiLevelAcc) createSnapshot() {
	acc.snapshot = &MutiLevelAcc{}
	acc.snapshot.copy(acc)
}

func (acc *MutiLevelAcc) setUpdate(yes bool) bool {
	acc.rw.Lock()
	defer acc.rw.Unlock()
	//two or more updates at the same time are not allowed
	if yes && (acc.isUpdate || !acc.stable) {
		return false
	}
	if yes {
		acc.createSnapshot()
		acc.isUpdate = true
		acc.stable = false
		return true
	}
	//acc.createSnapshot()
	acc.isUpdate = false
	return true
}

// updateAcc update one sub acc and its elements' witness
func (acc *MutiLevelAcc) updateAcc(node *AccNode) {
	if node == nil {
		return
	}
	lens := len(node.Children)
	node.Len = lens
	if lens == 0 {
		node.Value = acc.Key.G.Bytes()
		node.Wit = nil
		return
	}
	genWitsForAccNodes(acc.Key.G, acc.Key.N, node.Children)
	last := node.Children[lens-1]
	node.Value = generateAcc(acc.Key, last.Wit, [][]byte{last.Value})
}

// AddElements add elements to sub-acc and update muti-acc.
func (acc *MutiLevelAcc) AddElements(elems [][]byte) error {

	lens := len(elems)
	// the range of length of elems be insert is (0,DEFAULT_ELEMS_NUM],
	// one insertion cannot exceed the range of one sub acc
	if lens <= 0 || acc.CurrCount < DEFAULT_ELEMS_NUM &&
		lens+acc.CurrCount > DEFAULT_ELEMS_NUM {
		err := errors.New("illegal number of elements")
		return errors.Wrap(err, "add elements error")
	}
	newAcc, err := acc.addElements(elems)
	if err != nil {
		return errors.Wrap(err, "add elements error")
	}
	acc.addSubAcc(newAcc)
	return nil
}

// addElements add elements to sub acc and seve elements' value and witness.
func (acc *MutiLevelAcc) addElements(elems [][]byte) (*AccNode, error) {
	var (
		data *AccData
		err  error
	)
	node := &AccNode{}
	if acc.CurrCount > 0 && acc.CurrCount < DEFAULT_ELEMS_NUM {
		index := (acc.Deleted + acc.ElemNums - 1) / DEFAULT_ELEMS_NUM //element label indexing starts from zero,the file index also starts from 0
		data, err = readAccData(acc.FilePath, index)
		if err != nil {
			return nil, errors.Wrap(err, "add elements to sub acc error")
		}
		data.Values = append(data.Values, elems...)
	} else {
		data = new(AccData)
		data.Values = elems
	}
	data.Wits = generateWitness(acc.Key.G, acc.Key.N, data.Values)
	node.Len = len(data.Values)
	node.Value = generateAcc(
		acc.Key, data.Wits[node.Len-1],
		[][]byte{data.Values[node.Len-1]},
	)
	index := ((acc.Deleted + acc.ElemNums + len(elems)) - 1) / DEFAULT_ELEMS_NUM //save to original file or new file(index +1)
	err = saveAccData(acc.FilePath, index, data.Values, data.Wits)
	return node, errors.Wrap(err, "add elements to sub acc error")
}

// addSubAccs inserts the sub acc built with new elements into the multilevel accumulator
func (acc *MutiLevelAcc) addSubAcc(subAcc *AccNode) {
	//acc.CurrCount will be equal to zero when the accumulator is empty,otherwise it will just be greater than 0.
	if acc.CurrCount == 0 {
		acc.Curr = subAcc
		acc.CurrCount = acc.Curr.Len
		acc.Curr.Wit = acc.Key.G.Bytes()
		acc.Parent = &AccNode{
			Value:    generateAcc(acc.Key, acc.Key.G.Bytes(), [][]byte{subAcc.Value}),
			Wit:      acc.Key.G.Bytes(),
			Children: []*AccNode{subAcc},
			Len:      1,
		}
		acc.Accs = &AccNode{
			Value:    generateAcc(acc.Key, acc.Key.G.Bytes(), [][]byte{acc.Parent.Value}),
			Children: []*AccNode{acc.Parent},
			Len:      1,
		}
		acc.ElemNums += acc.CurrCount
		return
	}
	//The upper function has judged that acc.CurrCount+elemNums is less than or equal DEFAULT_ELEMS_NUM
	if acc.CurrCount > 0 && acc.CurrCount < DEFAULT_ELEMS_NUM {
		acc.ElemNums += subAcc.Len - acc.CurrCount //sub acc container old elements and new elements
		lens := len(acc.Parent.Children)
		acc.Parent.Children[lens-1] = subAcc //directly replace the old sub acc
	} else if len(acc.Parent.Children)+1 <= DEFAULT_ELEMS_NUM { //if it is new sub acc and the parent acc is not full, insert the sub acc directly into it.
		acc.ElemNums += subAcc.Len
		acc.Parent.Children = append(acc.Parent.Children, subAcc)
	} else { //insert sub acc to new parent acc and insert parent acc to top acc.
		acc.ElemNums += subAcc.Len
		node := &AccNode{
			Wit:      acc.Key.G.Bytes(),
			Children: []*AccNode{subAcc},
		}
		acc.Accs.Children = append(acc.Accs.Children, node)
		acc.Parent = node
	}
	acc.Curr = subAcc
	acc.CurrCount = acc.Curr.Len
	//update sibling witness and parent acc
	acc.updateAcc(acc.Parent)
	//update parents and top acc
	acc.updateAcc(acc.Accs)
}

// DeleteElements delete elements from head sub acc and update the muti-acc.
func (acc *MutiLevelAcc) DeleteElements(num int) error {

	index := acc.Deleted / DEFAULT_ELEMS_NUM  //the file index of the next element to be deleted
	offset := acc.Deleted % DEFAULT_ELEMS_NUM //the number of deleted elements under the current sub acc
	if num <= 0 || num > acc.ElemNums || num+offset > DEFAULT_ELEMS_NUM {
		err := errors.New("illegal number of elements")
		return errors.Wrap(err, "delete elements error")
	}

	//read data from disk
	data, err := readAccData(acc.FilePath, index)
	if err != nil {
		return errors.Wrap(err, "delet elements error")
	}
	//buckup file
	err = backupAccData(acc.FilePath, index)
	if err != nil {
		return errors.Wrap(err, "delet elements error")
	}

	//delete elements from sub acc and update muti-acc
	if num < len(data.Values) { //
		data.Values = data.Values[num:]
		data.Wits = generateWitness(acc.Key.G, acc.Key.N, data.Values)
		err = saveAccData(acc.FilePath, index, data.Values, data.Wits)
		if err != nil {
			return errors.Wrap(err, "delet elements error")
		}
		acc.Accs.Children[0].Children[0].Len -= num
		len := acc.Accs.Children[0].Children[0].Len
		acc.Accs.Children[0].Children[0].Value = generateAcc(
			acc.Key, data.Wits[len-1],
			[][]byte{data.Values[len-1]})
	} else {

		if err = deleteAccData(acc.FilePath, index); err != nil {
			return errors.Wrap(err, "delet elements error")
		}

		//update parent acc
		acc.Accs.Children[0].Children = acc.Accs.Children[0].Children[1:]
		acc.Accs.Children[0].Len -= 1
		if acc.Accs.Children[0].Len == 0 && acc.Accs.Len >= 1 {
			acc.Accs.Children = acc.Accs.Children[1:]
			acc.Accs.Len -= 1
		}

		//update top acc
		if acc.Accs.Len == 0 {
			acc.Parent = nil
			acc.Curr = nil
			acc.CurrCount = 0
		}
	}
	acc.ElemNums -= num
	//update sibling witness and parent acc
	acc.updateAcc(acc.Parent)
	//update parents and top acc
	acc.updateAcc(acc.Accs)
	acc.Deleted += num
	return nil
}

// GetWitnessChains be used to get elements witness from sub acc to top acc (called witness chain)
func (acc *MutiLevelAcc) GetWitnessChains(indexs []int64) ([]*WitnessNode, error) {
	var err error
	snapshot := acc.GetSnapshot()
	chains := make([]*WitnessNode, len(indexs))
	for i := 0; i < len(indexs); i++ {
		chains[i], err = snapshot.getWitnessChain(indexs[i])
		if err != nil {
			return nil, errors.Wrap(err, "get witness chains error")
		}
	}
	return chains, nil
}

// getWitnessChain get one element witness chain.
func (acc *MutiLevelAcc) getWitnessChain(index int64) (*WitnessNode, error) {
	if index <= int64(acc.Deleted) || index > int64(acc.Deleted+acc.ElemNums) {
		return nil, errors.New("bad index")
	}
	data, err := readAccData(acc.FilePath, int((index-1)/DEFAULT_ELEMS_NUM))
	if err != nil {
		return nil, err
	}
	idx := (index - int64(DEFAULT_ELEMS_NUM-len(data.Values)) - 1) % DEFAULT_ELEMS_NUM //calc label index in acc file
	index -= int64(acc.Deleted)
	p := acc.Accs
	var wit *WitnessNode
	i := 0
	for ; i < DEFAULT_LEVEL; i++ {
		wit = &WitnessNode{
			Elem: p.Value,
			Wit:  p.Wit,
			Acc:  wit,
		}
		size := int64(math.Pow(DEFAULT_ELEMS_NUM, float64(DEFAULT_LEVEL-i-1)))
		idx := (index - 1) / size //get the position of the element in upper acc
		idx = idx % DEFAULT_ELEMS_NUM
		if len(p.Children) < int(idx+1) || p.Children == nil { //wrong acc or index data
			continue
		}
		p = p.Children[idx]
	}
	wit = &WitnessNode{
		Elem: data.Values[idx],
		Wit:  data.Wits[idx],
		Acc:  wit,
	}
	return wit, nil
}

// DeleteElementsAndProof delete elements from muti-level acc and create proof of deleted elements
func (acc *MutiLevelAcc) DeleteElementsAndProof(num int) (*WitnessNode, [][]byte, error) {

	if acc.ElemNums == 0 {
		err := errors.New("delete null set")
		return nil, nil, errors.Wrap(err, "proof acc delete error")
	}
	//Before deleting elements, get their chain of witness
	exist := &WitnessNode{
		Elem: acc.Accs.Children[0].Children[0].Value,
		Wit:  acc.Accs.Children[0].Children[0].Wit,
		Acc: &WitnessNode{
			Elem: acc.Accs.Children[0].Value,
			Wit:  acc.Accs.Children[0].Wit,
			Acc:  &WitnessNode{Elem: acc.Accs.Value},
		},
	}

	snapshot := acc.GetSnapshot()

	acc.isDel.Store(true)
	for !acc.setUpdate(true) {
		time.Sleep(time.Second * 2)
	}
	acc.isDel.Store(false)
	defer acc.setUpdate(false)

	err := acc.DeleteElements(num)
	if err != nil {
		return nil, nil, errors.Wrap(err, "proof acc delete error")
	}
	//computes the new accumulators generated after removing elements,
	//when deleting element requires deleting an empty accumulator at the same time,
	//the corresponding new accumulator is G
	accs := make([][]byte, DEFAULT_LEVEL)
	accs[DEFAULT_LEVEL-1] = acc.Accs.Value
	count := 1
	for p, q := acc.Accs, snapshot.Accs; p != nil && q != nil && count < DEFAULT_LEVEL; {
		if p.Len < q.Len {
			for i := DEFAULT_LEVEL - count - 1; i >= 0; i-- {
				accs[i] = acc.Key.G.Bytes()
			}
			break
		}
		count++
		p, q = p.Children[0], q.Children[0]
		accs[DEFAULT_LEVEL-count] = p.Value
	}
	return exist, accs, nil
}

// AddElementsAndProof add elements to muti-level acc and create proof of added elements
func (acc *MutiLevelAcc) AddElementsAndProof(elems [][]byte) (*WitnessNode, [][]byte, error) {
	snapshot := acc.GetSnapshot()
	exist := &WitnessNode{Elem: snapshot.Accs.Value}

	for acc.isDel.Load() || !acc.setUpdate(true) {
		time.Sleep(time.Second * 2)
	}
	defer acc.setUpdate(false)

	err := acc.AddElements(elems)
	if err != nil {
		return nil, nil, errors.Wrap(err, "proof acc insert error")
	}
	//the proof of adding elements consists of two parts,
	//the first part is the witness chain of the bottom accumulator where the element is located,
	//witness chain node is a special structure(Elem(acc value) is G,Wit is parent node's Elem)
	//when inserting an element needs to trigger the generation of a new accumulator,
	//the second part is an accumulator list, which contains the accumulator value
	//recalculated from the bottom to the top after inserting elements
	count := 1
	for p, q := acc.Accs, snapshot.Accs; p != nil && q != nil && count < DEFAULT_LEVEL; {
		if p.Len > q.Len {
			for i := count; i < DEFAULT_LEVEL; i++ {
				exist = &WitnessNode{Acc: exist}
				exist.Elem, exist.Wit = acc.Key.G.Bytes(), exist.Acc.Elem
			}
			break
		}
		count++
		p, q = p.Children[p.Len-1], q.Children[q.Len-1]
		exist = &WitnessNode{Acc: exist}
		exist.Elem, exist.Wit = q.Value, q.Wit
	}
	p := acc.Accs
	accs := make([][]byte, DEFAULT_LEVEL)
	for i := 0; i < DEFAULT_LEVEL; i++ {
		accs[DEFAULT_LEVEL-i-1] = p.Value
		if p.Children != nil {
			p = p.Children[p.Len-1]
		}
	}
	return exist, accs, nil
}

// constructMutiAcc be used to restore muti-acc from sub-acc files
func (acc *MutiLevelAcc) constructMutiAcc(rear int64) error {
	//acc is empty
	if rear == int64(acc.Deleted) {
		return nil
	}
	fileNum, err := GetRecoveryFileNum(acc.FilePath) //get accumulator tag number for all logged files
	if err != nil {
		return err
	}
	num := (int(rear) - acc.Deleted - 1) / DEFAULT_ELEMS_NUM //number of underlying accumulators,the "-1" operation is to correspond to the accumulator element index[0,N)
	offset := acc.Deleted % DEFAULT_ELEMS_NUM                //the relative position of the element to be deleted as an offset
	for i := 0; i <= num; i++ {
		index := acc.Deleted/DEFAULT_ELEMS_NUM + i     //sub-acc file index
		backup, err := readBackup(acc.FilePath, index) //read sub-acc file backup

		//if the backup does not exist or is inconsistent with the actual, it means that the program crashed after the accumulator was updated and stabilized
		if err != nil || len(backup.Values)+offset != DEFAULT_ELEMS_NUM {
			backup, err = readAccData(acc.FilePath, index) //so the correct set of elements is recorded in the sub-acc file
			if err != nil {
				return err
			}
		} else { //if the program crashes before the accumulator update is complete, the backup file needs to be restored to the sub-acc file
			err = recoveryAccData(acc.FilePath, index)
			if err != nil {
				return err
			}
		} //backup file records the state of the accumulator before it is updated. If the accumulator is down before the update is completed, the update will be invalid
		node := &AccNode{}
		if fileNum != rear-int64(acc.Deleted) { //
			left, right := 0, len(backup.Values)
			if i == 0 && offset > 0 && //The recorded value is inconsistent with the value to be restored and needs to be normalized
				(len(backup.Values) == DEFAULT_ELEMS_NUM || DEFAULT_ELEMS_NUM-offset < len(backup.Values)) {
				left = acc.Deleted%DEFAULT_ELEMS_NUM - (DEFAULT_ELEMS_NUM - len(backup.Values)) //sub real file offset
			}
			if i == num && rear%DEFAULT_ELEMS_NUM != 0 { //when the recovery is consistent with the record, right=len(backup.Values), otherwise the rear will prevail
				right = int((rear-1)%DEFAULT_ELEMS_NUM + 1)
			}
			backup.Values = backup.Values[left:right]
		}
		node.Len = len(backup.Values)
		node.Value = generateAcc(
			acc.Key, acc.Key.G.Bytes(),
			backup.Values,
		)
		acc.addSubAcc(node)
		if i == 0 && offset > 0 { //Restore the deleted state,consistent with before recovery
			acc.CurrCount += acc.Deleted % DEFAULT_ELEMS_NUM
		}
	}
	return nil
}

// Accumulator validation interface

func VerifyAcc(key RsaKey, acc, u, wit []byte) bool {
	e := Hprime(*new(big.Int).SetBytes(u))
	dash := new(big.Int).Exp(
		big.NewInt(0).SetBytes(wit),
		&e, &key.N,
	)
	return dash.Cmp(new(big.Int).SetBytes(acc)) == 0
}

// VerifyMutilevelAcc uses witness chains to realize the existence proof of elements in multi-level accumulators;
// The witness chain is the witness list from the bottom accumulator to the top accumulator (root accumulator)
func VerifyMutilevelAcc(key RsaKey, wits *WitnessNode, acc []byte) bool {
	for wits != nil && wits.Acc != nil {
		if !VerifyAcc(key, wits.Acc.Elem, wits.Elem, wits.Wit) {
			return false
		}
		wits = wits.Acc
	}
	if wits == nil {
		return false
	}
	return bytes.Equal(wits.Elem, acc)
}

func VerifyInsertUpdate(key RsaKey, exist *WitnessNode, elems, accs [][]byte, acc []byte) bool {
	if exist == nil || len(elems) == 0 || len(accs) < DEFAULT_LEVEL {
		return false
	}
	p := exist
	//if the condition is true, a new accumulator is inserted
	for p.Acc != nil && bytes.Equal(p.Acc.Elem, p.Wit) {
		p = p.Acc
	}
	//proof of the witness of accumulator elements,
	//when the element's accumulator does not exist, recursively verify its parent accumulator
	if !VerifyMutilevelAcc(key, p, acc) {
		return false
	}

	//verify that the newly generated accumulators after inserting elements
	//is calculated on the original accumulators
	subAcc := generateAcc(key, exist.Elem, elems)
	if !bytes.Equal(subAcc, accs[0]) {
		return false
	}
	p = exist
	count := 1
	for p != nil && p.Acc != nil {
		subAcc = generateAcc(key, p.Wit, [][]byte{accs[count-1]})
		if !bytes.Equal(subAcc, accs[count]) {
			return false
		}
		p = p.Acc
		count++
	}
	return true
}

func VerifyDeleteUpdate(key RsaKey, exist *WitnessNode, elems, accs [][]byte, acc []byte) bool {
	if exist == nil || len(elems) == 0 || len(accs) < DEFAULT_LEVEL {
		return false
	}
	//first need to verify whether the deleted elements are in the muti-level accumulator
	if !VerifyMutilevelAcc(key, exist, acc) {
		return false
	}
	subAcc := generateAcc(key, accs[0], elems)
	if !bytes.Equal(subAcc, exist.Elem) {
		return false
	}
	//then verify that the new accumulators is deleted on the original accumulators
	p := exist
	count := 1
	for p != nil && p.Acc != nil {
		if !bytes.Equal(accs[count-1], key.G.Bytes()) {
			subAcc = generateAcc(key, p.Wit, [][]byte{accs[count-1]})
		} else {
			subAcc = p.Wit
		}
		if !bytes.Equal(subAcc, accs[count]) {
			return false
		}
		p = p.Acc
		count++
	}
	return true
}
