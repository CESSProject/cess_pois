package pois

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/CESSProject/cess_pois/acc"
	"github.com/CESSProject/cess_pois/expanders"
	"github.com/CESSProject/cess_pois/tree"
	"github.com/CESSProject/cess_pois/util"
	"github.com/pkg/errors"
)

type FileList []fs.DirEntry

func (fl FileList) Len() int {
	return len(fl)
}
func (fl FileList) Less(i, j int) bool {
	tmp := strings.Split(fl[i].Name(), "-")
	idxi, _ := strconv.Atoi(tmp[len(tmp)-1])
	tmp = strings.Split(fl[j].Name(), "-")
	idxj, _ := strconv.Atoi(tmp[len(tmp)-1])
	return idxi < idxj
}
func (fl FileList) Swap(i, j int) {
	fl[i], fl[j] = fl[j], fl[i]
}

// RestoreIdleFiles method will restore damaged and proved idle files.
func (prover *Prover) RestoreIdleFiles(setId int64) error {
	if err := prover.RestoreRawIdleFiles(setId); err != nil {
		return errors.Wrap(err, "restore idle files error")
	}
	fileNum := prover.clusterSize * prover.setLen
	if err := prover.organizeFiles(setId*fileNum, fileNum); err != nil {
		return errors.Wrap(err, "restore idle files error")
	}
	return nil
}

// RestoreRawIdleFiles method will restore damaged and unporved idle files,
// this method usually be used to restore a small number of files before node restart.
func (prover *Prover) RestoreRawIdleFiles(setId int64) error {

	if setId < 1 {
		return errors.New("restore raw idle files error file set id error")
	}

	fileNum := prover.setLen * prover.clusterSize
	if prover.space < (fileNum+prover.setLen*prover.Expanders.K)*FileSize {
		return SpaceFullError
	}
	start := (setId-1)*256/prover.clusterSize + 1

	if err := prover.Expanders.GenerateIdleFileSet(
		prover.ID, start, prover.setLen, IdleFilePath); err != nil {
		return errors.Wrap(err, "restore raw idle files error")
	}

	return nil
}

// RestoreSubAccFiles method is used to recover damaged subaccumulator files.
// The output of this method may affect the final state of the multi-accumulator, please use it with caution.
// If the idle file of the specified set is damaged, this method will restore the file first.
func (prover *Prover) RestoreSubAccFiles(setId int64) error {

	rear := setId * prover.clusterSize * prover.setLen
	if rear > prover.rear || rear <= 0 {
		err := errors.New("bad set id")
		return errors.Wrap(err, "restore sub acc files error")
	}
	roots, _ := prover.CheckFilesAndGetTreeRoots(setId)
	if len(roots) != acc.DEFAULT_ELEMS_NUM {
		err := prover.RestoreIdleFiles(setId) //restore raw idle files and remove tempfile
		if err != nil {
			return errors.Wrap(err, "restore sub acc files error")
		}
		roots, err = prover.CheckFilesAndGetTreeRoots(setId)
		if err != nil {
			return errors.Wrap(err, "restore sub acc files error")
		}
	}
	labels := make([][]byte, len(roots))
	offset := int((setId - 1) * prover.setLen * prover.clusterSize)
	for i := 0; i < int(prover.setLen*prover.clusterSize); i++ {
		label := append([]byte{}, prover.ID...)
		label = append(label, expanders.GetBytes(int64(offset+i+1))...)
		labels[i] = expanders.GetHash(append(label, roots[i]...))
	}

	err := prover.AccManager.RestoreSubAccFile(int(setId-1), labels)
	if err != nil {
		return errors.Wrap(err, "restore sub acc files error")
	}
	return nil
}

func (prover *Prover) CheckAndRestoreSubAccFiles(front, rear int64) error {

	if front < 0 || front > rear {
		err := errors.New("bad front and rear value")
		return errors.Wrap(err, "check and restore sub acc files error")
	}
	start := front/acc.DEFAULT_ELEMS_NUM + 1
	end := rear / acc.DEFAULT_ELEMS_NUM
	for i := start; i <= end; i++ {
		fpath := path.Join(prover.AccManager.GetFilePath(), fmt.Sprintf("%s-%d", acc.DEFAULT_NAME, i-1))
		if _, err := os.Stat(fpath); err == nil {
			continue
		}
		err := prover.RestoreSubAccFiles(i)
		if err != nil {
			return errors.Wrap(err, "check and restore sub acc files error")
		}
	}
	return nil
}

// CheckAndRestoredIdleData is used to recover idle data in parallel
func (prover *Prover) CheckAndRestoreIdleData(front, rear int64, tNum int) error {

	if front < 0 || front > rear {
		err := errors.New("bad front and rear value")
		return errors.Wrap(err, "check and restore sub acc files error")
	}
	start := front/acc.DEFAULT_ELEMS_NUM + 1
	end := rear / acc.DEFAULT_ELEMS_NUM
	ch := make(chan int64)
	go func() {
		for i := start; i <= end; i++ {
			ch <- i
		}
		close(ch)
	}()
	wg := sync.WaitGroup{}
	wg.Add(tNum)
	var tErr error
	for j := 0; j < tNum; j++ {
		go func() {
			defer wg.Done()
			for {
				i, ok := <-ch
				if !ok {
					break
				}
				fpath := path.Join(prover.AccManager.GetFilePath(), fmt.Sprintf("%s-%d", acc.DEFAULT_NAME, i-1))
				if _, err := os.Stat(fpath); err == nil {
					continue
				}
				err := prover.RestoreSubAccFiles(i)
				if err != nil {
					tErr = errors.Wrap(err, "check and restore sub acc files error")
					log.Println(tErr)
					return
				}
			}
		}()
	}
	wg.Wait()
	if tErr != nil {
		return tErr
	}
	return nil
}

func (prover *Prover) CheckFilesAndGetTreeRoots(setId int64) ([][]byte, error) {

	filesDir := path.Join(
		IdleFilePath,
		fmt.Sprintf("%s-%d", expanders.SET_DIR_NAME, setId),
	)
	auxFSize := expanders.DEFAULT_AUX_SIZE * tree.DEFAULT_HASH_SIZE
	entries, err := os.ReadDir(filesDir)
	if err != nil {
		return nil, err
	}
	roots := make([][]byte, 0, acc.DEFAULT_ELEMS_NUM)
	mht := make(tree.LightMHT, auxFSize)

	sort.Sort(FileList(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		cluster, err := os.ReadDir(path.Join(filesDir, entry.Name()))
		if err != nil {
			return nil, err
		}

		sort.Sort(FileList(cluster))
		for _, file := range cluster {
			info, err := file.Info()
			if err != nil {
				return nil, err
			}
			if info.IsDir() || info.Size() != int64(auxFSize) {
				continue
			}
			tmp := strings.Split(info.Name(), "-")
			index, err := strconv.Atoi(tmp[len(tmp)-1])
			if err != nil {
				return nil, err
			}
			if index < int(prover.Expanders.K) {
				continue
			}
			aux := make([]byte, auxFSize)
			err = util.ReadFileToBuf(path.Join(filesDir, entry.Name(), info.Name()), aux)
			if err != nil {
				return nil, err
			}

			mht.CalcLightMhtWithAux(aux)
			roots = append(roots, mht.GetRoot())
		}
	}
	if len(roots) != int(prover.setLen*prover.clusterSize) {
		return nil, errors.New("error root number")
	}
	return roots, nil
}
