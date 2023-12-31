package pois

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/CESSProject/cess_pois/acc"
	"github.com/CESSProject/cess_pois/expanders"
	"github.com/CESSProject/cess_pois/tree"
	"github.com/CESSProject/cess_pois/util"
	"github.com/pkg/errors"
)

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
	if !prover.generate.CompareAndSwap(false, true) {
		return errors.New("restore raw idle files error lock is occupied")
	}
	defer prover.generate.Store(false)

	start := (setId-1)*256/prover.clusterSize + 1

	if err := prover.Expanders.GenerateIdleFileSet(
		prover.ID, start, prover.setLen, IdleFilePath); err != nil {
		prover.space += (fileNum + prover.setLen*prover.Expanders.K) * FileSize
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
	roots, err := prover.CheckFilesAndGetTreeRoots(setId)
	if err != nil {
		return errors.Wrap(err, "restore sub acc files error")
	}
	if len(roots) == 0 {
		err := prover.RestoreRawIdleFiles(setId)
		if err != nil {
			return errors.Wrap(err, "restore sub acc files error")
		}
	}
	err = prover.AccManager.RestoreSubAccFile(int(setId-1), roots)
	if err != nil {
		return errors.Wrap(err, "restore sub acc files error")
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
	roots, count := make([][]byte, acc.DEFAULT_ELEMS_NUM), 0
	mht := make(tree.LightMHT, expanders.DEFAULT_AUX_SIZE)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		cluster, err := os.ReadDir(path.Join(filesDir, entry.Name()))
		if err != nil {
			return nil, err
		}
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
			aux, err := util.ReadFile(path.Join(filesDir, entry.Name(), info.Name()))
			if err != nil {
				return nil, err
			}
			mht.CalcLightMhtWithAux(aux)
			roots[count] = mht.GetRoot()
			count++
		}
	}
	if count != 256 {
		return nil, nil
	}
	return roots, nil
}
