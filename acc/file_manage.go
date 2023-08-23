package acc

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/CESSProject/cess_pois/util"

	"github.com/pkg/errors"
)

//tools

func saveAccData(dir string, index int, elems, wits [][]byte) error {
	data := AccData{
		Values: elems,
		Wits:   wits,
	}
	jbytes, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "save element data error")
	}
	fpath := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_NAME, index))
	return util.SaveFile(fpath, jbytes)
}

func readAccData(dir string, index int) (*AccData, error) {
	fpath := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_NAME, index))
	return readData(fpath)
}

func readBackup(dir string, index int) (*AccData, error) {
	fpath := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_BACKUP_NAME, index))
	return readData(fpath)
}

func readData(fpath string) (*AccData, error) {
	data, err := util.ReadFile(fpath)
	if err != nil {
		return nil, errors.Wrap(err, "read element data error")
	}
	accData := &AccData{}
	err = json.Unmarshal(data, accData)
	return accData, errors.Wrap(err, "read element data error")
}

// deleteAccData delete from the given index
func DeleteAccData(dir string, last int) error {
	fs, err := os.ReadDir(dir)
	if err != nil {
		return errors.Wrap(err, "delete element data error")
	}
	for _, f := range fs {
		slice := strings.Split(f.Name(), "-")
		index, err := strconv.Atoi(slice[len(slice)-1])
		if err != nil {
			return errors.Wrap(err, "delete element data error")
		}
		if index <= last {
			util.DeleteFile(path.Join(dir, f.Name()))
		}
	}
	return nil
}

func CleanBackup(dir string, index int) error {
	backup := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_BACKUP_NAME, index))
	err := util.DeleteFile(backup)
	return errors.Wrap(err, "clean backup error")
}

func backupAccData(dir string, index int) error {
	fpath := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_NAME, index))
	backup := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_BACKUP_NAME, index))
	return errors.Wrap(util.CopyFile(fpath, backup), "backup element data error")
}

func BackupAccDataForChall(src, des string, index int) error {
	fpath := path.Join(src, fmt.Sprintf("%s-%d", DEFAULT_NAME, index))
	backup := path.Join(des, fmt.Sprintf("%s-%d", DEFAULT_NAME, index))
	return errors.Wrap(util.CopyFile(fpath, backup), "backup acc data for challenge error")
}

func recoveryAccData(dir string, index int) error {
	backup := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_BACKUP_NAME, index))
	fpath := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_NAME, index))
	if _, err := os.Stat(backup); err != nil {
		return nil
	}
	err := os.Rename(backup, fpath)
	return errors.Wrap(err, "recovery element data error")
}
