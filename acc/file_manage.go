package acc

import (
	"encoding/json"
	"fmt"
	"io"
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
func deleteAccData(dir string, last int) error {
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

func cleanBackup(dir string, index int) error {
	backup := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_BACKUP_NAME, index))
	err := util.DeleteFile(backup)
	return errors.Wrap(err, "clean backup error")
}

func backupAccData(dir string, index int) error {
	fpath := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_NAME, index))
	backup := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_BACKUP_NAME, index))
	bf, err := os.Create(backup)
	if err != nil {
		return errors.Wrap(err, "backup element data error")
	}
	defer bf.Close()
	sf, err := os.Open(fpath)
	if err != nil {
		return errors.Wrap(err, "backup element data error")
	}
	defer sf.Close()
	_, err = io.Copy(bf, sf)
	return errors.Wrap(err, "backup element data error")
}

func recoveryAccData(dir string, index int) error {
	backup := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_BACKUP_NAME, index))
	fpath := path.Join(dir, fmt.Sprintf("%s-%d", DEFAULT_NAME, index))

	err := os.Rename(backup, fpath)
	return errors.Wrap(err, "recovery element data error")
}

func GetRecoveryFileNum(dpath string) (int64, error) {
	var num int64
	entrys, err := os.ReadDir(dpath)
	if err != nil {
		return num, err
	}

	for i := 0; i < len(entrys); i++ {
		splitNames := strings.Split(entrys[i].Name(), "-")
		name := splitNames[len(splitNames)-1]
		index, err := strconv.Atoi(name)
		if err != nil {
			return num, err
		}
		files, err := readAccData(dpath, index)
		if err != nil {
			return num, err
		}
		num += int64(len(files.Values))
	}

	return num, nil
}
