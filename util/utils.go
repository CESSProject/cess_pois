package util

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	r "math/rand"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"
)

var CHARS = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
	"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
	"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"}

func SaveProofFile(path string, data [][]byte) error {
	file, err := os.Create(path)
	if err != nil {
		return errors.Wrap(err, "save proof file error")
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, d := range data {
		n, err := writer.Write(d)
		if err != nil || n != len(d) {
			err := errors.New(fmt.Sprint("write label error", err))
			return errors.Wrap(err, "write proof file error")
		}
		writer.Flush()
	}
	return nil
}

func ReadProofFile(path string, num, len int) ([][]byte, error) {
	if num <= 0 {
		err := errors.New("illegal label number")
		return nil, errors.Wrap(err, "read proof file error")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrap(err, "read proof file error")
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	data := make([][]byte, num)
	for i := 0; i < num; i++ {
		label := make([]byte, len)
		n, err := reader.Read(label)
		if err != nil || n != len {
			err := errors.New(fmt.Sprint("read label error", err))
			return nil, errors.Wrap(err, "read proof file error")
		}
		data[i] = label

	}
	return data, nil
}

func DeleteDir(dir string) error {
	return os.RemoveAll(dir)
}

func SaveFile(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	in := bufio.NewWriter(f)
	_, err = in.Write(data)
	in.Flush()
	return err
}

func DeleteFile(path string) error {
	return os.Remove(path)
}

func ReadFileToBuf(path string, buf []byte) error {
	if len(buf) <= 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	n, err := reader.Read(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return errors.New("byte number read does not match")
	}
	return nil
}

func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := bufio.NewReader(f)
	buffer := bytes.NewBuffer(nil)
	buf := make([]byte, 1024)
	for {
		n, err := out.Read(buf)
		if err != nil {
			return nil, err
		}
		if _, err = buffer.Write(buf[:n]); err != nil {
			return nil, err
		}
		if n < 1024 {
			break
		}
	}
	return buffer.Bytes(), nil
}

func RandString(lenNum int) string {
	str := strings.Builder{}
	length := 52
	for i := 0; i < lenNum; i++ {
		str.WriteString(CHARS[r.Intn(length)])
	}
	return str.String()
}

func CopyData(target []byte, src ...[]byte) {
	count, lens := 0, len(target)
	for _, d := range src {
		l := len(d)
		if l == 0 || l+count > lens {
			continue
		}
		count += l
		copy(target[count-l:count], d)
	}
}

func CopyFiles(src, des string) error {

	if _, err := os.Stat(des); err == nil {
		err = os.RemoveAll(des)
		if err != nil {
			return err
		}
	}

	if err := os.MkdirAll(des, 0777); err != nil {
		return err
	}

	files, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		sf, err := os.Open(path.Join(src, file.Name()))
		if err != nil {
			return err
		}
		df, err := os.Create(path.Join(des, file.Name()))
		if err != nil {
			return err
		}
		_, err = io.Copy(df, sf)
		sf.Close()
		df.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
