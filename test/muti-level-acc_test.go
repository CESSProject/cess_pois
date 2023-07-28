package test

import (
	"testing"
	"time"

	"github.com/CESSProject/cess_pois/acc"
	"github.com/CESSProject/cess_pois/expanders"
	"github.com/CESSProject/cess_pois/util"
)

func TestMutiLevelAcc(t *testing.T) {
	size := 1024 * 1024 * 2
	data := make([][]byte, size)
	for i := 0; i < len(data); i++ {
		data[i] = expanders.GetHash([]byte(util.RandString(64)))
	}
	key := acc.RsaKeygen(2048)
	macc, err := acc.NewMutiLevelAcc("", key)
	if err != nil {
		t.Fatal("create new muti level acc error", err)
	}
	ts := time.Now()
	for i := 0; i < size/1024; i++ {
		oldAcc := macc.GetSnapshot().Accs.Value
		//test add elements and proof
		ts := time.Now()
		exist, accs, err := macc.AddElementsAndProof(data[i*1024 : (i+1)*1024])
		if err != nil {
			t.Fatal("add elements and generate proof error", err)
		}
		t.Log("add elements and proof time", time.Since(ts))
		macc.UpdateSnapshot()
		//test verify insert update
		ts = time.Now()
		if !acc.VerifyInsertUpdate(key, exist, data[i*1024:(i+1)*1024], accs, oldAcc) {
			t.Fatal("verify acc insert update error")
		}
		t.Log("verify insert proof time", time.Since(ts))
	}
	t.Log("------------------------------ total add elements time", time.Since(ts))
	ts = time.Now()
	for i := 0; i < size/1024; i++ {
		oldAcc := macc.GetSnapshot().Accs.Value
		//test delete elements and proof
		ts := time.Now()
		if i < 1023 {
			exist, accs, err := macc.DeleteElementsAndProof(1024 - i - 1)
			if err != nil {
				t.Fatal("delete elements and generate proof error", err)
			}
			t.Log("delete elements and proof time", time.Since(ts))
			//test verify delete update
			ts = time.Now()
			if !acc.VerifyDeleteUpdate(key, exist, data[size-(i+1)*1024+i+1:size-i*1024], accs, oldAcc) {
				t.Fatal("verify acc delete update error")
			}
			t.Log("verify delete proof time", time.Since(ts))
		}
		//delete 1 elems
		oldAcc = macc.GetSnapshot().Accs.Value
		//test delete elements and proof
		ts = time.Now()
		exist, accs, err := macc.DeleteElementsAndProof(i + 1)
		if err != nil {
			t.Fatal("delete elements and generate proof error", err)
		}
		t.Log("delete elements and proof time", time.Since(ts))
		macc.UpdateSnapshot()
		//test verify delete update
		ts = time.Now()
		if !acc.VerifyDeleteUpdate(key, exist, data[size-(i+1)*1024:size-(i+1)*1024+i+1], accs, oldAcc) {
			t.Fatal("verify acc delete update error")
		}
		t.Log("verify delete proof time", time.Since(ts))
	}
	t.Log("------------------------------ total delete elements time", time.Since(ts))
}

func TestDeleteAndProve(t *testing.T) {
	key := acc.RsaKeygen(2048)
	macc, err := acc.NewMutiLevelAcc("", key)
	if err != nil {
		t.Fatal("create new muti level acc error", err)
	}
	size := 102
	data := make([][]byte, size)
	for i := 0; i < len(data); i++ {
		data[i] = expanders.GetHash([]byte(util.RandString(64)))
	}

	oldAcc := macc.GetSnapshot().Accs.Value
	//test add elements and proof
	ts := time.Now()
	exist, accs, err := macc.AddElementsAndProof(data)
	if err != nil {
		t.Fatal("add elements and generate proof error", err)
	}
	t.Log("add elements and proof time", time.Since(ts))
	macc.UpdateSnapshot()
	//test verify insert update
	ts = time.Now()
	if !acc.VerifyInsertUpdate(key, exist, data, accs, oldAcc) {
		t.Fatal("verify acc insert update error")
	}
	t.Log("verify insert proof time", time.Since(ts))

	oldAcc = macc.GetSnapshot().Accs.Value
	//test delete elements and proof
	ts = time.Now()

	exist, accs, err = macc.DeleteElementsAndProof(11)
	if err != nil {
		t.Fatal("delete elements and generate proof error", err)
	}
	t.Log("delete elements and proof time", time.Since(ts))
	//test verify delete update
	ts = time.Now()
	if !acc.VerifyDeleteUpdate(key, exist, data[:11], accs, oldAcc) {
		t.Fatal("verify acc delete update error")
	}
	t.Log("verify delete proof time", time.Since(ts))

}
