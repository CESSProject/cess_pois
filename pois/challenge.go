package pois

import (
	"crypto/rand"
	"math/big"

	"github.com/CESSProject/cess_pois/expanders"
	"github.com/pkg/errors"
)

func (v *Verifier) CommitChallenges(pNode ProverNode) ([][]int64, error) {

	challenges := make([][]int64, IdleSetLen) //
	start := (pNode.CommitsBuf.FileIndexs[0] - 1) / ClusterSize
	for i := int64(0); i < IdleSetLen; i++ { //
		challenges[i] = make([]int64, v.Expanders.K+ClusterSize+1) //
		challenges[i][0] = start + i + 1                           // calculate file cluster id
		//
		for j := 1; j <= int(ClusterSize); j++ {
			r, err := rand.Int(rand.Reader, new(big.Int).SetInt64(v.Expanders.N))
			if err != nil {
				return nil, errors.Wrap(err, "generate commit challenges error")
			}
			r.Add(r, new(big.Int).SetInt64(v.Expanders.N*v.Expanders.K))
			challenges[i][j] = r.Int64()
		}

		r, err := rand.Int(rand.Reader, new(big.Int).SetInt64(v.Expanders.N))
		if err != nil {
			return nil, errors.Wrap(err, "generate commit challenges error")
		}
		r.Add(r, new(big.Int).SetInt64(v.Expanders.N*(v.Expanders.K-1)))
		challenges[i][ClusterSize+1] = r.Int64()

		for j := int(ClusterSize + 2); j < len(challenges[i]); j++ { //
			r, err := rand.Int(rand.Reader, new(big.Int).SetInt64(v.Expanders.D+1))
			if err != nil {
				return nil, errors.Wrap(err, "generate commit challenges error")
			}
			challenges[i][j] = r.Int64()
		}
		//
	}
	return challenges, nil
}

func (v *Verifier) SpaceChallenges(param int64) ([]int64, error) {
	//Randomly select several nodes from idle files as random challenges
	if param < SpaceChals {
		param = SpaceChals
	}
	challenges := make([]int64, param)
	mp := make(map[int64]struct{})
	for i := int64(0); i < param; i++ {
		for {
			r, err := rand.Int(rand.Reader, new(big.Int).SetInt64(v.Expanders.N))
			if err != nil {
				return nil, errors.Wrap(err, "generate commit challenges error")
			}
			if _, ok := mp[r.Int64()]; ok {
				continue
			}
			mp[r.Int64()] = struct{}{}
			r.Add(r, new(big.Int).SetInt64(v.Expanders.N*v.Expanders.K))
			challenges[i] = r.Int64()
			break
		}
	}
	return challenges, nil
}

func (p *Prover) NewChallengeHandle(teeID []byte, chal []int64) func([]byte) (int64, int64) {

	bytesChal := expanders.GetBytes(chal)
	frontSize := len(p.ID) + len(teeID) + len(bytesChal)
	source := make([]byte, 0, frontSize+32)
	source = append(source, p.ID...)
	source = append(source, teeID...)
	source = append(source, bytesChal...)

	fileNum := p.setLen * p.clusterSize
	number := int64(DEFAULT_CHAL_GROUP_NUM)

	front, rear := p.chainState.Front, p.chainState.Rear
	groupSize := 16 * (number / fileNum)
	start, count, total := front/fileNum, int64(0), (rear-front+front%fileNum)/(fileNum*groupSize)

	return func(priorHash []byte) (left int64, right int64) {
		if count >= total {
			return 0, 0
		}
		if len(priorHash) > 0 {
			copy(source[frontSize:], priorHash)
		}
		hash := expanders.GetHash(source)
		v := int64(expanders.BytesToNodeValue(hash, groupSize-(number/fileNum)))

		left = (start + count*groupSize + v) * fileNum
		right = (left/fileNum)*fileNum + number
		if left < front {
			left = front
		}
		count++
		return left, right
	}

}

func NewChallengeHandle(minerID, teeID []byte, chal []int64, front, rear, proofNum int64) func([]byte, int64, int64) bool {

	bytesChal := expanders.GetBytes(chal)
	frontSize := len(minerID) + len(teeID) + len(bytesChal)
	source := make([]byte, 0, frontSize+32)
	source = append(source, minerID...)
	source = append(source, teeID...)
	source = append(source, bytesChal...)

	fileNum := int64(256)
	groupSize := int64(16)
	start, count, total := front/fileNum, int64(0), (rear-front+front%fileNum)/(fileNum*groupSize)

	if total > proofNum {
		return nil
	}

	return func(priorHash []byte, left, right int64) bool {
		if len(priorHash) > 0 {
			copy(source[frontSize:], priorHash)
		}
		hash := expanders.GetHash(source)
		v := int64(expanders.BytesToNodeValue(hash, groupSize-1))

		l := (start + count*groupSize + v) * fileNum
		r := (l/fileNum)*fileNum + 256
		if l < front {
			l = front
		}
		count++
		if l != left || r != right {
			return false
		}
		return true
	}
}
