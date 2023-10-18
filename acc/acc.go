package acc

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"sync"
)

type RsaKey struct {
	N big.Int //Z/nZ
	G big.Int // Generator

}

// Generate N and G
// lamda is the bit size of N(preferably 2048 bit)
// Note that the primes factors of N are not exposed for security reason
func RsaKeygen(lambda int) RsaKey {

	pk, _ := rsa.GenerateKey(rand.Reader, lambda)
	var F *big.Int
	var err error
	N := pk.PublicKey.N

	for {
		F, err = rand.Int(rand.Reader, N)
		if new(big.Int).GCD(nil, nil, F, N).Cmp(big.NewInt(1)) == 0 && err == nil {
			break
		}
	}
	G := new(big.Int).Exp(F, big.NewInt(2), pk.PublicKey.N)
	return RsaKey{
		N: *N,
		G: *G,
	}
}

// Generate the accumulator
func GenerateAcc(key RsaKey, U [][]byte) []byte {

	Primes := make([]big.Int, len(U))
	G := key.G

	for i, u := range U {
		Primes[i] = Hprime(*big.NewInt(0).SetBytes(u))
		G.Exp(&G, &Primes[i], &key.N)
	}

	return G.Bytes()
}

func Verify(key RsaKey, acc, u, wit []byte) bool {
	e := Hprime(*big.NewInt(0).SetBytes(u))
	dash := new(big.Int).Exp(
		big.NewInt(0).SetBytes(wit),
		&e, &key.N)
	return dash.Cmp(big.NewInt(0).SetBytes(acc)) == 0
}

func GenerateWitness(G, N []byte, us [][]byte) [][]byte {
	if len(us) == 1 {
		return [][]byte{G}
	}
	n := big.NewInt(0).SetBytes(N)
	left, right := us[:len(us)/2], us[len(us)/2:]
	g1, g2 := *big.NewInt(0).SetBytes(G), *big.NewInt(0).SetBytes(G)
	sig := make(chan struct{}, 2)
	go func() {
		for _, u := range right {
			e := Hprime(*new(big.Int).SetBytes(u))
			g1.Exp(&g1, &e, n)
		}
		sig <- struct{}{}
	}()
	go func() {
		for _, u := range left {
			e := Hprime(*new(big.Int).SetBytes(u))
			g2.Exp(&g2, &e, n)
		}
		sig <- struct{}{}
	}()
	<-sig
	<-sig
	u1 := GenerateWitness(g1.Bytes(), N, left)
	u2 := GenerateWitness(g2.Bytes(), N, right)
	return append(u1, u2...)
}

// Generate the accumulator
func generateAcc(key RsaKey, acc []byte, elems [][]byte) []byte {
	if acc == nil {
		return nil
	}
	G := new(big.Int).SetBytes(acc)
	for _, elem := range elems {
		prime := Hprime(*new(big.Int).SetBytes(elem))
		G.Exp(G, &prime, &key.N)
	}
	return G.Bytes()
}

func generateWitness(G, N big.Int, us [][]byte) [][]byte {
	if len(us) == 0 {
		return nil
	}
	if len(us) == 1 {
		return [][]byte{G.Bytes()}
	}
	left, right := us[:len(us)/2], us[len(us)/2:]
	g1, g2 := G, G
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for _, u := range right {
			e := Hprime(*new(big.Int).SetBytes(u))
			g1.Exp(&g1, &e, &N)
		}
	}()
	go func() {
		defer wg.Done()
		for _, u := range left {
			e := Hprime(*new(big.Int).SetBytes(u))
			g2.Exp(&g2, &e, &N)
		}
	}()
	wg.Wait()
	u1 := generateWitness(g1, N, left)
	u2 := generateWitness(g2, N, right)
	return append(u1, u2...)
}

func genWitsForAccNodes(G, N big.Int, elems []*AccNode) {
	lens := len(elems)
	if lens <= 0 {
		return
	}
	if lens == 1 {
		elems[0].Wit = G.Bytes()
		return
	}
	left, right := elems[:lens/2], elems[lens/2:]
	g1, g2 := G, G
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for _, u := range right {
			e := Hprime(*new(big.Int).SetBytes(u.Value))
			g1.Exp(&g1, &e, &N)
		}
	}()
	go func() {
		defer wg.Done()
		for _, u := range left {
			e := Hprime(*new(big.Int).SetBytes(u.Value))
			g2.Exp(&g2, &e, &N)
		}
	}()
	wg.Wait()
	genWitsForAccNodes(g1, N, left)
	genWitsForAccNodes(g2, N, right)
}
