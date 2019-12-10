package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
)

type foo struct {
	bar *string
	yo  string
}

func main() {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	eBytes := make([]byte, 64)
	_ = binary.PutVarint(eBytes, int64(rsaKey.PublicKey.E))
	key := &jwkPlayground{
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.PublicKey.E)).Bytes()),
		N: base64.RawURLEncoding.EncodeToString(rsaKey.PublicKey.N.Bytes()),
	}

	fmt.Println(key)

	//done := make(chan bool)
	//var mu sync.Mutex
	//
	//fmt.Println("Locking outer")
	//mu.Lock()
	//go func() {
	//	fmt.Println("Locking inner")
	//	mu.Lock()
	//	fmt.Println("Unlock inner")
	//	mu.Unlock()
	//	done<- true
	//}()
	//fmt.Println("Unlock outer")
	//mu.Unlock()
	//<-done

}

type jwkPlayground struct {
	E string
	N string
}

//func main() {
//	c := make(chan int)
//	quit := make(chan int)
//	go func() {
//		for i := 0; i < 10; i++ {
//			fmt.Println(<-c)
//		}
//		quit <- 0
//	}()
//	fibonacci(c, quit)
//}
