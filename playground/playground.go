package main

import (
	"context"
	"fmt"
)

type foo struct {
	bar *string
	yo  string
}

func main() {

	context.Background()
	f := give()

	fmt.Println(f)
	fmt.Println(*f.bar)

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

func give() *foo {
	value := "Test"
	test := foo{
		bar: &value,
		yo:  "hi",
	}
	fmt.Println(test)
	fmt.Println(*test.bar)
	defer func(foo *foo) {
		v := "rekt"
		foo.bar = &v
		foo.yo = "rekt"
	}(&test)
	return &test
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
