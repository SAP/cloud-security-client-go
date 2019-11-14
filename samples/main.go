package main

import "fmt"

// Class for test cases during development
func main() {
	s := "foo"
	var test *string
	test = &s
	fmt.Println(s)
	fmt.Println(test)
	fmt.Println(*test)

	ss := "bar"
	var test2 *string

	test2 = &ss
	*test = *test2

	fmt.Println(s)
	fmt.Println(test)

	fmt.Println(ss)
	fmt.Println(test2)
}
