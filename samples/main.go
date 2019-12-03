package main

import (
	"crypto/rsa"
	"fmt"
	"gopkg.in/square/go-jose.v2"
)

// Class for test cases during development
func main() {
	var something interface{}

	//bytes, e := ioutil.ReadFile("samples/rsa-publickey.txt")
	//if e != nil {
	//	log.Fatal(e)
	//}

	myKey := jwk{
		e: "AQAB",
		n: "j9XvbTYr3uXbkrAM10zQmOXkt4Gaj-SKZHbOK1y_eIdvrZge_LeSKVIgce6ZtC5b7F3HfJ1TAPy2kCSfusQ-P17egl6ka6-kMvPhDltWnurgAgfjDPnt6NckHxadut7L_-s9kd2L84GO-PznvcHGbc8ntTjtlgLmxDq-gZgCJKJqhWM3NYifUkLbbQT-c4dK6my-JtNyuye2fd2cR_G7IQE1UrZm7zqu9DttjN5A-R1eLYmtTuTC3xSHRCLVks6OyzIjzXP1TcyxXUvbwZWD6LpTidcapztRcwckO_AJHsztAvtC2hsPbl03lKzloHqQeRSEWVzRcgtK5ViRxcH7VQ",
	}
	var key jose.JSONWebSignature
	something = myKey

	fmt.Printf("string: %s\n", something)

	key := something.(*rsa.PublicKey)
	fmt.Println(key)

	//s := "foo"
	//var test *string
	//test = &s
	//fmt.Println(s)
	//fmt.Println(test)
	//fmt.Println(*test)
	//
	//ss := "bar"
	//var test2 *string
	//
	//test2 = &ss
	//*test = *test2
	//
	//fmt.Println(s)
	//fmt.Println(test)
	//
	//fmt.Println(ss)
	//fmt.Println(test2)
}

type jwk struct {
	kty string
	e   string
	n   string
	use string
	kid string
	alg string
}
