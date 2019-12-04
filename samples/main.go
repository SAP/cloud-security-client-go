package main

import (
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.wdf.sap.corp/CPSecurity/go-cloud-security-integration/core"
	"github.wdf.sap.corp/CPSecurity/go-cloud-security-integration/env"
	"log"
	"net/http"
	"os"
)

// Class for test cases during development
func main() {
	r := mux.NewRouter()
	middleware := core.New(core.Options{
		UserContext:  "user",
		OAuthConfig:  env.GetIASConfig(),
		ErrorHandler: nil,
	})
	r.Use(middleware.Handler)

	r.HandleFunc("/helloWorld", helloWorld).Methods("GET")

	address := ":8080"
	log.Println("Starting server on address", address)
	err := http.ListenAndServe(address, handlers.LoggingHandler(os.Stdout, r))
	if err != nil {
		panic(err)
	}

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

func helloWorld(w http.ResponseWriter, r *http.Request) {
	context := r.Context().Value("user")
	user, ok := context.(*core.OIDCClaims)
	if !ok {
		log.Fatal("not ok")
	}
	email := user.Email
	_, _ = w.Write([]byte(fmt.Sprintf("Hello world %s ! \n You're logged in as %s", r.Header.Get("X-Forwarded-For"), email)))
}
