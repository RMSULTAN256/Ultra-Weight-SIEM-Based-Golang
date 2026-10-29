package main

import (
	"fmt"
	"io"
	"net/http"
)

func main() {

}

func getRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Println("got / request root")
	io.WriteString(w, "Hello hello")
}

func getHello(w http.ResponseWriter, r *http.Request) {
	fmt.Println("got /hello request")
	io.WriteString(w, "Hello World")
}
