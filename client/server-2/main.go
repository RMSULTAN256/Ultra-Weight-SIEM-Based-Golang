package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next(w, r)
		duration := time.Since(start)

		logLine := fmt.Sprintf("[%s] %s %s %s %v\n",
			time.Now().Format("2006-01-02 15:04:05"),
			r.RemoteAddr,
			r.Method,
			r.URL.Path,
			duration,
		)

		f, err := os.OpenFile("/app/logs/app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.WriteString(logLine)
			f.Close()
		}
	}
}

func main() {
	_ = os.MkdirAll("/app/logs", 0755)

	http.HandleFunc("/", loggingMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Node 2: Catalog API Online\n"))
	}))

	http.HandleFunc("/products", loggingMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"id":1,"name":"Item A"},{"id":2,"name":"Item B"}]` + "\n"))
	}))

	fmt.Println("Server 2 (Catalog) listening on :3000...")
	log.Fatal(http.ListenAndServe(":3000", nil))
}
