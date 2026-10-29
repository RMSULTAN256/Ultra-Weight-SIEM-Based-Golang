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
		w.Write([]byte("Node 3: Order Service Online\n"))
	}))

	http.HandleFunc("/order", loggingMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"order_id":"ORD-991","status":"created"}` + "\n"))
	}))

	fmt.Println("Server 3 (Order) listening on :3000...")
	log.Fatal(http.ListenAndServe(":3000", nil))
}
