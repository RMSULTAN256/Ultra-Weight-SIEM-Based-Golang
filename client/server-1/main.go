package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// Middleware pencatat log request ke file
func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next(w, r)
		duration := time.Since(start)

		// Format log standar: [WAKTU] IP METHOD URL STATUS DURATION
		logLine := fmt.Sprintf("[%s] %s %s %s %v\n",
			time.Now().Format("2006-01-02 15:04:05"),
			r.RemoteAddr,
			r.Method,
			r.URL.Path,
			duration,
		)

		// Tulis ke file log shared volume
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
		w.Write([]byte("Node 1: Auth Service Online\n"))
	}))

	http.HandleFunc("/login", loggingMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"success","service":"auth"}` + "\n"))
	}))

	fmt.Println("Server 1 (Auth) listening on :3000...")
	log.Fatal(http.ListenAndServe(":3000", nil))
}
