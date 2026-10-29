# Stage 1: Build binary Go
FROM golang:1.26-alpine AS builder
ENV GOPROXY=https://goproxy.io,https://proxy.golang.org,direct
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server2-app .

# Stage 2: Runtime CentOS
FROM quay.io/centos/centos:stream8
WORKDIR /app
COPY --from=builder /app/server2-app .
EXPOSE 3001
CMD ["./server2-app"]
