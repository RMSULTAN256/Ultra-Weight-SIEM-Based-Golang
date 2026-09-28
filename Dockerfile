# Stage 1: Build binary Go
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY ./CenterServer ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o CenterServer-app .

# Stage 2: Runtime CentOS
FROM quay.io/centos/centos:stream8
WORKDIR /app
COPY --from=builder /app/CenterServer .
COPY .env .
EXPOSE 3000
CMD ["./agentGo"]
