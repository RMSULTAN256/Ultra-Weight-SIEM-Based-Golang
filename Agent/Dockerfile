# Stage 1: Compile binary agent
FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o agent-app .

# Stage 2: Runtime image super ringan (Alpine ~5MB)
FROM alpine:3.20
WORKDIR /app
RUN apk --no-cache add ca-certificates tzdata
COPY --from=builder /app/agent-app .

CMD ["./agent-app"]
