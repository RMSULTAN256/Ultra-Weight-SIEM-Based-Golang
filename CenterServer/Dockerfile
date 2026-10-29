# Stage 1: Build binary Go
FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o CenterServer-app .

# Stage 2: Runtime super ringan
FROM alpine:3.20
WORKDIR /app
RUN apk --no-cache add ca-certificates tzdata
COPY --from=builder /app/CenterServer-app .
EXPOSE 8082
CMD ["./CenterServer-app"]
