# Stage 1: Build
FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o web-app .

# Stage 2: Runtime ringan
FROM alpine:3.20
WORKDIR /app
RUN mkdir -p /app/logs
COPY --from=builder /app/web-app .
EXPOSE 3000
CMD ["./web-app"]
