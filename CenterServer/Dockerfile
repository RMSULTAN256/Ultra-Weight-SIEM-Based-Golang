# Stage 1: Build binary Go
FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o CenterServer-app .

# Stage 2: Runtime super ringan
FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -g 1000 appgroup && \
    adduser -u 1000 -G appgroup -s /bin/sh -D appuser
WORKDIR /app
COPY --from=builder --chown=appuser:appgroup /app/CenterServer-app .
USER appuser:appgroup
EXPOSE 8082
CMD ["./CenterServer-app"] 