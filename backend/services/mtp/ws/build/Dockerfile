FROM golang:1.24 AS builder
WORKDIR /app
COPY ../ .
RUN CGO_ENABLED=0 GOOS=linux go build -o ws cmd/ws/main.go

FROM alpine:latest
COPY --from=builder /app/ws /
ENTRYPOINT ["/ws"]