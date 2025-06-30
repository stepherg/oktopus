FROM golang:1.23 AS builder
WORKDIR /app
COPY ../ .
RUN CGO_ENABLED=0 GOOS=linux go build -o webpa cmd/webpa/main.go

FROM alpine:latest
COPY --from=builder /app/webpa /
ENTRYPOINT ["/webpa"]