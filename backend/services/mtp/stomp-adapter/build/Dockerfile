FROM golang:1.24 AS builder
WORKDIR /app
COPY ../ .
RUN CGO_ENABLED=0 GOOS=linux go build -o stomp-adapter cmd/stomp-adapter/main.go

FROM alpine:latest
COPY --from=builder /app/stomp-adapter /
ENTRYPOINT ["/stomp-adapter"]