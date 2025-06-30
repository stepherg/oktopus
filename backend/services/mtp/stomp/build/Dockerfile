FROM golang:1.23 AS builder
WORKDIR /app
COPY ../ .
RUN CGO_ENABLED=0 GOOS=linux go build -o stomp cmd/stomp/main.go

FROM alpine:latest
COPY --from=builder /app/stomp /
ENTRYPOINT ["/stomp"]