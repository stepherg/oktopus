FROM golang:1.23 as builder
WORKDIR /app
COPY ../ .
RUN CGO_ENABLED=0 GOOS=linux go build -o adapter cmd/adapter/main.go

FROM alpine:latest
COPY --from=builder /app/adapter /
ENTRYPOINT ["/adapter"]