FROM docker.io/library/golang AS builder
WORKDIR /app
COPY ../ .
RUN CGO_ENABLED=0 GOOS=linux go build -o mqtt-adapter cmd/mqtt-adapter/main.go

FROM alpine:latest
COPY --from=builder /app/mqtt-adapter /
ENTRYPOINT ["/mqtt-adapter"]