FROM docker.io/library/golang AS builder
WORKDIR /app
COPY ../ .
RUN CGO_ENABLED=0 GOOS=linux go build -o taas cmd/taas/main.go

FROM alpine:latest
COPY --from=builder /app/taas /
ENTRYPOINT ["/taas"]
