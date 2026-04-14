FROM docker.io/library/golang AS builder
WORKDIR /app
COPY ../ .
RUN CGO_ENABLED=0 GOOS=linux go build -o controller cmd/controller/main.go

FROM alpine:latest
COPY --from=builder /app/controller /
ENTRYPOINT ["/controller"]