FROM docker.io/library/golang AS builder
WORKDIR /app
COPY ../ .
RUN CGO_ENABLED=0 GOOS=linux go build -o http-bulk-collector cmd/http-bulk-collector/main.go

FROM alpine:latest
COPY --from=builder /app/http-bulk-collector /
ENTRYPOINT ["/bulkdata"]