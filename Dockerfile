# syntax=docker/dockerfile:1

FROM golang:alpine as builder

# Set destination for COPY
WORKDIR /app

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/engine/reference/builder/#copy
COPY go.mod  *.go  ./
COPY  socks5 ./socks5

# Build
RUN go mod download && CGO_ENABLED=0 GOOS=linux go build -o socks5Server

# runner
FROM alpine:latest as runner

ENV PORT = 8080

WORKDIR /

COPY ./entrypoint.sh /

COPY --from=builder /app/socks5Server ./

# Optional:
# To bind to a TCP port, runtime parameters must be supplied to the docker command.
# But we can document in the Dockerfile what ports
# the application is going to listen on by default.
# https://docs.docker.com/engine/reference/builder/#expose
EXPOSE 8080

#ENTRYPOINT ["./entrypoint.sh"]
CMD ["./socks5Server -server -port=8080"]
