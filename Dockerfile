FROM golang:latest as builder
WORKDIR /app
ADD go.mod .
ADD go.sum .
RUN apt-get update \
 && apt-get install -y libpcap-dev \
 && go mod download
ADD . .
RUN go build -o sklton-key

FROM debian
RUN apt-get update \
 && apt-get install -y libpcap-dev procps
COPY --from=builder /app/sklton-key /usr/bin/sklton-key
ENTRYPOINT ["sklton-key", "-tcpdump", "-cmd"]
