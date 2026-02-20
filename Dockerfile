FROM golang:1.23-alpine AS build
WORKDIR /app
COPY src/go.mod src/go.sum ./
RUN go mod download
COPY src/ .
RUN go build -o firewall .

FROM alpine:3.20
COPY --from=build /app/firewall /usr/local/bin/
EXPOSE 11434 8080
ENTRYPOINT ["firewall"]
