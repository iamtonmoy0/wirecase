FROM golang:1.22-alpine AS build
WORKDIR /src
COPY server.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /http-503 server.go

FROM scratch
COPY --from=build /http-503 /http-503
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/http-503"]
