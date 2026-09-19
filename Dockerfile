# Server image. The same image is later converted into a Nitro Enclave image
# (nitro-cli build-enclave), so everything the server trusts (registry,
# publisher key) is baked in and therefore covered by the enclave measurement.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w -buildid=' -o /out/trustgate-server ./cmd/trustgate-server

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/trustgate-server /trustgate-server
COPY registry/manifests /registry
COPY .trustgate-dev/publisher.pub /publisher.pub
EXPOSE 8080
ENTRYPOINT ["/trustgate-server", "-registry", "/registry", "-publisher-pub-file", "/publisher.pub", "-addr", ":8080"]
# Default is INSECURE local dev mode. On Nitro, run with: -mode nitro
CMD ["-mode", "dev", "-dev-dir", "/tmp/dev"]
