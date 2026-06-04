# Build the manager binary
FROM golang:1.25 AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build
# the GOARCH has no default value to allow the binary to be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -a -ldflags "-s -w -X github.com/achetronic/tunnel/internal/version.Version=${VERSION}" -o manager cmd/main.go

# The operator pushes the static tunnelctl binary to each VPS over SSH, picking
# the one that matches the VPS architecture, so the image carries both arches
# regardless of the operator's own TARGETARCH. Stripped (-s -w) to keep the
# shipped payload small.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -a -ldflags "-s -w -X github.com/achetronic/tunnel/internal/version.Version=${VERSION}" -o /opt/tunnelctl/tunnelctl-linux-amd64 ./cmd/tunnelctl \
 && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -a -ldflags "-s -w -X github.com/achetronic/tunnel/internal/version.Version=${VERSION}" -o /opt/tunnelctl/tunnelctl-linux-arm64 ./cmd/tunnelctl

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
COPY --from=builder /opt/tunnelctl /opt/tunnelctl
USER 65532:65532

ENTRYPOINT ["/manager"]
