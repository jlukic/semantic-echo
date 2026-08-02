FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go page.html ./
RUN CGO_ENABLED=0 go build -o /wt-lab .

# rung A builds from its own module so the v0.11.0 pin cannot drift with the control
FROM golang:1.26-alpine AS build-legacy
WORKDIR /src
COPY legacy/go.mod legacy/go.sum ./
RUN go mod download
COPY legacy/main.go ./
RUN CGO_ENABLED=0 go build -o /wt-legacy .

FROM rust:1-bookworm AS build-rust
WORKDIR /src
COPY rust/Cargo.toml rust/Cargo.lock ./
COPY rust/src ./src
RUN cargo build --release --locked

# glibc runtime, because the Rust binary needs it. the Go binaries are
# CGO_ENABLED=0 and do not care either way
FROM debian:bookworm-slim
COPY --from=build /wt-lab /wt-lab
COPY --from=build-legacy /wt-legacy /wt-legacy
COPY --from=build-rust /src/target/release/wt-rust /wt-rust
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
