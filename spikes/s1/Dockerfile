FROM rust:1-slim-bookworm AS build
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=build /app/target/release/spike-s1 /usr/local/bin/spike-s1
EXPOSE 6432
ENTRYPOINT ["/usr/local/bin/spike-s1"]
