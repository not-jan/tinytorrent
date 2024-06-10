# Base image with Rust installed for building our application
FROM rust:1.78-slim-buster as build

# Define working directory in the container
WORKDIR /app

# Copy manifest file to the working directory
COPY Cargo.toml .

# Copy source code to the working directory
COPY src/ ./src

# Create a directory for the build
RUN mkdir /build

# Use Docker's caching mechanism to improve subsequent builds
# Build the source code and copy the output binary to the /build directory
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --bin tinytorrent &&  cp /app/target/release/tinytorrent /build/

# Start a new stage with a slim Debian image
FROM debian:buster-slim



# Create a user `debian` with a home directory and bash as the default shell
RUN useradd -ms /bin/bash debian

# Switch to the new user
USER debian

# Set the user's home directory as the working directory
WORKDIR /home/debian

COPY --from=build /build/tinytorrent .


# Start bash when the container is run
ENTRYPOINT ["/home/debian/tinytorrent"]

