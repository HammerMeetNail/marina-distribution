# Stage 1: Build the application
# Use a Go version compatible with go.mod (>= 1.23.2)
FROM golang:1.23-alpine AS builder

WORKDIR /src

# Copy go module files and download dependencies first
# This leverages Docker cache layers
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the statically linked binary
# -ldflags="-w -s" reduces binary size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/marina-distribution ./cmd/registry/main.go

# Stage 2: Create the final lightweight image
FROM alpine:latest

# Install CA certificates (needed for potential HTTPS communication, good practice)
RUN apk add --no-cache ca-certificates

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Create directory for registry data and set permissions
RUN mkdir /data && chown appuser:appgroup /data

# Copy the built binary from the builder stage
COPY --from=builder /app/marina-distribution /usr/local/bin/marina-distribution

# Switch to the non-root user
USER appuser

# Expose the default port the registry listens on
EXPOSE 5000

# Set the working directory for data storage
WORKDIR /data

# Define the entrypoint
ENTRYPOINT ["/usr/local/bin/marina-distribution"]

# Default command (can be overridden) - specify data directory
CMD ["--storage-path", "/data"]
