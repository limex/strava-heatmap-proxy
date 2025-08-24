# Use the official Go image as the base image
FROM golang:1.25-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o strava-heatmap-proxy .

# Use a minimal base image for the final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create a non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set the working directory
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/strava-heatmap-proxy .

# Copy configuration files from builder stage (they should be there after COPY . .)
COPY --from=builder /app/build/strava-cookies.json ./strava-cookies.json
COPY --from=builder /app/build/api-keys.json ./api-keys.json

# Change ownership of the app directory to the non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose the port
EXPOSE 8080

# Set environment variable for the port (Cloud Run will set this)
ENV PORT=8080

# Run the application with environment variable support
CMD ./strava-heatmap-proxy \
    -cookies ./strava-cookies.json \
    -apikeys ./api-keys.json \
    -port ${PORT} \
    -target https://content-a.strava.com/
