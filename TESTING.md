# Testing the Strava Heatmap Proxy

This document describes how to run and understand the tests for the API key authentication feature.

## Running Tests

### Run All Tests
```bash
go test -v
```

### Run Specific Tests
```bash
# Test only authentication functionality
go test -v -run TestAuthenticated

# Test configuration loading
go test -v -run TestNewAuthenticatedHandler

# Test with actual config file
go test -v -run TestAuthenticatedHandler_WithActualConfigFile
```

### Run Benchmarks
```bash
# Run all benchmarks
go test -bench=.

# Run authentication benchmarks only
go test -bench=BenchmarkAuthenticatedHandler -benchmem
```

## Test Coverage

The test suite covers: 

### Configuration Loading Tests
- ✅ Loading valid API keys from JSON file
- ✅ Handling missing API keys file
- ✅ Handling invalid JSON format
- ✅ Handling empty keys array
- ✅ Filtering out empty string keys
- ✅ Non-existent file handling

### Authentication Tests
- ✅ Valid API key authentication
- ✅ Invalid API key rejection
- ✅ Missing API key rejection
- ✅ Empty API key rejection
- ✅ No authentication when no keys configured
- ✅ Case-sensitive API key validation
- ✅ Multiple key parameters handling
- ✅ Key parameter removal from proxied requests

### Integration Tests
- ✅ Full authentication flow with real HTTP requests
- ✅ End-to-end proxy testing with authentication
- ✅ Testing with actual `api-keys.json` file

### Performance Tests
- ✅ Benchmark without API keys
- ✅ Benchmark with valid API key
- ✅ Benchmark with invalid API key
- ✅ Benchmark with many API keys (1000)

## Test Results Interpretation

### Performance Benchmarks
From the benchmark results:

```
BenchmarkAuthenticatedHandler_NoAPIKeys-10      8194449    132.0 ns/op    280 B/op     6 allocs/op
BenchmarkAuthenticatedHandler_ValidAPIKey-10    2304970    518.3 ns/op   1104 B/op    12 allocs/op
BenchmarkAuthenticatedHandler_InvalidAPIKey-10  1783101    671.8 ns/op   1472 B/op    14 allocs/op
BenchmarkAuthenticatedHandler_ManyAPIKeys-10    2205283    523.6 ns/op   1104 B/op    12 allocs/op
```

**Key Insights:**
- **No API Keys**: Very fast (132 ns/op) - minimal overhead when authentication is disabled
- **Valid API Key**: Moderate overhead (518 ns/op) - acceptable for most use cases
- **Invalid API Key**: Slightly slower (672 ns/op) - due to error response generation
- **Many API Keys**: Similar performance (524 ns/op) - Go's map lookup is O(1)

### Memory Usage
- Authentication adds ~800B memory overhead per request
- Memory usage scales well with number of API keys
- No memory leaks detected in tests

## Test Files Structure

### Main Test File: `strava-heatmap-proxy_test.go`
```
├── Configuration Tests
│   ├── TestNewAuthenticatedHandler_*
│   └── TestApiKeyConfig_JSONStructure
├── Authentication Tests
│   ├── TestAuthenticatedHandler_*
│   └── TestAuthenticatedHandler_WithActualConfigFile
├── Integration Tests
│   └── TestIntegration_AuthenticationFlow
└── Performance Tests
    └── BenchmarkAuthenticatedHandler_*
```

## Running Tests in CI/CD

For automated testing, use:

```bash
# Run tests with coverage
go test -v -cover

# Generate coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

# Run tests with race detection
go test -race -v
```

## Mock Objects

The tests use mock objects for:
- **mockHandler**: Simulates the underlying HTTP handler
- **httptest.NewServer**: Creates test HTTP servers
- **httptest.NewRecorder**: Records HTTP responses

This allows testing without external dependencies or network calls.

## Test Configuration Files

Tests create temporary configuration files to ensure isolation:
- Each test creates its own temporary directory
- Configuration files are automatically cleaned up
- No interference between test runs

## Adding New Tests

When adding new authentication features, ensure:

1. **Unit Tests**: Test individual functions
2. **Integration Tests**: Test full request flow
3. **Error Cases**: Test all error conditions
4. **Performance Tests**: Benchmark critical paths
5. **Edge Cases**: Test boundary conditions

Example test structure:
```go
func TestNewFeature(t *testing.T) {
    // Setup
    // Test
    // Verify
    // Cleanup (if needed)
}
```
