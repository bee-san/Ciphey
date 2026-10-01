# ciphey Architecture and Technical Details

## Core Architecture

ciphey is built with a modular architecture that separates concerns and enables extensibility. The system is composed of several key components:

### 1. Library API

The core of ciphey is a Rust library that provides the main functionality through a clean API. The entry point is the `perform_cracking` function in `src/lib.rs`:

```rust
pub fn perform_cracking(text: &str, config: Config) -> Result<Option<DecoderResult>, CipheyError>
```

This function takes the text to decode and a configuration object, then returns either:
- `Ok(Some(DecoderResult))` containing the decoded plaintext and the path of decoders used
- `Ok(None)` if the search finished without finding plaintext
- `Err(CipheyError)` if the search timed out or `config.regex` is invalid

### 2. Decoders

Decoders are the components that perform the actual transformation of encoded text. Each decoder implements the `Decoder` trait defined in `src/decoders/interface.rs`, which requires a `crack` method:

```rust
fn crack(&self, text: &str) -> Vec<String>
```

This method attempts to decode the input text and returns a vector of possible results (some decoders like Caesar cipher may return multiple possible decodings).

Decoders are organized in the `src/decoders` module and include implementations for various encoding schemes like Base64, Hexadecimal, Caesar cipher, etc.

### 3. Checkers

Checkers determine whether a given text is valid plaintext. They implement the `Check` trait defined in `src/checkers/checker_type.rs`:

```rust
fn check(&self, text: &str) -> CheckResult
```

The `CheckResult` structure contains information about whether the text was identified as plaintext, which checker identified it, and additional metadata.

The main checkers include:
- **Athena**: The primary checker that orchestrates other checkers
- **LemmeKnow**: Uses pattern matching to identify known formats
- **EnglishChecker**: Determines if text is valid English
- **RegexChecker**: Checks if text matches a user-provided regex pattern

### 4. Search Algorithms

Search algorithms determine the order in which decoders are applied and manage the search for plaintext. ciphey implements two main search algorithms:

- **A* Search** (`src/searchers/astar.rs`): Uses heuristics to prioritize promising decoders, enhanced with Cipher Identifier for statistical analysis of ciphertext
- **BFS** (`src/searchers/bfs.rs`): Systematically explores all possible decodings

The search process is managed by the `search_for_plaintext` function in `src/searchers/mod.rs`, which runs the search algorithm in a separate thread with a timeout.

### 5. Filtration System

The filtration system (`src/filtration_system/mod.rs`) determines which decoders to use for a given input. It can filter decoders based on:
- Input characteristics
- Performance considerations
- User configuration

This component helps optimize the decoding process by avoiding unnecessary decoder attempts.

### 6. Configuration

The configuration system (`src/config/mod.rs`) manages user-configurable settings like:
- Timeout duration
- Whether to use the human checker
- Verbosity level
- Custom regex patterns

Configuration is stored in a global singleton for easy access throughout the codebase.

### 7. CLI Interface

The CLI interface (`src/cli/mod.rs` and `src/cli_input_parser/mod.rs`) handles command-line arguments, user interaction, and result presentation. It's built on top of the library API and provides a user-friendly interface to ciphey's functionality.

## Data Flow

The typical data flow through ciphey follows these steps:

1. **Input Processing**: The input text is received through the API or CLI
2. **Initial Check**: The system checks if the input is already plaintext
3. **Search Initialization**: If not plaintext, a search algorithm is initialized
4. **Decoder Selection**: The filtration system selects appropriate decoders
5. **Iterative Decoding**:
   - Decoders are applied to the input
   - Results are checked for plaintext
   - If not plaintext, they're added to the search queue
6. **Result Generation**: When plaintext is found, a `DecoderResult` is created with the decoded text and the path of decoders used
7. **Output Formatting**: The CLI formats and presents the results to the user

## Concurrency Model

ciphey uses a multi-threaded approach to improve performance:

1. **Search Thread**: The search algorithm runs in a dedicated thread
2. **Timeout Thread**: A separate thread monitors for timeout
3. **Parallel Decoding**: Decoders can run in parallel using Rayon

This concurrency model allows ciphey to efficiently utilize multiple CPU cores and handle timeouts gracefully.

## Plaintext Identification

Plaintext identification is a critical component of ciphey. The process works as follows:

1. **Athena Checker**: The main checker that orchestrates other checkers
   - If a regex pattern is provided, it checks if the text matches
   - Otherwise, it tries the LemmeKnow checker and then the English checker

2. **LemmeKnow Checker**: Uses the LemmeKnow library to identify if the text matches known patterns
   - IP addresses, URLs, email addresses, etc.
   - Returns true if a match is found with sufficient confidence

3. **English Checker**: Determines if the text is valid English
   - Normalizes the text (lowercase, remove punctuation)
   - Uses the gibberish-or-not library to check if the text is meaningful English
   - Handles edge cases like very short strings

4. **Human Checker** (optional): Asks a human to verify if the text is valid plaintext
   - Only used if enabled in the configuration
   - Useful for ambiguous cases or specialized content

## Error Handling

ciphey uses a combination of Rust's Result and Option types for error handling:

- `Option<DecoderResult>` is used for the main API return type, with `None` indicating failure
- `Result<T, E>` is used for operations that can fail with specific error types
- Logging is used to provide additional context for errors and debugging

## Testing Strategy

ciphey has a comprehensive testing strategy:

1. **Unit Tests**: Each component has unit tests to verify its behavior in isolation
2. **Integration Tests**: Tests that verify the interaction between components
3. **Documentation Tests**: Examples in documentation that are verified by the test suite
4. **Benchmarks**: Performance tests to ensure efficiency

## Performance Considerations

Several optimizations contribute to ciphey's performance:

1. **Efficient Decoders**: Decoders are implemented with performance in mind
2. **Parallel Processing**: Multi-threading for CPU-intensive operations
3. **Early Termination**: The system stops as soon as plaintext is found
4. **Cipher Identification**: Uses statistical analysis to prioritize likely decoders
5. **Timeout Mechanism**: Prevents infinite processing on difficult inputs
5. **Heuristic-Based Search**: A* search prioritizes promising decoders

## Extensibility

ciphey is designed to be extensible:

1. **Adding New Decoders**: Implement the `Decoder` trait and add to the decoders module
2. **Custom Checkers**: Implement the `Check` trait for specialized plaintext detection
3. **Alternative Search Algorithms**: The search system can be extended with new algorithms
4. **Configuration Options**: The configuration system can be extended with new options

## Future Architectural Improvements

Planned improvements to the architecture include:

1. **Adaptive Learning**: Enhance the A* search with adaptive learning based on decoder success rates
2. **Contextual Heuristics**: Consider the path of decoders used so far when prioritizing next steps
3. **Decoder Dependencies**: Allow decoders to specify dependencies or prerequisites
4. **Dynamic Loading**: Support for dynamically loading decoders as plugins
5. **Distributed Processing**: Support for distributing work across multiple machines