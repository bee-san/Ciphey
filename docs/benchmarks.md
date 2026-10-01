# Benchmark baseline

Numbers from the criterion suite in [`benches/`](../benches/README.md), run on `master` at
`42fbebcc` with the suite added and no library changes.

* Machine: Intel Xeon Platinum 8488C, 8 cores / 16 threads (KVM guest), 123 GiB RAM,
  Amazon Linux 2023, kernel 6.12.
* Toolchain: rustc 1.98.1, the `bench` profile (inherits release: fat LTO, one codegen unit).
* Command: `cargo bench -- --save-baseline pr1 --noplot`, about 10 minutes.
* The host was shared with other jobs (load average 15 to 36 on 16 threads), so treat
  differences under about 10% as noise, especially for the multi-threaded `search` suite.

All times are criterion medians.

## Headline numbers

| What | Time |
|---|---:|
| Already-plaintext input, `perform_cracking` (early exit) | 184 µs |
| One layer (base64, rot13, hex, atbash, ...), `perform_cracking` | 10.5 to 20.8 ms |
| Two or three layers | 41 to 170 ms |
| Gibberish with no solution, until the search gives up | 215 ms to 1.03 s (1 s timeout) |
| `ciphey -t <text>` process, cache hit | 4.5 ms |
| `ciphey -t <text>` process, new plaintext input | 49 ms |
| `ciphey -t <base64>` process, new input | 71 ms |
| Athena checker on an English sentence / on gibberish | 21 µs / 17 µs |

## Where the time goes

`perf record -F 1999` over `search/single` and `search/multi` (all threads, self time):

| Share | Where |
|---:|---|
| 39.6% | `VigenereDecoder::crack`, almost all of it the key search in `break_vigenere` |
| ~25% | `gibberish_or_not` behind the English checker: `sip128` hashing 6.1%, `phf` lookups 4.7%, `is_gibberish` 4.4%, `generate_ngrams` 4.2% |
| ~15% | `malloc` / `free`, mostly per-call `String`s in `gibberish_or_not` and per-candidate clones in the search |
| ~6% | regex matching for LemmeKnow, including 2.2% contention on the regex cache pool |
| 1.5% | sorting in the railfence decoder |

What that means:

1. **Vigenere is the critical path of every node expansion.** All decoders run in
   parallel on a node, so a node takes as long as its slowest decoder, and Vigenere is
   the slowest on almost every input: 6.4 ms on an 88 character miss, 4.1 ms on 576
   characters. `break_vigenere` tries all 26×26 key letter pairs at every key position
   for every key length from 3 to 29, with each step looking up two `Vec<Vec<char>>`
   tables and one `Vec<Vec<i64>>` table.
2. **Searches are quantised to 10 ms.** `wait_for_search_result` polls the result
   channel and then sleeps 10 ms. A search that finishes in 1 ms reports after 10.5 ms
   (`search/single/rot13`, `atbash`, `railfence` are all 10.5 ms); one that takes just
   over 10 ms reports after 20.7 ms (`base32`, `vigenere`). Even an input every decoder
   rejects at once takes 11.2 ms (`search/no_solution/unicode_exhausts`).
3. **The English checker is most of the remaining CPU.** Caesar, rot47, railfence and
   binary check 25, 93, 72 and 24 candidates each, and almost every candidate is a miss
   that runs LemmeKnow (2 to 4 µs), the password list (50 ns) and the English checker
   (17 to 130 µs). The English checker cost is inside `gibberish_or_not`.
4. **Some setup is repeated on every call.** `a1z26` compiles three regexes per call
   (77 µs on a miss, where most decoders take under 1 µs), `morse_code` one (32 µs),
   and the regex checker compiles the crib on every check (31 µs per candidate).
5. **Candidate lists are cloned once per candidate.** `expand_node` clones the whole
   `CrackResult`, including every candidate, for each candidate it keeps, so rot47's
   93 candidates are copied 93 times per node.
6. **CLI cold start is regex compilation.** A run on a new input takes 49 ms against
   4.5 ms for a cache hit. About 90% of it is LemmeKnow compiling its regexes on first
   use: 68 ms for the 129 patterns compiled one after another in isolation, 30 ms of
   that for the Discord Webhook pattern alone. This is inside `lemmeknow`.
7. **Brainfuck is quadratic in program length** (1.4 ms for 3 KB, 48 ms for 19.5 KB)
   because `brainfuck-exe` looks up each instruction with `code.chars().nth(i)`.

Items 1, 2, 4 and 5 are in Ciphey's code. Items 3, 6 and 7 are in dependencies.

## Results

### decoders

`crack` with the Athena checker. `medium` and `long` are 84 and 576 characters of
English encoded with that decoder; `miss` is 88 characters of gibberish.

| decoder | medium | long | miss |
|---|---:|---:|---:|
| a1z26 | 191.8 µs | 380.4 µs | 77.5 µs |
| atbash | 31.8 µs | 172.4 µs | 26.1 µs |
| base32 | 30.1 µs | 172.5 µs | 186 ns |
| base58_bitcoin | 33.3 µs | 349.5 µs | 66 ns |
| base58_flickr | 29.5 µs | 347.4 µs | 69 ns |
| base58_monero | 26.7 µs | 336.8 µs | 70 ns |
| base58_ripple | 33.0 µs | 342.2 µs | 69 ns |
| base64 | 30.0 µs | 178.3 µs | 248 ns |
| base65536 | 29.7 µs | 141.7 µs | 51 ns |
| base91 | 30.3 µs | 174.4 µs | 4.3 µs |
| binary | 100.5 µs | 607.6 µs | 54.6 µs |
| braille | 36.2 µs | 204.8 µs | 3.3 µs |
| brainfuck | 1.40 ms | 48.21 ms | 44 ns |
| caesar | 396.6 µs | 2.38 ms | 669.1 µs |
| citrix_ctx1 | 31.3 µs | 186.8 µs | 93 ns |
| hexadecimal | 27.0 µs | 150.8 µs | 550 ns |
| morse_code | 80.9 µs | 261.8 µs | 32.5 µs |
| railfence | 106.7 µs | 692.0 µs | 3.41 ms |
| reverse | 31.0 µs | 150.0 µs | 26.2 µs |
| rot47 | 365.2 µs | 1.81 ms | 2.45 ms |
| simplesubstitution | 540.6 µs | 1.76 ms | 2.7 µs |
| url | 29.4 µs | 132.5 µs | 118 ns |
| vigenere | 323.3 µs | 4.11 ms | 6.44 ms |
| z85 | 30.5 µs | 117.4 µs | 38 ns |

### checkers

| benchmark | median | 95% CI |
|---|---:|---:|
| `checkers/athena/base64_like` | 36.1 µs | 34.5 µs – 36.8 µs |
| `checkers/athena/gibberish` | 17.5 µs | 17.2 µs – 17.8 µs |
| `checkers/athena/paragraph` | 120.0 µs | 117.8 µs – 124.1 µs |
| `checkers/athena/password` | 1.7 µs | 1.6 µs – 1.7 µs |
| `checkers/athena/rot13_paragraph` | 116.2 µs | 114.3 µs – 118.1 µs |
| `checkers/athena/sentence` | 20.9 µs | 20.4 µs – 21.3 µs |
| `checkers/athena/url` | 2.6 µs | 2.5 µs – 2.8 µs |
| `checkers/athena_low/base64_like` | 37.6 µs | 36.7 µs – 38.4 µs |
| `checkers/athena_low/rot13_paragraph` | 116.8 µs | 114.7 µs – 120.8 µs |
| `checkers/english/base64_like` | 33.6 µs | 33.0 µs – 34.4 µs |
| `checkers/english/gibberish` | 19.8 µs | 18.9 µs – 21.3 µs |
| `checkers/english/paragraph` | 124.8 µs | 122.3 µs – 127.6 µs |
| `checkers/english/rot13_paragraph` | 128.9 µs | 123.8 µs – 136.1 µs |
| `checkers/english/sentence` | 17.4 µs | 16.8 µs – 17.9 µs |
| `checkers/english/word` | 413 ns | 360 ns – 431 ns |
| `checkers/english_high/rot13_paragraph` | 120.3 µs | 117.3 µs – 123.7 µs |
| `checkers/english_high/sentence` | 24.0 µs | 23.3 µs – 24.3 µs |
| `checkers/english_low/rot13_paragraph` | 121.6 µs | 119.3 µs – 122.7 µs |
| `checkers/english_low/sentence` | 19.2 µs | 18.2 µs – 19.9 µs |
| `checkers/lemmeknow/base64_like` | 3.0 µs | 3.0 µs – 3.1 µs |
| `checkers/lemmeknow/email` | 2.7 µs | 2.7 µs – 2.7 µs |
| `checkers/lemmeknow/gibberish` | 2.7 µs | 2.6 µs – 2.9 µs |
| `checkers/lemmeknow/ipv4` | 1.8 µs | 1.7 µs – 1.8 µs |
| `checkers/lemmeknow/paragraph` | 3.9 µs | 3.8 µs – 3.9 µs |
| `checkers/lemmeknow/sentence` | 2.5 µs | 2.4 µs – 2.6 µs |
| `checkers/lemmeknow/url` | 2.1 µs | 2.0 µs – 2.2 µs |
| `checkers/password/password` | 44 ns | 43 ns – 46 ns |
| `checkers/password/sentence` | 61 ns | 59 ns – 62 ns |

### crib

With `--regex 'flag\{[^}]*\}'` and a 5,000 word wordlist.

| benchmark | median | 95% CI |
|---|---:|---:|
| `crib/athena/flag_sentence` | 34.1 µs | 33.4 µs – 34.6 µs |
| `crib/athena/gibberish` | 31.7 µs | 31.2 µs – 32.1 µs |
| `crib/regex/flag_sentence` | 34.1 µs | 33.3 µs – 34.9 µs |
| `crib/regex/paragraph` | 30.7 µs | 29.9 µs – 31.0 µs |
| `crib/regex/sentence` | 30.8 µs | 30.3 µs – 31.5 µs |
| `crib/search/base64` | 17.52 ms | 15.40 ms – 18.14 ms |
| `crib/search/rot13_base64` | 42.35 ms | 40.22 ms – 51.56 ms |
| `crib/wordlist/sentence` | 33 ns | 33 ns – 34 ns |
| `crib/wordlist/wordlist_word` | 43 ns | 42 ns – 44 ns |

### search

`perform_cracking` with a 1 second timeout and an in-memory cache.

| benchmark | median | 95% CI |
|---|---:|---:|
| `search/plaintext/already_plaintext` | 184.1 µs | 180.9 µs – 187.5 µs |
| `search/single/atbash` | 10.52 ms | 10.49 ms – 10.58 ms |
| `search/single/base32` | 20.77 ms | 20.75 ms – 20.80 ms |
| `search/single/base58_bitcoin` | 18.57 ms | 16.83 ms – 22.57 ms |
| `search/single/base64` | 18.29 ms | 16.93 ms – 19.61 ms |
| `search/single/base64_long` | 71.43 ms | 66.92 ms – 76.57 ms |
| `search/single/binary` | 25.88 ms | 24.22 ms – 26.81 ms |
| `search/single/citrix_ctx1` | 38.63 ms | 35.96 ms – 41.08 ms |
| `search/single/hexadecimal` | 10.71 ms | 10.61 ms – 11.44 ms |
| `search/single/morse` | 11.33 ms | 10.75 ms – 12.22 ms |
| `search/single/railfence` | 10.54 ms | 10.51 ms – 11.67 ms |
| `search/single/rot13` | 10.51 ms | 10.49 ms – 10.52 ms |
| `search/single/url` | 14.07 ms | 13.56 ms – 16.29 ms |
| `search/single/vigenere` | 20.71 ms | 20.70 ms – 20.74 ms |
| `search/multi/atbash_base64` | 42.71 ms | 41.65 ms – 44.73 ms |
| `search/multi/base32_hex_base64` | 170.44 ms | 165.76 ms – 172.77 ms |
| `search/multi/base64_reverse` | 49.97 ms | 46.94 ms – 52.82 ms |
| `search/multi/base64_x3` | 106.44 ms | 104.53 ms – 108.93 ms |
| `search/multi/binary_base64` | 121.92 ms | 116.57 ms – 127.24 ms |
| `search/multi/hex_base32` | 78.95 ms | 77.17 ms – 86.28 ms |
| `search/multi/rot13_base64` | 40.77 ms | 39.33 ms – 41.78 ms |
| `search/multi/rot13_base64_hex` | 132.98 ms | 127.65 ms – 140.91 ms |
| `search/multi/url_base64` | 59.94 ms | 56.41 ms – 63.02 ms |
| `search/no_solution/gibberish` | 215.05 ms | 210.57 ms – 229.30 ms |
| `search/no_solution/gibberish_long` | 783.32 ms | 735.70 ms – 953.01 ms |
| `search/no_solution/gibberish_timeout` | 1.03 s | 1.03 s – 1.04 s |
| `search/no_solution/unicode_exhausts` | 11.21 ms | 11.08 ms – 11.51 ms |

### startup

| benchmark | median | 95% CI |
|---|---:|---:|
| `startup/config/default` | 517 ns | 454 ns – 559 ns |
| `startup/config/load_config_file` | 37.7 µs | 37.1 µs – 39.3 µs |
| `startup/config/load_wordlist_5k` | 1.33 ms | 1.24 ms – 1.66 ms |
| `startup/cache/insert` | 187.6 µs | 180.2 µs – 196.5 µs |
| `startup/cache/read_hit` | 73.4 µs | 71.3 µs – 77.8 µs |
| `startup/cache/read_miss` | 60.5 µs | 59.8 µs – 61.5 µs |
| `startup/cache/setup_database` | 98.1 µs | 94.4 µs – 105.0 µs |
| `startup/perform_cracking/plaintext_cache_hit` | 165.8 µs | 163.4 µs – 169.9 µs |
| `startup/perform_cracking/plaintext_cache_miss` | 417.9 µs | 404.5 µs – 448.0 µs |
| `startup/cli/plaintext_cache_hit` | 4.52 ms | 4.49 ms – 4.57 ms |
| `startup/cli/plaintext_fresh_db` | 49.47 ms | 48.83 ms – 50.63 ms |
| `startup/cli/base64_fresh_db` | 71.08 ms | 70.66 ms – 72.41 ms |
