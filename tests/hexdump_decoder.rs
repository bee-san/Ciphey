//! End-to-end tests for the Hexdump decoder (<https://github.com/bee-san/Ciphey/issues/946>):
//! the whole search, as the CLI runs it, has to find the plaintext through Hexdump.
//!
//! The dumps were written by xxd 2026-06-16, hexdump from util-linux 2.37.4 and od from
//! GNU coreutils 8.32. `xxd` and `hexdump -C` dumps of English aren't tested here: their
//! ASCII column is readable, so the search returns the input unchanged as plaintext
//! before any decoder runs.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

const LIGHTHOUSE: &str =
    "Meet me at the old lighthouse after midnight and bring the map, the key and a torch.";

/// Runs the whole search on `text` and returns what it found.
fn crack(text: &str) -> DecoderResult {
    // With no database path every connection is a fresh in-memory database, so the search
    // doesn't read the cache in ~/.ciphey (an answer cached by another build would stand
    // in for the search under test) and doesn't write to it.
    let _ = DB_PATH.set(None);
    perform_cracking(text, Config::default())
        .unwrap_or_else(|error| panic!("searching {text:?} failed: {error}"))
        .unwrap_or_else(|| panic!("the search found nothing for {text:?}"))
}

/// The names of the decoders the search used, in order.
fn path(result: &DecoderResult) -> Vec<&str> {
    result.path.iter().map(|step| step.decoder).collect()
}

#[test]
fn one_line_xxd_is_cracked() {
    // `printf 'Hello, World!' | xxd`. On one line the ASCII column is too short to be
    // taken for plaintext.
    let result = crack("00000000: 4865 6c6c 6f2c 2057 6f72 6c64 21         Hello, World!\n");
    assert_eq!(result.text[0], "Hello, World!");
    assert_eq!(path(&result), ["Hexdump"]);
}

#[test]
fn plain_hexdump_is_cracked() {
    // `hexdump`: little-endian 16-bit words and no ASCII column
    let result = crack(
        "\
0000000 654d 7465 6d20 2065 7461 7420 6568 6f20\n\
0000010 646c 6c20 6769 7468 6f68 7375 2065 6661\n\
0000020 6574 2072 696d 6e64 6769 7468 6120 646e\n\
0000030 6220 6972 676e 7420 6568 6d20 7061 202c\n\
0000040 6874 2065 656b 2079 6e61 2064 2061 6f74\n\
0000050 6372 2e68                              \n\
0000054\n",
    );
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["Hexdump"]);
}

#[test]
fn od_is_cracked() {
    // `od -t x1`: octal offsets and no ASCII column
    let result = crack(
        "\
0000000 4d 65 65 74 20 6d 65 20 61 74 20 74 68 65 20 6f\n\
0000020 6c 64 20 6c 69 67 68 74 68 6f 75 73 65 20 61 66\n\
0000040 74 65 72 20 6d 69 64 6e 69 67 68 74 20 61 6e 64\n\
0000060 20 62 72 69 6e 67 20 74 68 65 20 6d 61 70 2c 20\n\
0000100 74 68 65 20 6b 65 79 20 61 6e 64 20 61 20 74 6f\n\
0000120 72 63 68 2e\n\
0000124\n",
    );
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["Hexdump"]);
}

#[test]
fn xxd_of_base64_is_cracked() {
    // `base64 -w0 | xxd`: the ASCII column is Base64, which isn't plaintext
    let result = crack(
        "\
00000000: 5457 566c 6443 4274 5a53 4268 6443 4230  TWVldCBtZSBhdCB0\n\
00000010: 6147 5567 6232 786b 4947 7870 5a32 6830  aGUgb2xkIGxpZ2h0\n\
00000020: 6147 3931 6332 5567 5957 5a30 5a58 4967  aG91c2UgYWZ0ZXIg\n\
00000030: 6257 6c6b 626d 6c6e 6148 5167 5957 356b  bWlkbmlnaHQgYW5k\n\
00000040: 4947 4a79 6157 356e 4948 526f 5a53 4274  IGJyaW5nIHRoZSBt\n\
00000050: 5958 4173 4948 526f 5a53 4272 5a58 6b67  YXAsIHRoZSBrZXkg\n\
00000060: 5957 356b 4947 4567 6447 3979 5932 6775  YW5kIGEgdG9yY2gu\n",
    );
    assert_eq!(result.text[0], LIGHTHOUSE);
    assert_eq!(path(&result), ["Hexdump", "Base64"]);
}

#[test]
fn internetwache_od_dump_is_cracked() {
    // Internetwache CTF 2016, misc50 "The hidden message": the `od -b` dump of a Base64
    // string, copied from the challenge.
    // https://raw.githubusercontent.com/internetwache/Internetwache-CTF-2016/master/tasks/misc50/task/README.txt
    let result = crack(
        "\
0000000 126 062 126 163 142 103 102 153 142 062 065 154 111 121 157 113\n\
0000020 122 155 170 150 132 172 157 147 123 126 144 067 124 152 102 146\n\
0000040 115 107 065 154 130 062 116 150 142 154 071 172 144 104 102 167\n\
0000060 130 063 153 167 144 130 060 113 012\n\
0000071",
    );
    assert_eq!(
        result.text[0],
        "Well done!\n\nFlag: IW{N0_0ne_can_st0p_y0u}\n"
    );
    assert_eq!(path(&result), ["Hexdump", "Base64"]);
}
