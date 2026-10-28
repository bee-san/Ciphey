//! End-to-end tests for the Keyboard layout decoder
//! (<https://github.com/bee-san/Ciphey/issues/977>): the whole search, as the CLI runs it,
//! has to find the plaintext through Keyboard layout.
//!
//! The ciphertexts were made with a Python 3 prototype of the decoder's tables, which are
//! xkeyboard-config 2.41's `us(basic)`, `us(dvorak)` and `fr(basic)` legends, and decoded
//! back with the opposite table. `d.nnr ,rpne` and `itssg vgksr` are the examples in the
//! issue. Many layout ciphertexts read as English already (`hello zorld` is `hello world`
//! typed on QWERTY and read as AZERTY) and the search returns them unchanged before any
//! decoder runs, so these are ones it doesn't.

use ciphey::config::Config;
use ciphey::perform_cracking;
use ciphey::storage::database::DB_PATH;
use ciphey::DecoderResult;

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
fn qwerty_read_as_dvorak_is_decoded() {
    // The issue's example
    let result = crack("d.nnr ,rpne");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Keyboard layout"]);
    assert_eq!(result.path[0].key.as_deref(), Some("QWERTY→Dvorak"));
}

#[test]
fn alphabet_in_qwerty_order_is_decoded() {
    // The issue's example of the keyboard cipher: A is written Q, B is W, ...
    let result = crack("itssg vgksr");
    assert_eq!(result.text[0], "hello world");
    assert_eq!(path(&result), ["Keyboard layout"]);
    assert_eq!(result.path[0].key.as_deref(), Some("ABC→QWE"));
}

#[test]
fn flag_typed_on_the_wrong_layout_is_decoded() {
    let result = crack("unai?,prbi{nafrgy{aiacb+");
    assert_eq!(result.text[0], "flag{wrong_layout_again}");
    assert_eq!(path(&result), ["Keyboard layout"]);
}

#[test]
fn qwerty_read_as_azerty_is_decoded() {
    // AZERTY's ù is QWERTY's apostrophe
    let result = crack("Q,qwing jqww zqs ,y ,o,ùs qnthe,");
    assert_eq!(result.text[0], "Amazing jazz was my mom's anthem");
    assert_eq!(path(&result), ["Keyboard layout"]);
    assert_eq!(result.path[0].key.as_deref(), Some("QWERTY→AZERTY"));
}

#[test]
fn keyboard_layout_inside_base64_is_decoded() {
    // Python 3: base64.b64encode of the bench medium text typed on QWERTY, read as Dvorak
    let result = crack("TS4ueSBtLiBheSB5ZC4gcm5lIG5jaWR5ZHJnby4gYXV5LnAgbWNlYmNpZHkgYWJlIHhwY2JpIHlkLiBtYWx3IHlkLiB0LmYgYWJlIGEgeXJwamR2");
    assert_eq!(
        result.text[0],
        "Meet me at the old lighthouse after midnight and bring the map, the key and a torch."
    );
    assert_eq!(path(&result), ["Base64", "Keyboard layout"]);
}

#[test]
fn dawgctf_2020_qwerky_qwerty_is_decoded() {
    // DawgCTF 2020, "Qwerky Qwerty" (Misc), from
    // https://raw.githubusercontent.com/o621/c4r0-ctf/master/DawgCTF2020/Misc/Qwerky%20Qwerty/README.md
    // The challenge's own text starts garbled, so its first words decode to gibberish too.
    let result = crack(
        "Oh no... whays.. ,dats hall.bing yr me... nr br brw ,df M>vv ,df BR<vvvvv Xgy ,day-o \
         ydcovv yd.p. co a bry. cb mf dabeS U.ap bry e.ap jdcnew ydco co rbnf a ep.amvv A \
         ep.am yday dao x..b jago.e xf JRKCE[19v Mabf 'g.oycrbo frg dak.w ,dcn. frg-k. x..b \
         aon..lv D.p.cb ydco bry. nc.o yd. abo,.p frg o..tS Ea,iJYU?L4ydu1be3p+",
    );
    assert_eq!(
        result.text[0],
        "Sj lseee ,jat;ee whak; jappenglu to mdeee lo no no, why ME.. why NOW..... But what's \
         this.. there is a note in my hand: Fear not dear child, this is only a dream.. A dream \
         that has been caused by COVID-19. Many questions you have, while you've been asleep. \
         Herein this note lies the answer you seek: DawgCTF{P4thf1nd3r}"
    );
    assert_eq!(path(&result), ["Keyboard layout"]);
    assert_eq!(result.path[0].key.as_deref(), Some("QWERTY→Dvorak"));
}
