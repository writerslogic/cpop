// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;

#[test]
fn test_embed_and_extract_roundtrip() {
    let params = ZwcParams::default();
    let embedder = ZwcEmbedder::new(params.clone());
    let extractor = ZwcExtractor::new(params);

    let text = "The quick brown fox jumps over the lazy dog. \
                She sells sea shells by the sea shore near the lighthouse. \
                A stitch in time saves nine but two wrongs do not make a right. \
                Every cloud has a silver lining and every rose has its thorn. \
                The pen is mightier than the sword yet actions speak louder than words. \
                Knowledge is power and ignorance is bliss in the garden of wisdom. \
                Fortune favors the bold while patience is a virtue for the meek. \
                All that glitters is not gold but silence is truly golden. \
                Rome was not built in a day and neither was any great cathedral. \
                Better late than never but the early bird still catches the worm.";

    let mmr_root = [42u8; 32];
    let key = [99u8; 32];

    let (watermarked, binding) = embedder.embed(text, &mmr_root, &key).unwrap();

    // Watermarked text should be longer (ZWCs added)
    assert!(watermarked.len() > text.len());
    assert_eq!(binding.zwc_count, 32);

    // Stripping ZWCs should recover original text
    let stripped = ZwcExtractor::strip_zwc(&watermarked);
    assert_eq!(stripped, text);

    // Verification should pass
    let verification = extractor.verify(&watermarked, &mmr_root, &key);
    assert!(verification.valid);
    assert_eq!(verification.zwc_found, 32);

    // Binding verification should also pass
    let binding_verification = extractor.verify_binding(&watermarked, &binding);
    assert!(binding_verification.valid);
}

#[test]
fn test_tampered_text_fails_verification() {
    let params = ZwcParams::default();
    let embedder = ZwcEmbedder::new(params.clone());
    let extractor = ZwcExtractor::new(params);

    let text = "The quick brown fox jumps over the lazy dog. \
                She sells sea shells by the sea shore near the lighthouse. \
                A stitch in time saves nine but two wrongs do not make a right. \
                Every cloud has a silver lining and every rose has its thorn. \
                The pen is mightier than the sword yet actions speak louder than words. \
                Knowledge is power and ignorance is bliss in the garden of wisdom. \
                Fortune favors the bold while patience is a virtue for the meek. \
                All that glitters is not gold but silence is truly golden. \
                Rome was not built in a day and neither was any great cathedral. \
                Better late than never but the early bird still catches the worm.";

    let mmr_root = [42u8; 32];
    let key = [99u8; 32];

    let (watermarked, _) = embedder.embed(text, &mmr_root, &key).unwrap();

    // Tamper with the text (change a word)
    let tampered = watermarked.replace("fox", "cat");
    let verification = extractor.verify(&tampered, &mmr_root, &key);
    assert!(!verification.valid);
}

#[test]
fn test_wrong_mmr_root_fails() {
    let params = ZwcParams::default();
    let embedder = ZwcEmbedder::new(params.clone());
    let extractor = ZwcExtractor::new(params);

    let text = "The quick brown fox jumps over the lazy dog. \
                She sells sea shells by the sea shore near the lighthouse. \
                A stitch in time saves nine but two wrongs do not make a right. \
                Every cloud has a silver lining and every rose has its thorn. \
                The pen is mightier than the sword yet actions speak louder than words. \
                Knowledge is power and ignorance is bliss in the garden of wisdom. \
                Fortune favors the bold while patience is a virtue for the meek. \
                All that glitters is not gold but silence is truly golden. \
                Rome was not built in a day and neither was any great cathedral. \
                Better late than never but the early bird still catches the worm.";

    let mmr_root = [42u8; 32];
    let key = [99u8; 32];

    let (watermarked, _) = embedder.embed(text, &mmr_root, &key).unwrap();

    // Verify with wrong MMR root
    let wrong_root = [0u8; 32];
    let verification = extractor.verify(&watermarked, &wrong_root, &key);
    assert!(!verification.valid);
}

#[test]
fn test_wrong_key_fails() {
    let params = ZwcParams::default();
    let embedder = ZwcEmbedder::new(params.clone());
    let extractor = ZwcExtractor::new(params);

    let text = "The quick brown fox jumps over the lazy dog. \
                She sells sea shells by the sea shore near the lighthouse. \
                A stitch in time saves nine but two wrongs do not make a right. \
                Every cloud has a silver lining and every rose has its thorn. \
                The pen is mightier than the sword yet actions speak louder than words. \
                Knowledge is power and ignorance is bliss in the garden of wisdom. \
                Fortune favors the bold while patience is a virtue for the meek. \
                All that glitters is not gold but silence is truly golden. \
                Rome was not built in a day and neither was any great cathedral. \
                Better late than never but the early bird still catches the worm.";

    let mmr_root = [42u8; 32];
    let key = [99u8; 32];

    let (watermarked, _) = embedder.embed(text, &mmr_root, &key).unwrap();

    // Verify with wrong key
    let wrong_key = [0u8; 32];
    let verification = extractor.verify(&watermarked, &mmr_root, &wrong_key);
    assert!(!verification.valid);
}

#[test]
fn test_too_short_document_rejected() {
    let params = ZwcParams {
        min_word_count: 64,
        ..Default::default()
    };
    let embedder = ZwcEmbedder::new(params);

    let text = "Too short document with few words.";
    let mmr_root = [42u8; 32];
    let key = [99u8; 32];

    let result = embedder.embed(text, &mmr_root, &key);
    assert!(result.is_err());
}

#[test]
fn test_has_watermark() {
    assert!(!ZwcExtractor::has_watermark("clean text"));
    assert!(ZwcExtractor::has_watermark("text\u{200B}with watermark"));
    assert!(ZwcExtractor::has_watermark("text\u{200C}here"));
    assert!(ZwcExtractor::has_watermark("text\u{200D}here"));
    assert!(ZwcExtractor::has_watermark("text\u{FEFF}here"));
}

#[test]
fn test_count_zwc() {
    assert_eq!(ZwcExtractor::count_zwc("no markers"), 0);
    assert_eq!(ZwcExtractor::count_zwc("one\u{200B}two\u{200C}three"), 2);
}

#[test]
fn test_strip_zwc() {
    let text = "hello\u{200B}world\u{200C}foo\u{200D}bar\u{FEFF}baz";
    assert_eq!(ZwcExtractor::strip_zwc(text), "helloworldfoobarbaz");
}

#[test]
fn test_deterministic_embedding() {
    let params = ZwcParams::default();
    let embedder = ZwcEmbedder::new(params);

    let text = "The quick brown fox jumps over the lazy dog. \
                She sells sea shells by the sea shore near the lighthouse. \
                A stitch in time saves nine but two wrongs do not make a right. \
                Every cloud has a silver lining and every rose has its thorn. \
                The pen is mightier than the sword yet actions speak louder than words. \
                Knowledge is power and ignorance is bliss in the garden of wisdom. \
                Fortune favors the bold while patience is a virtue for the meek. \
                All that glitters is not gold but silence is truly golden. \
                Rome was not built in a day and neither was any great cathedral. \
                Better late than never but the early bird still catches the worm.";

    let mmr_root = [42u8; 32];
    let key = [99u8; 32];

    let (watermarked1, binding1) = embedder.embed(text, &mmr_root, &key).unwrap();
    let (watermarked2, binding2) = embedder.embed(text, &mmr_root, &key).unwrap();

    assert_eq!(watermarked1, watermarked2);
    assert_eq!(binding1.tag_hex, binding2.tag_hex);
    assert_eq!(binding1.positions, binding2.positions);
}
