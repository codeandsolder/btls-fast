use btls_sys::{ERR_GET_LIB, ERR_GET_REASON, ERR_PACK};

#[test]
fn matches_native_error_field_layout() {
    // Independent literal expectations from openssl/err.h. The middle twelve
    // bits are not part of either field, even in an arbitrary packed value.
    assert_eq!(ERR_PACK(0x12, 0x345), 0x1200_0345);
    assert_eq!(ERR_PACK(u32::MAX, u32::MAX), 0xff00_0fff);
    assert_eq!(ERR_GET_LIB(0xabcd_ef01), 0xab);
    assert_eq!(ERR_GET_REASON(0xabcd_ef01), 0xf01);
}

#[test]
fn error_library_identifiers_roundtrip_across_native_enum_representations() {
    for library in [
        btls_sys::ERR_LIB_NONE,
        btls_sys::ERR_LIB_PEM,
        btls_sys::ERR_LIB_SSL,
    ] {
        let code = ERR_PACK(library.as_unsigned(), 0x123);
        assert_eq!(ERR_GET_LIB(code), library.as_signed());
        assert_eq!(ERR_GET_REASON(code), 0x123);
    }
}
