//! AES-128-GCM with one copy per TLS-sized record, through each library's generic AEAD API.
//!
//! These rows help compare the crypto libraries, but do not isolate the cipher's share of a TLS
//! result. The stacks use TLS-specific contexts and different buffers and sealing paths, so
//! subtracting these times from a stack's time does not measure its protocol overhead.

use std::cell::Cell;

use ::aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ::btls::aead::{AeadCtx, Algorithm};
use criterion::{BenchmarkGroup, measurement::WallTime};

use super::{BenchTarget, BoxError, Direction, case::MAX_RECORD};

/// AES-GCM tag length.
const TAG_LEN: usize = 16;

/// Largest sealed record: plaintext, inner content type and tag.
const MAX_SEALED: usize = MAX_RECORD + 1 + TAG_LEN;

/// TLS 1.3 inner content type of application data.
const APPLICATION_DATA: u8 = 23;

const KEY: [u8; 16] = [7; 16];

/// One AES-128-GCM implementation, sealing and opening records in place.
///
/// A record buffer holds the payload followed by room for, or the bytes of, its tag.
trait AeadAdapter: Sized {
    /// Name appended to the Criterion benchmark ID.
    const NAME: &'static str;

    /// Builds the cipher for `key`.
    fn new(key: &[u8; 16]) -> Result<Self, BoxError>;

    /// Encrypts the payload and writes its tag into the last [`TAG_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// The AEAD implementation rejects the record.
    fn seal(&mut self, nonce: [u8; 12], aad: &[u8], record: &mut [u8]) -> Result<(), BoxError>;

    /// Decrypts the payload in place; returns whether the tag matched.
    fn open(&mut self, nonce: [u8; 12], aad: &[u8], record: &mut [u8]) -> bool;
}

/// `BoringSSL`'s AEAD through btls.
struct Btls(AeadCtx);

/// AWS-LC's AEAD through aws-lc-rs, which rustls uses.
struct AwsLc(LessSafeKey);

// ===== impl Btls =====

impl AeadAdapter for Btls {
    const NAME: &'static str = "btls";

    fn new(key: &[u8; 16]) -> Result<Self, BoxError> {
        Ok(Self(AeadCtx::new_default_tag(
            Algorithm::aes_128_gcm(),
            key,
        )?))
    }

    fn seal(&mut self, nonce: [u8; 12], aad: &[u8], record: &mut [u8]) -> Result<(), BoxError> {
        let (payload, tag) = record.split_at_mut(record.len() - TAG_LEN);
        self.0.seal_in_place(&nonce, payload, tag, aad)?;
        Ok(())
    }

    fn open(&mut self, nonce: [u8; 12], aad: &[u8], record: &mut [u8]) -> bool {
        let (payload, tag) = record.split_at_mut(record.len() - TAG_LEN);
        self.0.open_in_place(&nonce, payload, tag, aad).is_ok()
    }
}

// ===== impl AwsLc =====

impl AeadAdapter for AwsLc {
    const NAME: &'static str = "aws-lc-rs";

    fn new(key: &[u8; 16]) -> Result<Self, BoxError> {
        let key = UnboundKey::new(&AES_128_GCM, key).map_err(|_| "aws-lc-rs rejected the key")?;
        Ok(Self(LessSafeKey::new(key)))
    }

    fn seal(&mut self, nonce: [u8; 12], aad: &[u8], record: &mut [u8]) -> Result<(), BoxError> {
        let (payload, tag) = record.split_at_mut(record.len() - TAG_LEN);
        let sealed = self
            .0
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                payload,
            )
            .map_err(|_| "aws-lc-rs failed to seal a record")?;
        tag.copy_from_slice(sealed.as_ref());
        Ok(())
    }

    fn open(&mut self, nonce: [u8; 12], aad: &[u8], record: &mut [u8]) -> bool {
        self.0
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), record)
            .is_ok()
    }
}

/// Registers the AES-128-GCM rows for `body` beside the TLS stacks of a memory target.
///
/// Returns an error if a key cannot be built or a sealed body does not open to the same bytes.
pub(super) fn bench_aead(
    group: &mut BenchmarkGroup<'_, WallTime>,
    target: BenchTarget,
    body: &[u8],
    reverse_order: bool,
) -> Result<(), BoxError> {
    if reverse_order {
        register::<AwsLc>(group, target, body)?;
        register::<Btls>(group, target, body)
    } else {
        register::<Btls>(group, target, body)?;
        register::<AwsLc>(group, target, body)
    }
}

/// Seals (write targets) or opens (read targets) one body's records per iteration.
///
/// Both adapters copy each record through one scratch buffer. This keeps their memory workload
/// alike, without reproducing either TLS stack's buffer layout.
fn register<A>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    target: BenchTarget,
    body: &[u8],
) -> Result<(), BoxError>
where
    A: AeadAdapter,
{
    let mut aead = A::new(&KEY)?;
    let clock = target.clock;
    let mut scratch = vec![0; MAX_SEALED];

    // Checked round, outside measurement: the sealed body opens to the same bytes.
    let mut sealed = Vec::new();
    for (seq, chunk) in (0..).zip(body.chunks(MAX_RECORD)) {
        sealed.extend_from_slice(seal_record(&mut aead, seq, chunk, &mut scratch)?);
    }
    let opened = (0..)
        .zip(sealed.chunks(MAX_SEALED))
        .zip(body.chunks(MAX_RECORD))
        .all(|((seq, record), chunk)| {
            open_record(&mut aead, seq, record, &mut scratch) == Some(chunk)
        });
    if !opened {
        return Err(format!("{} did not open its own records", A::NAME).into());
    }

    let label = format!("aead/{}", A::NAME);
    // Criterion's timing API returns Duration, not Result. Preserve any
    // failed seal/open for reporting once the current benchmark call ends.
    let failure = Cell::new(None::<BoxError>);
    match target.direction {
        Direction::Write => {
            // Continue after the checked round's records, so no nonce repeats.
            let mut seq = u64::try_from(body.len().div_ceil(MAX_RECORD))?;
            group.bench_function(label, |bencher| {
                bencher.iter_custom(|iters| {
                    let stopwatch = clock.start();
                    'work: for _ in 0..iters {
                        for chunk in body.chunks(MAX_RECORD) {
                            if let Err(error) = seal_record(&mut aead, seq, chunk, &mut scratch) {
                                failure.set(Some(error));
                                break 'work;
                            }
                            seq = seq.wrapping_add(1);
                        }
                    }
                    match stopwatch.elapsed() {
                        Ok(elapsed) => elapsed,
                        Err(error) => {
                            failure.set(Some(error.into()));
                            std::time::Duration::ZERO
                        }
                    }
                });
            });
        }
        Direction::Read => {
            group.bench_function(label, |bencher| {
                bencher.iter_custom(|iters| {
                    let stopwatch = clock.start();
                    'work: for _ in 0..iters {
                        for (seq, record) in (0..).zip(sealed.chunks(MAX_SEALED)) {
                            if open_record(&mut aead, seq, record, &mut scratch).is_none() {
                                failure.set(Some("record failed to open".into()));
                                break 'work;
                            }
                        }
                    }
                    match stopwatch.elapsed() {
                        Ok(elapsed) => elapsed,
                        Err(error) => {
                            failure.set(Some(error.into()));
                            std::time::Duration::ZERO
                        }
                    }
                });
            });
        }
    }
    if let Some(error) = failure.take() {
        return Err(error);
    }
    Ok(())
}

/// Copies `chunk` into `scratch` as a record payload, seals it there, and returns the record.
fn seal_record<'s, A>(
    aead: &mut A,
    seq: u64,
    chunk: &[u8],
    scratch: &'s mut [u8],
) -> Result<&'s [u8], BoxError>
where
    A: AeadAdapter,
{
    let len = chunk
        .len()
        .checked_add(1 + TAG_LEN)
        .ok_or("record length overflow")?;
    let record = scratch
        .get_mut(..len)
        .ok_or("record exceeds scratch capacity")?;
    record[..chunk.len()].copy_from_slice(chunk);
    record[chunk.len()] = APPLICATION_DATA;
    aead.seal(nonce(seq), &header(record.len())?, record)?;
    Ok(record)
}

/// Copies a sealed record into `scratch`, opens it there, and returns its payload without the
/// content type, or `None` if the tag did not match.
fn open_record<'s, A>(
    aead: &mut A,
    seq: u64,
    sealed: &[u8],
    scratch: &'s mut [u8],
) -> Option<&'s [u8]>
where
    A: AeadAdapter,
{
    if sealed.len() < 1 + TAG_LEN {
        return None;
    }
    let record = scratch.get_mut(..sealed.len())?;
    record.copy_from_slice(sealed);
    if !aead.open(nonce(seq), &header(record.len()).ok()?, record) {
        return None;
    }
    let record: &[u8] = record;
    Some(&record[..record.len() - 1 - TAG_LEN])
}

/// TLS 1.3 per-record nonce for sequence number `seq` with an all-zero IV
/// ([RFC 8446 §5.3](https://www.rfc-editor.org/rfc/rfc8446#section-5.3)).
fn nonce(seq: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// Record header used as additional data: application data, TLS 1.2 legacy version, length.
fn header(len: usize) -> Result<[u8; 5], BoxError> {
    let [hi, lo] = u16::try_from(len)?.to_be_bytes();
    Ok([APPLICATION_DATA, 3, 3, hi, lo])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_tls_aead_record_roundtrip_and_tamper_detection() {
        let mut aead = Btls::new(&KEY).unwrap();
        let plaintext = b"ciphertext needs authenticated framing";
        let mut scratch = vec![0; MAX_SEALED];
        let sealed = seal_record(&mut aead, 0, plaintext, &mut scratch)
            .unwrap()
            .to_vec();
        assert_eq!(
            open_record(&mut aead, 0, &sealed, &mut scratch),
            Some(plaintext.as_slice())
        );
        let mut tampered = sealed;
        tampered[0] ^= 1;
        assert_eq!(open_record(&mut aead, 0, &tampered, &mut scratch), None);
        assert_eq!(open_record(&mut aead, 0, &[], &mut scratch), None);
    }

    #[test]
    fn checked_tls_aead_framing_rejects_oversized_lengths() {
        let mut aead = Btls::new(&KEY).unwrap();
        let mut scratch = [0; 3];
        assert!(seal_record(&mut aead, 0, b"payload", &mut scratch).is_err());
        assert!(header(usize::from(u16::MAX) + 1).is_err());
        assert_eq!(header(0).unwrap(), [APPLICATION_DATA, 3, 3, 0, 0]);
    }
}
