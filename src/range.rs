//! Ranged reads — map an HTTP `Range: bytes=a-b` request onto the object's manifest so only the
//! covering chunks are fetched, then slice the exact window out.
//!
//! An object is a manifest (ordered chunk CIDs, fixed `chunk_size`, `total_size`). A byte range
//! `[start, end]` (inclusive, S3/HTTP semantics) touches a contiguous run of chunks; this module
//! computes that run purely (no network) so the client can swarm-fetch just those chunks and slice.
//! Keeping it pure makes it trivially testable and reusable by both the CLI and the gateway.

use anyhow::{Result, bail};
use ce_rs::Manifest;

/// A resolved byte range plus the chunk indices that cover it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveringRange {
    /// First byte offset (inclusive).
    pub start: u64,
    /// Last byte offset (inclusive).
    pub end: u64,
    /// Number of bytes in the range (`end - start + 1`).
    pub length: u64,
    /// Indices into `Manifest::chunks` that must be fetched, contiguous and in order.
    pub chunk_indices: Vec<usize>,
    /// Byte offset of the range start within the first fetched chunk's bytes.
    pub offset_in_first: usize,
}

/// Parse an HTTP `Range` header value of the form `bytes=START-END`, `bytes=START-`, or
/// `bytes=-SUFFIX` against a known `total_size`, returning the inclusive absolute `(start, end)`.
///
/// Only a single range is supported (the common S3 case); multi-range is rejected. Returns an error
/// for an unsatisfiable range, matching the HTTP 416 contract the gateway maps it to.
///
/// ```
/// use ce_storage::range::parse_range;
/// assert_eq!(parse_range("bytes=0-99", 1000).unwrap(), (0, 99));   // explicit window
/// assert_eq!(parse_range("bytes=500-", 1000).unwrap(), (500, 999)); // open-ended → to end
/// assert_eq!(parse_range("bytes=-100", 1000).unwrap(), (900, 999)); // suffix → last N bytes
/// assert_eq!(parse_range("bytes=0-99999", 1000).unwrap(), (0, 999)); // end clamps to size-1
/// assert!(parse_range("bytes=2000-3000", 1000).is_err());           // unsatisfiable → 416
/// ```
pub fn parse_range(header: &str, total_size: u64) -> Result<(u64, u64)> {
    let spec = header
        .trim()
        .strip_prefix("bytes=")
        .ok_or_else(|| anyhow::anyhow!("range must start with 'bytes='"))?;
    if spec.contains(',') {
        bail!("multiple ranges are not supported");
    }
    let (a, b) = spec
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("malformed range: {header}"))?;

    if total_size == 0 {
        bail!("range not satisfiable: empty object");
    }

    let (start, end) = match (a.trim(), b.trim()) {
        // bytes=-N  → last N bytes
        ("", suffix) => {
            let n: u64 = suffix
                .parse()
                .map_err(|_| anyhow::anyhow!("bad suffix length"))?;
            if n == 0 {
                bail!("range not satisfiable: zero-length suffix");
            }
            let n = n.min(total_size);
            (total_size - n, total_size - 1)
        }
        // bytes=S-  → from S to end
        (s, "") => {
            let start: u64 = s.parse().map_err(|_| anyhow::anyhow!("bad range start"))?;
            (start, total_size - 1)
        }
        // bytes=S-E → inclusive window
        (s, e) => {
            let start: u64 = s.parse().map_err(|_| anyhow::anyhow!("bad range start"))?;
            let end: u64 = e.parse().map_err(|_| anyhow::anyhow!("bad range end"))?;
            (start, end.min(total_size - 1))
        }
    };

    if start > end || start >= total_size {
        bail!("range not satisfiable: start={start} end={end} size={total_size}");
    }
    Ok((start, end))
}

/// Compute the chunks covering inclusive byte range `[start, end]` of an object described by
/// `manifest`. Pure: no network. The caller fetches `chunk_indices` (in order), concatenates them,
/// and slices `[offset_in_first .. offset_in_first + length]` out of the concatenation.
pub fn covering(manifest: &Manifest, start: u64, end: u64) -> Result<CoveringRange> {
    if manifest.chunk_size == 0 {
        bail!("manifest has zero chunk_size");
    }
    if start > end || end >= manifest.total_size {
        bail!(
            "range [{start},{end}] out of bounds for object of {} bytes",
            manifest.total_size
        );
    }
    let cs = manifest.chunk_size;
    let first = (start / cs) as usize;
    let last = (end / cs) as usize;
    if last >= manifest.chunks.len() {
        bail!("range exceeds manifest chunk count");
    }
    let chunk_indices: Vec<usize> = (first..=last).collect();
    let offset_in_first = (start - (first as u64) * cs) as usize;
    Ok(CoveringRange {
        start,
        end,
        length: end - start + 1,
        chunk_indices,
        offset_in_first,
    })
}

/// Slice the exact range bytes out of the concatenation of the covering chunks. `concat` must be
/// the covering chunks joined in order; `range.offset_in_first` and `range.length` index into it.
pub fn slice<'a>(range: &CoveringRange, concat: &'a [u8]) -> Result<&'a [u8]> {
    let start = range.offset_in_first;
    let end = start
        .checked_add(range.length as usize)
        .ok_or_else(|| anyhow::anyhow!("range length overflow"))?;
    if end > concat.len() {
        bail!("covering chunks are shorter than the requested range");
    }
    Ok(&concat[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_rs::data;

    fn manifest_for(total: usize, chunk: usize) -> Manifest {
        let bytes = vec![0u8; total];
        let (m, _) = data::chunk_object(&bytes, chunk);
        m
    }

    #[test]
    fn parse_basic_ranges() {
        assert_eq!(parse_range("bytes=0-99", 1000).unwrap(), (0, 99));
        assert_eq!(parse_range("bytes=500-", 1000).unwrap(), (500, 999));
        assert_eq!(parse_range("bytes=-100", 1000).unwrap(), (900, 999));
        // end clamps to size-1
        assert_eq!(parse_range("bytes=0-99999", 1000).unwrap(), (0, 999));
    }

    #[test]
    fn parse_rejects_bad() {
        assert!(parse_range("0-99", 1000).is_err());
        assert!(parse_range("bytes=0-0,5-9", 1000).is_err());
        assert!(parse_range("bytes=2000-3000", 1000).is_err());
        assert!(parse_range("bytes=0-0", 0).is_err());
    }

    #[test]
    fn covering_single_chunk() {
        let m = manifest_for(300, 100); // 3 chunks of 100
        let c = covering(&m, 10, 50).unwrap();
        assert_eq!(c.chunk_indices, vec![0]);
        assert_eq!(c.offset_in_first, 10);
        assert_eq!(c.length, 41);
    }

    #[test]
    fn covering_spans_chunks() {
        let m = manifest_for(300, 100);
        let c = covering(&m, 90, 210).unwrap();
        assert_eq!(c.chunk_indices, vec![0, 1, 2]);
        assert_eq!(c.offset_in_first, 90);
        assert_eq!(c.length, 121);
    }

    #[test]
    fn slice_extracts_window() {
        // object = 0..255 repeated; verify the sliced range equals the original window.
        let total: usize = 250;
        let chunk: usize = 64;
        let bytes: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let (m, chunks) = data::chunk_object(&bytes, chunk);
        let (start, end) = (70u64, 200u64);
        let cov = covering(&m, start, end).unwrap();
        // concat the covering chunks
        let mut concat = Vec::new();
        for &i in &cov.chunk_indices {
            concat.extend_from_slice(&chunks[i].1);
        }
        let got = slice(&cov, &concat).unwrap();
        assert_eq!(got, &bytes[start as usize..=end as usize]);
    }

    #[test]
    fn out_of_bounds_covering_errors() {
        let m = manifest_for(100, 100);
        assert!(covering(&m, 50, 200).is_err());
    }
}
