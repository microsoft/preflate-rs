use std::io::Cursor;

use cabac::fpaq0::{Fpaq0Decoder, Fpaq0Encoder};
use cabac::fpaq0parallel::{
    BypassBitDecoder, BypassBitEncoder, Fpaq0DecoderParallel, Fpaq0EncoderParallel,
    ParallelEncoderOutput,
};
use cabac::rans32::{RansReader32, RansWriter32};
use cabac::vp8::{VP8Context, VP8Reader, VP8Writer};
use cabac::{CabacReader, CabacWriter};

#[derive(Clone, Copy)]
enum Seq {
    Normal(bool, usize),
    Bypass(bool),
}

fn do_write<C: Default, CW: CabacWriter<C>>(seq: &[Seq], mut writer: CW) {
    let mut context = Vec::new();
    for _i in 0..16 {
        context.push(C::default());
    }

    for &s in seq {
        match s {
            Seq::Normal(b, c) => writer.put(b, &mut context[c]).unwrap(),
            Seq::Bypass(b) => writer.put_bypass(b).unwrap(),
        }
    }

    writer.finish().unwrap();
}

fn do_read<C: Default, CR: CabacReader<C>>(seq: &[Seq], mut reader: CR, scheme: &str) {
    {
        let mut context = Vec::new();
        for _ in 0..16 {
            context.push(C::default());
        }

        for (i, s) in seq.iter().enumerate() {
            match *s {
                Seq::Normal(b, c) => {
                    assert_eq!(
                        b,
                        reader.get(&mut context[c]).unwrap(),
                        "offset:{i} scheme:{scheme}"
                    );
                }
                Seq::Bypass(b) => {
                    assert_eq!(
                        b,
                        reader.get_bypass().unwrap(),
                        "offset:{i} scheme:{scheme}"
                    );
                }
            }
        }
    }
}

fn test_seq_vp8(seq: &[Seq]) {
    let mut vec = Vec::new();
    do_write(seq, VP8Writer::new(&mut vec).unwrap());
    do_read(seq, VP8Reader::new(Cursor::new(&vec)).unwrap(), "vp8");
}

fn test_seq_rans(seq: &[Seq]) {
    let mut vec = Vec::new();
    do_write(seq, RansWriter32::new(&mut vec));
    do_read(seq, RansReader32::new(Cursor::new(&vec)).unwrap(), "rans");
}

fn test_seq_fpaq(seq: &[Seq]) {
    let mut vec = Vec::new();
    do_write(seq, Fpaq0Encoder::new(&mut vec));
    do_read(seq, Fpaq0Decoder::new(Cursor::new(&vec)).unwrap(), "fpaq");
}

/// FPAQ parallel encoder/decoder
fn test_seq_fpaq_parallel(seq: &[Seq]) {
    let mut vec = Vec::new();

    {
        let mut encoder_output = ParallelEncoderOutput::new(&mut vec);

        let mut context = Vec::new();
        let mut writers: Vec<Fpaq0EncoderParallel> = Vec::new();
        for _i in 0..16 {
            context.push(VP8Context::default());
            writers.push(Fpaq0EncoderParallel::new(&mut encoder_output));
        }

        let mut bypassencoder = BypassBitEncoder::new(&mut encoder_output);

        for (i, &s) in seq.iter().enumerate() {
            match s {
                Seq::Normal(b, c) => writers[i % 16]
                    .put(b, &mut context[c], &mut encoder_output)
                    .unwrap(),
                Seq::Bypass(b) => bypassencoder.put(b, &mut encoder_output).unwrap(),
            }
        }

        for writer in writers.iter_mut() {
            writer.finish(&mut encoder_output).unwrap();
        }
        bypassencoder.finish(&mut encoder_output).unwrap();
    }

    let mut bytestreamreader = Cursor::new(&vec);

    let mut context = Vec::new();
    let mut readers = Vec::new();
    for _i in 0..16 {
        context.push(VP8Context::default());
        readers.push(Fpaq0DecoderParallel::new(&mut bytestreamreader).unwrap());
    }

    let mut bypassdecoder = BypassBitDecoder::new(&mut bytestreamreader).unwrap();

    for (i, s) in seq.iter().enumerate() {
        match *s {
            Seq::Normal(b, c) => {
                assert_eq!(
                    b,
                    readers[i % 16]
                        .get(&mut context[c], &mut bytestreamreader)
                        .unwrap(),
                    "offset:{i} scheme:FpaqParallel"
                );
            }
            Seq::Bypass(b) => {
                assert_eq!(
                    b,
                    bypassdecoder.get(&mut bytestreamreader).unwrap(),
                    "offset:{i} scheme:FpaqParallel"
                );
            }
        }
    }
}

fn test_all(seq: &[Seq]) {
    test_seq_vp8(seq);
    test_seq_rans(seq);
    test_seq_fpaq(seq);
    test_seq_fpaq_parallel(seq);
}

#[test]
fn bypass_vp8() {
    let mut output = Vec::new();
    {
        let mut writer = VP8Writer::new(&mut output).unwrap();
        for i in 0..1024 {
            writer.put_bypass((i & 1) != 0).unwrap();
        }

        writer.finish().unwrap();
    }

    {
        let mut reader = VP8Reader::new(Cursor::new(&output)).unwrap();
        for i in 0..1024 {
            assert_eq!(reader.get_bypass().unwrap(), (i & 1) != 0);
        }
    }
}

#[test]
fn test_random_sequences() {
    use rand::Rng;

    let mut rng = rand::thread_rng();

    let probs: [f64; 16] = [
        0.001, 0.01, 0.1, 0.11, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.9, 0.91, 0.99, 0.999, 0.9999, 1.0,
    ];

    for _ in 1..10 {
        let mut seq = Vec::new();

        for _ in 0..100000 {
            let ctx = rng.gen_range(0..16);

            seq.push(match rng.gen_range(0..4) {
                0 | 1 => Seq::Normal(rng.gen_bool(probs[ctx]), ctx),
                2 => Seq::Bypass(false),
                _ => Seq::Bypass(true),
            });
        }

        test_all(&seq);
    }
}

#[test]
fn test_all_0() {
    let all_0 = vec![Seq::Normal(false, 0); 10000];

    test_all(&all_0);
}

#[test]
fn test_all_1() {
    let all_1 = vec![Seq::Normal(true, 0); 10000];

    test_all(&all_1);
}

#[test]
fn test_alt() {
    let mut seq = Vec::new();
    for i in 0..10000 {
        seq.push(Seq::Normal(i % 2 == 0, 0));
    }

    test_all(&seq);
}

#[test]
fn test_alt_bypass() {
    let mut seq = Vec::new();
    for i in 0..10000 {
        seq.push(Seq::Bypass(i % 2 == 0));
    }

    test_all(&seq);
}
