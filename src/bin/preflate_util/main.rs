use preflate_rs::preflate_error::PreflateError;

use clap::Parser;
use std::{fs::File, io::Read, path::PathBuf};

/// A very simple utility to search for a string across multiple files.
#[derive(Debug, Parser)]
#[clap(name = "preflate_util")]
pub struct PreflateUtil {
    #[clap(long, short = 'i')]
    input_file: PathBuf,
}

fn main_with_result() -> anyhow::Result<()> {
    let args = PreflateUtil::parse();

    let input_file = args.input_file;

    let mut f = File::open(input_file)?;

    let mut content = Vec::new();
    f.read_to_end(&mut content).unwrap();

    let result = preflate_rs::decompress_deflate_stream(&content, true)?;

    let recomp = preflate_rs::recompress_deflate_stream(&result.plain_text, &result.cabac_encoded)?;

    if content[..] != recomp[..] {
        return Err(anyhow::anyhow!("recompressed data does not match original"));
    }

    Ok(())
}

fn main() {
    match main_with_result() {
        Ok(_) => {}
        Err(e) => match e.root_cause().downcast_ref::<PreflateError>() {
            // try to extract the exit code if it was a well known error
            Some(x) => {
                eprintln!("error code: {0:?}", x);
                std::process::exit(-1);
            }
            None => {
                eprintln!("unknown error {0:?}", e);
                std::process::exit(-2);
            }
        },
    }
}
