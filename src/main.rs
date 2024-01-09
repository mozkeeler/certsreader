use base64::Engine;
use nom::bytes::complete::tag;
use nom::character::complete::u8;
use nom::multi::separated_list0;
use nom::sequence::{preceded, terminated};
use nom::IResult;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result};

fn certificate(s: &str) -> IResult<&str, Vec<u8>> {
    preceded(
        tag("["),
        terminated(separated_list0(tag(","), u8), tag("]")),
    )(s)
}

fn certificates(s: &str) -> IResult<&str, Vec<Vec<u8>>> {
    preceded(
        tag("["),
        terminated(separated_list0(tag(","), certificate), tag("]")),
    )(s)
}

fn binary_to_pem(binary: &[u8]) -> String {
    let base64 = base64::engine::general_purpose::STANDARD.encode(binary);
    let chunks = base64.as_bytes().chunks(64).map(|chunk| std::str::from_utf8(chunk).unwrap()).collect::<Vec<&str>>().join("\n");
    chunks
}

fn main() -> Result<()> {
    let filename = std::env::args()
        .skip(1)
        .next()
        .ok_or(Error::new(ErrorKind::InvalidData, "invalid arg"))?;
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let contents = contents.replace(char::is_whitespace, "");
    let raw_certificates = match certificates(&contents) {
        Ok((_, raw_certificates)) => raw_certificates,
        Err(e) => {
            dbg!(e);
            return Err(Error::new(ErrorKind::InvalidData, "invalid input"));
        }
    };
    for raw_certificate in raw_certificates {
        let certificate = match X509Certificate::from_der(&raw_certificate) {
            Ok((_, certificate)) => certificate,
            Err(e) => {
                dbg!(e);
                return Err(Error::new(ErrorKind::InvalidData, "invalid input"));
            }
        };
        println!("Issuer: {}", certificate.issuer());
        println!("Subject: {}", certificate.subject());
        println!("-----BEGIN CERTIFICATE-----");
        println!("{}", binary_to_pem(&raw_certificate));
        println!("-----END CERTIFICATE-----");
    }
    Ok(())
}
