use std::{fs::File, io::Write, error::Error};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509Name};
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use rand::random;

fn generate_certificate(
    subject_name: &str,
    ca_name: &str,
) -> Result<(String, String), Box<dyn Error>> {

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    let rand_num = random::<u64>();
    let big_num = BigNum::from_dec_str(&rand_num.to_string())?;
    let serial_number = Asn1Integer::from_bn(&big_num)?;


    let rsa = Rsa::generate(4096)?;
    let private_key = PKey::from_rsa(rsa)?;

    let mut builder = X509Builder::new()?;
    let mut x509_name = X509Name::builder()?;
    x509_name.append_entry_by_nid(Nid::COMMONNAME, subject_name)?;
    let subject_name = x509_name.build();

    let mut issuer_name = X509Name::builder()?;
    issuer_name.append_entry_by_text("CN", ca_name)?;
    let issuer_name = issuer_name.build();

    builder.set_subject_name(&subject_name)?;
    builder.set_issuer_name(&issuer_name)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.set_pubkey(&private_key)?;
    builder.set_serial_number(&serial_number)?;

    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(basic_constraints)?;
    let key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .key_encipherment()
        .build()?;
    builder.append_extension(key_usage)?;

    builder.sign(&private_key, MessageDigest::sha256())?;
    
    let certificate = builder.build();
    let private_key_pem = private_key.private_key_to_pem_pkcs8()?;
    let certificate_pem = certificate.to_pem()?;
    let subject_key_file = "server.key";
    let mut output_key_file = File::create(subject_key_file)?;
    output_key_file.write_all(private_key_pem.as_slice())?;

    let subject_cert_file = "server.pem";
    let mut output_cert_file = File::create(subject_cert_file)?;
    output_cert_file.write_all(certificate_pem.as_slice())?;

    Ok((subject_key_file.to_string(), subject_cert_file.to_string()))}
fn main() {
    match generate_certificate("jb.tkirk.land", "Local CA") {
        Ok((key_file, cert_file)) => {
            println!("Private key file: {}", key_file);
            println!("Certificate file: {}", cert_file);
        }
        Err(e) => println!("There was an error: {}", e),
    }
}
