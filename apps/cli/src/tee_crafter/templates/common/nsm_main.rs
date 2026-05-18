use aws_nitro_enclaves_nsm_api::driver::{nsm_init, nsm_process_request, nsm_exit};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use base64::{engine::general_purpose, Engine as _};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut nonce_bytes = vec![];
    let mut pub_key_bytes: Option<Vec<u8>> = None;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--nonce" && i + 1 < args.len() {
            nonce_bytes = general_purpose::STANDARD.decode(&args[i+1]).expect("Invalid base64 nonce");
            i += 2;
        } else if args[i] == "--public-key" && i + 1 < args.len() {
            pub_key_bytes = Some(general_purpose::STANDARD.decode(&args[i+1]).expect("Invalid base64 pubkey"));
            i += 2;
        } else {
            i += 1;
        }
    }

    let fd = nsm_init();
    if fd < 0 { eprintln!("Failed to initialize NSM"); std::process::exit(1); }

    let pk_buf = pub_key_bytes.map(serde_bytes::ByteBuf::from);
    let nonce_buf = if nonce_bytes.is_empty() { None } else { Some(serde_bytes::ByteBuf::from(nonce_bytes)) };

    let req = Request::Attestation { user_data: None, nonce: nonce_buf, public_key: pk_buf };
    let resp = nsm_process_request(fd, req);

    if let Response::Attestation { document } = resp {
        print!("{}", general_purpose::STANDARD.encode(document));
    } else {
        eprintln!("Failed to get attestation doc: {:?}", resp);
        std::process::exit(1);
    }
    nsm_exit(fd);
}
