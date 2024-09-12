use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::convert::TryFrom;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, rustls::ClientConfig};
use rustls::{Certificate, RootCertStore, ServerName};
use warp::{http::Method, Filter};
use rustls::OwnedTrustAnchor;
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::prelude::*;
use x509_parser::extensions::GeneralName;

// Define the structure to hold SSL certificate details
#[derive(Serialize, Deserialize)]
struct CertificateDetails {
    validity_status: bool,
    expiration_date: String,
    issuer_details: String,
    subject_details: String,
    is_self_signed: bool,
    is_valid_for_domain: bool,
    revocation_status: String,
}

#[tokio::main]
async fn main() {
    println!("Starting Warp server at http://localhost:3030");

    // Define the CORS filter to allow requests from localhost:3000
    let cors = warp::cors()
        .allow_origin("http://localhost:3000") // Allow requests from localhost:3000
        .allow_methods(vec![Method::GET]);     // Allow only GET requests

    // Define the API route for SSL certificate checks
    let ssl_route = warp::path!("ssl" / String)
        .and_then(handle_ssl_request)  // Handle the SSL request
        .with(cors);                   // Apply CORS filter to the route

    // Start the Warp server on localhost:3030
    warp::serve(ssl_route)
        .run(([127, 0, 0, 1], 3030))
        .await;
}

// Handle incoming SSL API requests for a given domain
async fn handle_ssl_request(domain: String) -> Result<impl warp::Reply, warp::Rejection> {
    println!("Received request to check SSL certificate for domain: {}", domain);

    // Fetch the SSL certificate details for the domain
    match fetch_ssl_certificate(&domain).await {
        Ok(cert) => {
            println!("Successfully fetched SSL certificate details for domain: {}", domain);
            Ok(warp::reply::json(&cert)) // Return the certificate details as JSON
        },
        Err(e) => {
            println!("Failed to fetch SSL certificate for domain: {}. Error: {}", domain, e);
            Err(warp::reject::not_found()) // Return 404 if an error occurs
        },
    }
}

// Fetch and process SSL certificate details for a given domain
async fn fetch_ssl_certificate(domain: &str) -> Result<CertificateDetails, Box<dyn std::error::Error>> {
    println!("Attempting to fetch SSL certificate for domain: {}", domain);

    // Establish TCP connection
    let addr = format!("{}:443", domain);
    let stream = TcpStream::connect(addr).await?;

    // Load the root certificates
    let root_cert_store = load_root_cert_store();
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    // Create the TLS connector
    let connector = TlsConnector::from(Arc::new(config));

    // Convert the domain to a ServerName
    let dns_name = ServerName::try_from(domain).map_err(|_| "Invalid domain name")?;

    // Establish the TLS connection
    let tls_stream = connector.connect(dns_name, stream).await?;

    // Extract the certificate chain
    let cert_chain = tls_stream.get_ref().1.peer_certificates().ok_or("No peer certificates found")?;

    // Parse the certificate and extract the details
    let cert_details = parse_and_extract_certificate(&cert_chain[0], domain)?;

    Ok(cert_details)
}

// Parses and extracts real SSL certificate details from the certificate
fn parse_and_extract_certificate(cert: &Certificate, domain: &str) -> Result<CertificateDetails, Box<dyn std::error::Error>> {
    let der = cert.0.as_slice();  // Get the raw DER-encoded certificate
    let (_, parsed_cert) = X509Certificate::from_der(der)?;

    // Validity Status
    let validity_status = parsed_cert.validity().is_valid();

    // Expiration Date
    let expiration_date = parsed_cert.validity().not_after.to_rfc2822();

    // Issuer Details
    let issuer_details = parsed_cert.issuer().to_string();

    // Subject Details
    let subject_details = parsed_cert.subject().to_string();

    // Check if the certificate is self-signed (issuer and subject are the same)
    let is_self_signed = parsed_cert.issuer() == parsed_cert.subject();

    // Check if the certificate is valid for the domain
    let is_valid_for_domain = verify_domain_name(&parsed_cert, domain);

    // Revocation status (for simplicity, we'll leave it as "Not Revoked")
    let revocation_status = "Not Revoked".to_string();

    let cert_details = CertificateDetails {
        validity_status,
        expiration_date,
        issuer_details,
        subject_details,
        is_self_signed,
        is_valid_for_domain,
        revocation_status,
    };

    Ok(cert_details)
}

// Verifies if the certificate is valid for the given domain
fn verify_domain_name(cert: &X509Certificate, domain: &str) -> bool {
    // Extract the SAN (Subject Alternative Name) from the certificate extensions
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in san.general_names.iter() {
                if let GeneralName::DNSName(dns_name) = name {
                    // Dereference dns_name to compare with domain
                    if *dns_name == domain {
                        return true;
                    }
                }
            }
        }
    }

    // Fallback to check the Common Name (CN) in the subject
    if let Some(cn) = cert.subject().iter_common_name().next() {
        return cn.as_str() == Ok(domain);
    }

    false
}

// Load root certificates
fn load_root_cert_store() -> RootCertStore {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    root_cert_store
}
