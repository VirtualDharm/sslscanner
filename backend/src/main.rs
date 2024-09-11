use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::ToSocketAddrs;
use warp::{http::Method, Filter};

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
        .allow_methods(&[Method::GET]);         // Allow only GET requests
        // .allow_headers(vec!["content-type"]);  // Allow content-type header

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

    // Create a client that can bypass SSL certificate errors
    let client = Client::builder().danger_accept_invalid_certs(true).build()?;

    // Format the domain as a URL
    let url = format!("https://{}", domain);
    println!("Formatted URL: {}", url);

    // Send an HTTPS request to the domain
    let _response = client.get(&url).send().await?;
    println!("Sent HTTPS request to domain: {}", domain);

    // Resolve the domain into a socket address (used to extract SSL certificate)
    let socket_addr = format!("{}:443", domain).to_socket_addrs()?.next().unwrap();
    println!("Resolved domain {} to socket address: {:?}", domain, socket_addr);

    // Placeholder for real certificate extraction logic
    let _ssl_cert = extract_certificate(socket_addr)?;
    println!("SSL certificate extracted for domain: {}", domain);

    // Return mock SSL certificate details (replace with real data from extraction logic)
    let cert_details = CertificateDetails {
        validity_status: true,                     // Example value: the certificate is valid
        expiration_date: "2024-01-01".to_string(), // Example expiration date
        issuer_details: "Example Issuer".to_string(), // Example issuer
        subject_details: "Example Subject".to_string(), // Example subject details
        is_self_signed: false,                     // Example: the certificate is not self-signed
        is_valid_for_domain: true,                 // Example: the certificate is valid for the domain
        revocation_status: "Not Revoked".to_string(), // Example revocation status
    };

    println!("SSL certificate details generated for domain: {}", domain);
    Ok(cert_details)
}

// Placeholder function for actual SSL certificate extraction
fn extract_certificate(_socket: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    // Implement the actual logic to extract and parse the SSL certificate from the socket address
    println!("Extracting certificate for the socket address...");
    Ok(())
}
