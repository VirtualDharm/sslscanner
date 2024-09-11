import { useState } from "react";
import axios from "axios";

export default function Home() {
  const [domain, setDomain] = useState("");
  const [certDetails, setCertDetails] = useState(null);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Remove http:// or https:// from the input domain, if present
    let cleanedDomain = domain.replace(/(^\w+:|^)\/\//, "");

    try {
      const res = await axios.get(`http://localhost:3030/ssl/${cleanedDomain}`);
      setCertDetails(res.data);
      setError(null);
    } catch (err) {
      setError("Failed to fetch certificate details.");
      setCertDetails(null);
    }
  };

  return (
    <div>
      <h1>SSL Certificate Checker</h1>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Enter domain (e.g., www.example.com)"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
        />
        <button type="submit">Check</button>
      </form>

      {error && <p>{error}</p>}
      {certDetails && (
        <div>
          <h2>Certificate Details</h2>
          <p><strong>Validity Status:</strong> {certDetails.validity_status ? "Valid" : "Invalid"}</p>
          <p><strong>Expiration Date:</strong> {certDetails.expiration_date}</p>
          <p><strong>Issuer Details:</strong> {certDetails.issuer_details}</p>
          <p><strong>Subject Details:</strong> {certDetails.subject_details}</p>
          <p><strong>Is Self-Signed:</strong> {certDetails.is_self_signed ? "Yes" : "No"}</p>
          <p><strong>Revocation Status:</strong> {certDetails.revocation_status}</p>
        </div>
      )}
    </div>
  );
}
