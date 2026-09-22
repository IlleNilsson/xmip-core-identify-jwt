#![forbid(unsafe_code)]

//! Identify by jwt: a JSON Web Token's subject, read and not verified.
//!
//! RFC 7519 carries its claims as base64url JSON, so who the token says it is
//! for can be read by anyone who holds it. This identifier reads exactly that
//! — `sub` by default, or the claim the configuration names — and calls it
//! the claim; the issuer rides beside it as evidence and the token itself as
//! proof, for `authenticate/jwt` to check the signature, expiry, issuer and
//! audience. Nothing here checks any of them: a token with a forged
//! signature is presented exactly as a good one, because presenting is all
//! the first gate does.
//!
//! The mechanism travels on both layers (ADR-0050 section 3). On the
//! transport layer the token is in the `Authorization` header under the
//! `Bearer` scheme, or in whichever property the configuration names; on the
//! message layer the first section *is* the token, as `application/jwt`
//! carries it. A bearer value that is not three base64url parts around two
//! dots is an opaque token and `bearer`'s business, not this leaf's.
//!
//! What this reads and writes:
//!
//! ```text
//! http.header.authorization   Bearer <token>            the property, by default
//! jwt.issuer                  the iss claim             evidence
//! principal.user              upn, preferred_username   evidence, where it is one
//! principal.service           azp, appid                evidence, where it is one
//! jwt.token                   the compact token         proof
//! ```
//!
//! Principal evidence, in the capability's canonical form (ADR-0054): the
//! `upn` claim, else `preferred_username`, where it is a user principal name;
//! and for an application's token — `idtyp` is `app`, or neither of those
//! claims is there and `azp` or `appid` is — the application's identifier
//! where it is a service principal name. An opaque identifier is not one, and
//! nothing is added for it. The claim's value does not change.
//!
//! Only a pushed arrival carries a passed claim; where Xmip fetched the
//! Stream the token in play was Xmip's own.

use identify::jwt::{self, Compact};
use identify::{IdentifyError, MessageIdentifier, Presented, StreamArrival, TransportIdentifier};
use message::Message;
use xcore::{Arriving, Mechanism};

/// The property read by default: the HTTP `Authorization` header.
pub const AUTHORIZATION: &str = "http.header.authorization";
/// The media type of a section that is a token.
pub const MEDIA_TYPE: &str = "application/jwt";
/// The evidence name carrying the issuer.
pub const ISSUER: &str = "jwt.issuer";
/// The proof name the compact token rides under.
pub const TOKEN_PROOF: &str = "jwt.token";

/// Reads a token's subject, from a header or from the content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Jwt {
    property: String,
    scheme: Option<String>,
    claim: String,
}

impl Jwt {
    /// The token under `Bearer` in the `Authorization` header, `sub` the claim.
    #[must_use]
    pub fn bearer() -> Self {
        Self {
            property: AUTHORIZATION.to_string(),
            scheme: Some("Bearer".to_string()),
            claim: "sub".to_string(),
        }
    }

    /// The bare token in a named property — a custom header the transport
    /// promoted as `http.header.<name>`, or a message property.
    #[must_use]
    pub fn in_property(property: impl Into<String>) -> Self {
        Self {
            property: property.into(),
            scheme: None,
            claim: "sub".to_string(),
        }
    }

    /// Present this claim rather than `sub`.
    #[must_use]
    pub fn claiming(mut self, claim: impl Into<String>) -> Self {
        self.claim = claim.into();
        self
    }

    /// The token the property carries, where it carries one under the scheme.
    fn token<'a>(&self, raw: &'a str) -> Option<&'a str> {
        jwt::carried(raw, self.scheme.as_deref())
    }

    fn present(&self, token: &str) -> Result<Presented, IdentifyError> {
        let compact = Compact::parse(token)?;
        let Some(value) = compact.claim(&self.claim) else {
            return Err(IdentifyError::new(format!(
                "the token carries no `{}` claim",
                self.claim
            )));
        };

        let mut claim = Presented::passed(TransportIdentifier::mechanism(self), value);
        if let Some(issuer) = compact.claim("iss") {
            claim = claim.with_evidence(ISSUER, issuer);
        }
        if let Some(name) = compact.principal() {
            claim = claim.with_evidence(name.evidence(), name.to_string());
        }
        Ok(claim.with_proof(TOKEN_PROOF, token))
    }
}

impl TransportIdentifier for Jwt {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::jwt()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }
        match arrival
            .property(&self.property)
            .and_then(|raw| self.token(raw))
        {
            Some(token) => self.present(token).map(Some),
            None => Ok(None),
        }
    }
}

impl MessageIdentifier for Jwt {
    fn mechanism(&self) -> Mechanism {
        TransportIdentifier::mechanism(self)
    }

    fn identify(&self, message: &Message) -> Result<Option<Presented>, IdentifyError> {
        let Some(section) = message.sections().first() else {
            return Ok(None);
        };
        let declared = section.stream.media_type() == Some(MEDIA_TYPE);
        let Some(text) = core::str::from_utf8(section.stream.bytes())
            .ok()
            .map(str::trim)
        else {
            return if declared {
                Err(IdentifyError::new(
                    "the application/jwt section is not text",
                ))
            } else {
                Ok(None)
            };
        };
        if !jwt::is_compact(text) {
            return if declared {
                Err(IdentifyError::new(
                    "the application/jwt section is not a compact token",
                ))
            } else {
                Ok(None)
            };
        }
        self.present(text).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use context::MessageContext;
    use identify::principal;
    use message::{MessageSection, MessageTreatment};
    use stream::Stream;
    use xcore::{Established, Layer, MessageId, SectionId, StreamId};

    fn token(claims: &str) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#),
            URL_SAFE_NO_PAD.encode(claims),
            URL_SAFE_NO_PAD.encode(b"signature")
        )
    }

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"<order/>".to_vec(), None)
    }

    fn authorization(value: &str) -> Vec<(String, String)> {
        vec![(AUTHORIZATION.to_string(), value.to_string())]
    }

    fn message(bytes: &[u8], media_type: Option<&str>) -> Message {
        Message::received(
            MessageId::new(1),
            vec![MessageSection {
                section_id: SectionId::new(2),
                name: None,
                stream: Stream::new(
                    StreamId::new(3),
                    bytes.to_vec(),
                    media_type.map(String::from),
                ),
                contract: None,
            }],
            MessageContext::new(),
            MessageTreatment::default(),
        )
    }

    #[test]
    fn a_bearer_token_is_presented_by_its_subject_with_the_issuer_beside_and_the_token_as_proof() {
        let stream = stream();
        let minted = token(r#"{"iss":"https://idp.example","sub":"partner-x","exp":1}"#);
        let properties = authorization(&format!("bearer {minted}"));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = TransportIdentifier::identify(&Jwt::bearer(), &arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "partner-x");
        assert_eq!(claim.established, Established::Passed);
        assert_eq!(claim.layer(), Layer::Transport);
        assert_eq!(claim.mechanism.name(), "jwt");
        assert_eq!(
            claim.evidence,
            vec![(ISSUER.to_string(), "https://idp.example".to_string())]
        );
        assert_eq!(claim.proof(TOKEN_PROOF), Some(minted.as_str()));
    }

    #[test]
    fn an_opaque_bearer_token_and_another_scheme_present_nothing() {
        let stream = stream();
        for value in [
            "Bearer 2YotnFZFEjr1zCsicMWpAA",
            "Basic cGFydG5lcjpzZWNyZXQ=",
        ] {
            let properties = authorization(value);
            let arrival =
                StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

            assert!(
                TransportIdentifier::identify(&Jwt::bearer(), &arrival)
                    .expect("read")
                    .is_none(),
                "{value}"
            );
        }
    }

    #[test]
    fn an_arrival_without_the_header_presents_nothing() {
        let stream = stream();
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &[]);

        assert!(
            TransportIdentifier::identify(&Jwt::bearer(), &arrival)
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn a_token_that_does_not_decode_is_an_error_naming_why() {
        let stream = stream();
        let properties = authorization("Bearer aQ.b!!.aQ");
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let failure =
            TransportIdentifier::identify(&Jwt::bearer(), &arrival).expect_err("not base64url");

        assert!(failure.message.contains("base64url"), "{failure}");
    }

    #[test]
    fn a_token_without_the_claim_is_an_error_naming_the_claim() {
        let stream = stream();
        let minted = token(r#"{"iss":"https://idp.example"}"#);
        let properties = authorization(&format!("Bearer {minted}"));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let failure = TransportIdentifier::identify(&Jwt::bearer().claiming("client_id"), &arrival)
            .expect_err("no claim");

        assert!(failure.message.contains("`client_id`"), "{failure}");
    }

    #[test]
    fn a_configured_property_carries_the_bare_token_under_a_configured_claim() {
        let stream = stream();
        let minted = token(r#"{"sub":"partner-x","azp":"orders-client"}"#);
        let properties = [("http.header.x-id-token".to_string(), minted)];
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = TransportIdentifier::identify(
            &Jwt::in_property("http.header.x-id-token").claiming("azp"),
            &arrival,
        )
        .expect("read")
        .expect("a claim");

        assert_eq!(claim.value, "orders-client");
    }

    fn presented(claims: &str) -> Presented {
        let stream = stream();
        let properties = authorization(&format!("Bearer {}", token(claims)));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        TransportIdentifier::identify(&Jwt::bearer(), &arrival)
            .expect("read")
            .expect("a claim")
    }

    fn principals(claim: &Presented) -> Vec<(&str, &str)> {
        claim
            .evidence
            .iter()
            .filter(|(name, _)| name.starts_with("principal."))
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    #[test]
    fn a_users_principal_name_is_written_beside_the_subject_in_canonical_form() {
        let claim = presented(r#"{"sub":"u-17","upn":"Jane@Partner-X.Example"}"#);
        assert_eq!(claim.value, "u-17", "the value stays the subject");
        assert_eq!(
            principals(&claim),
            [(principal::USER, "Jane@partner-x.example")]
        );

        let claim = presented(r#"{"sub":"u-17","preferred_username":"PARTNERX\\jane"}"#);
        assert_eq!(principals(&claim), [(principal::USER, "jane@partnerx")]);
    }

    #[test]
    fn an_applications_token_names_a_service_only_where_its_identifier_is_one() {
        let claim = presented(concat!(
            r#"{"sub":"a-1","idtyp":"app","upn":"jane@partner-x.example","#,
            r#""azp":"HTTP/Orders.Example@EXAMPLE.COM"}"#,
        ));
        assert_eq!(
            principals(&claim),
            [(principal::SERVICE, "HTTP/orders.example@example.com")]
        );

        let claim = presented(r#"{"sub":"a-1","appid":"MSSQLSvc/DB01.Example:1433"}"#);
        assert_eq!(
            principals(&claim),
            [(principal::SERVICE, "MSSQLSvc/db01.example:1433")]
        );
    }

    #[test]
    fn text_that_is_not_a_principal_name_gains_no_principal_evidence() {
        for claims in [
            r#"{"sub":"u-17","preferred_username":"jane"}"#,
            r#"{"sub":"a-1","idtyp":"app","appid":"6f1c2a9e-3b7d-4c55-9e0a-2d1f8b7c4e11"}"#,
            r#"{"sub":"a-1","azp":"api://orders"}"#,
            r#"{"sub":"u-17","preferred_username":"jane","azp":"HTTP/orders.example"}"#,
            r#"{"sub":"jane@partner-x.example"}"#,
        ] {
            assert!(principals(&presented(claims)).is_empty(), "{claims}");
        }
    }

    #[test]
    fn a_section_that_is_a_token_is_read_on_the_message_layer() {
        let minted = token(r#"{"sub":"partner-x"}"#);

        let claim = MessageIdentifier::identify(
            &Jwt::bearer(),
            &message(minted.as_bytes(), Some(MEDIA_TYPE)),
        )
        .expect("read")
        .expect("a claim");

        assert_eq!(claim.value, "partner-x");
        assert_eq!(claim.proof(TOKEN_PROOF), Some(minted.as_str()));
    }

    #[test]
    fn content_that_is_not_a_token_presents_nothing_unless_it_said_it_was_one() {
        assert!(
            MessageIdentifier::identify(&Jwt::bearer(), &message(b"<order/>", None))
                .expect("read")
                .is_none()
        );

        let failure =
            MessageIdentifier::identify(&Jwt::bearer(), &message(b"<order/>", Some(MEDIA_TYPE)))
                .expect_err("declared and not a token");

        assert!(failure.message.contains("not a compact token"), "{failure}");
    }

    #[test]
    fn a_scheduled_pickup_presents_nothing_because_the_token_was_xmips_own() {
        let stream = stream();
        let properties = authorization(&format!("Bearer {}", token(r#"{"sub":"xmip"}"#)));
        let arrival =
            StreamArrival::new(&stream, Arriving::Scheduled, "https://api/out", &properties);

        assert!(
            TransportIdentifier::identify(&Jwt::bearer(), &arrival)
                .expect("read")
                .is_none()
        );
    }
}
