//! Error module.

use ark_std::string::String;
use ark_serialize::SerializationError;
use displaydoc::Display;

/// A `enum` specifying the possible failure modes of the Transcript.
#[derive(Display, Debug)]
pub enum TranscriptError {
    /// Invalid Transcript: {0}
    InvalidTranscript(String),
    /// An error during (de)serialization: {0}
    SerializationError(SerializationError),
}

impl From<SerializationError> for TranscriptError {
    fn from(e: SerializationError) -> Self {
        Self::SerializationError(e)
    }
}

pub enum PedersenErrors {
    /// Invalid Prover: {0}
    InvalidProver(String),
    /// Invalid Verifier: {0}
    InvalidVerifier(String),
    /// Invalid Proof: {0}
    InvalidProof(String),
    /// Invalid parameters: {0}
    InvalidParameters(String),
    /// An error during (de)serialization: {0}
    SerializationError(SerializationError),
}

impl From<SerializationError> for PedersenErrors {
    fn from(e: SerializationError) -> Self {
        Self::SerializationError(e)
    }
}

pub enum SchnorrErrors {
    /// Invalid Prover: {0}
    InvalidProver(String),
    /// Invalid Verifier: {0}
    InvalidVerifier(String),
    /// Invalid Proof: {0}
    InvalidProof(String),
    /// Invalid parameters: {0}
    InvalidParameters(String),
    /// Transcript error {0}
    TranscriptError(TranscriptError),
    /// Pedersen error {0}
    PedersenErrors(PedersenErrors),
    /// An error during (de)serialization: {0}
    SerializationError(SerializationError),
}

impl From<TranscriptError> for SchnorrErrors {
    fn from(e: TranscriptError) -> Self {
        Self::TranscriptError(e)
    }
}

impl From<PedersenErrors> for SchnorrErrors {
    fn from(e: PedersenErrors) -> Self {
        Self::PedersenErrors(e)
    }
}

impl From<SerializationError> for SchnorrErrors {
    fn from(e: SerializationError) -> Self {
        Self::SerializationError(e)
    }
}
