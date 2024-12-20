use ark_std::rand::Rng;
use ark_ec::CurveGroup;

use merlin::Transcript;
use crate::ProofError;

pub trait SchnorrCS {
    /// A handle for a scalar variable in the constraint system.
    type ScalarVar: Copy;
    /// A handle for a group variable in the constraint system.
    type GroupVar: Copy;

    /// Add a constraint of the form `lhs = linear_combination`.
    fn constrain(
        &mut self,
        lhs: Self::GroupVar,
        linear_combination: Vec<(Self::ScalarVar, Self::GroupVar)>,
    );
}

/// This trait defines the wire format for how the constraint system
/// interacts with the proof transcript.
pub trait TranscriptProtocol {
    /// Appends `label` to the transcript as a domain separator.
    fn domain_sep(&mut self, label: &'static [u8]);
    /// Append the `label` for a scalar variable to the transcript.
    fn append_scalar_var(&mut self, label: &'static [u8]);
    /// Append a point variable to the transcript, for use by a prover.
    fn append_group_var<C: CurveGroup>(&mut self, label: &'static [u8], group: &C);
}

impl TranscriptProtocol for Transcript {
    fn domain_sep(&mut self, label: &'static [u8]) {
        self.append_message(b"dom-sep", b"schnorrzkp/ark-ec");
        self.append_message(b"dom-sep", label);
    }

    fn append_scalar_var(&mut self, label: &'static [u8]) {
        self.append_message(b"scalarvar", label);
    }

    fn append_group_var<C: CurveGroup>(
        &mut self,
        label: &'static [u8],
        group: &C,
    ) -> C {
        self.append_message(b"groupvar", label);
        self.append_message(b"val", group.as_bytes());
    }
}