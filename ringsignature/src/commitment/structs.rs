use ark_ec::CurveGroup;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PedersenParams<C: CurveGroup> {
    pub gen: C,
    pub vec_gen: Vec<C::Affine>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PedersenOpening<C: CurveGroup> {
    pub message: Vec<C::ScalarField>,
    pub random: C::ScalarField,
}