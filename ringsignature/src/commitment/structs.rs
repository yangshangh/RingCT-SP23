use ark_ec::CurveGroup;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PedersenParams<C: CurveGroup> {
    pub h: C,
    pub vec_g: Vec<C::Affine>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PedersenOpening<C: CurveGroup> {
    pub message: Vec<C::ScalarField>,
    pub opt_random: Option<C::ScalarField>,
}