use ark_ec::CurveGroup;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PedersenParams<C: CurveGroup> {
    pub h: C,
    // the `GAffine` type is used here for more efficient MSM.
    pub vec_g: Vec<C::Affine>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PedersenOpening<C: CurveGroup> {
    pub message: Vec<C::ScalarField>,
    // the `GAffine` type is used here for more efficient MSM.
    pub random: C::ScalarField,
}
