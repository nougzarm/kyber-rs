pub mod kem_scheme;
pub mod pke_scheme;

use crate::constants::KyberParams;
use crate::polynomial::Polynomial;

pub type KyberPoly = Polynomial<KyberParams>;
