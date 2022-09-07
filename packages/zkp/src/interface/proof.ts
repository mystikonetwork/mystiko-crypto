export type Fq = string;
export type Fq2 = [Fq, Fq];

export type G1Affine = [Fq, Fq];
export type G2Affine = [Fq2, Fq2];

export interface ZKProof {
  proof: object;
  inputs: string[];
}

export interface ZKVerificationKey {
  alpha: G1Affine;
  beta: G2Affine;
  gamma: G2Affine;
  delta: G2Affine;
  gamma_abc: G1Affine[];
}
