import { ZKProof } from './proof';

export type ProveOptions = {
  program: Buffer;
  abi: string;
  provingKey: Buffer;
  inputs: any[];
};

export type VerifyOptions<P = ZKProof> = {
  verifyingKey: string;
  proof: P;
};

export interface ZKProver<P = ZKProof, PO = ProveOptions, VO = VerifyOptions<P>> {
  prove(options: PO): Promise<P>;
  verify(options: VO): Promise<boolean>;
}

export interface ZKProverFactory<O = any, P = ZKProof, PO = ProveOptions, VO = VerifyOptions<P>> {
  create(options?: O): Promise<ZKProver<P, PO, VO>>;
}
