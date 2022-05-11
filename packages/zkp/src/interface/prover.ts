import { ZKProof } from './proof';

export type ProveOptions = {
  programFile: string | string[];
  abiFile: string | string[];
  provingKeyFile: string | string[];
  arguments: any[];
};

export type VerifyOptions<P = ZKProof> = {
  verifyingKeyFile: string | string[];
  proof: P;
};

export interface ZKProver<P = ZKProof, PO = ProveOptions, VO = VerifyOptions<P>> {
  prove(options: PO): Promise<P>;
  verify(options: VO): Promise<boolean>;
}

export interface ZKProverFactory<P = ZKProof, PO = ProveOptions, VO = VerifyOptions<P>> {
  create(): Promise<ZKProver<P, PO, VO>>;
}
