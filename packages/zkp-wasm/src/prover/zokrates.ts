import { ProveOptions, VerifyOptions, ZKProof, ZKProver } from '@mystikonetwork/zkp';
import { CompilationArtifacts, VerificationKey, ZoKratesProvider } from '@mystikonetwork/zokrates-js';

export class ZokratesWasmProver implements ZKProver {
  private readonly zokratesProvider: ZoKratesProvider;

  constructor(zokratesProvider: ZoKratesProvider) {
    this.zokratesProvider = zokratesProvider;
  }

  public prove(options: ProveOptions): Promise<ZKProof> {
    const { program, abi, provingKey } = options;
    const artifacts: CompilationArtifacts = { program, abi: JSON.parse(abi) };
    const { witness } = this.zokratesProvider.computeWitness(artifacts, options.inputs);
    return Promise.resolve(this.zokratesProvider.generateProof(program, witness, provingKey));
  }

  public verify(options: VerifyOptions<ZKProof>): Promise<boolean> {
    const verifyingKey: VerificationKey = JSON.parse(options.verifyingKey);
    return Promise.resolve(this.zokratesProvider.verify(verifyingKey, options.proof));
  }
}
