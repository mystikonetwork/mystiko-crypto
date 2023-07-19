import { readCompressedFile, readJsonFile } from '@mystikonetwork/utils';
import { ProveOptions, VerifyOptions, ZKProof, ZKProver } from '@mystikonetwork/zkp';
import { CompilationArtifacts, VerificationKey, ZoKratesProvider } from 'zokrates-js';

export class ZokratesWasmProver implements ZKProver {
  private readonly zokratesProvider: ZoKratesProvider;

  constructor(zokratesProvider: ZoKratesProvider) {
    this.zokratesProvider = zokratesProvider;
  }

  public async prove(options: ProveOptions): Promise<ZKProof> {
    const program = await readCompressedFile(options.programFile);
    const abi = await readJsonFile(options.abiFile);
    const provingKey = await readCompressedFile(options.provingKeyFile);
    const artifacts: CompilationArtifacts = { program, abi };
    const { witness } = this.zokratesProvider.computeWitness(artifacts, options.inputs);
    return Promise.resolve(this.zokratesProvider.generateProof(program, witness, provingKey));
  }

  public async verify(options: VerifyOptions<ZKProof>): Promise<boolean> {
    const verifyingKey: VerificationKey = (await readJsonFile(options.verifyingKeyFile)) as VerificationKey;
    return Promise.resolve(this.zokratesProvider.verify(verifyingKey, options.proof));
  }
}
