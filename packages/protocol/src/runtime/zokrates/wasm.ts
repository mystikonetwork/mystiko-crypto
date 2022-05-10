import { CompilationArtifacts, Proof, VerificationKey, ZoKratesProvider } from 'zokrates-js';
import { readCompressedFile, readJsonFile } from '@mystikonetwork/utils';
import { ZokratesRuntime } from './interface';

// eslint-disable-next-line import/prefer-default-export
export class ZokratesWasmRuntime implements ZokratesRuntime {
  private readonly zokratesProvider: ZoKratesProvider;

  constructor(zokratesProvider: ZoKratesProvider) {
    this.zokratesProvider = zokratesProvider;
  }

  public async prove(
    programFile: string | string[],
    abiFile: string | string[],
    provingKeyFile: string | string[],
    args: any[],
  ): Promise<Proof> {
    const program = await readCompressedFile(programFile);
    const abi = await readJsonFile(abiFile);
    const provingKey = await readCompressedFile(provingKeyFile);
    const artifacts: CompilationArtifacts = { program, abi };
    const { witness } = this.zokratesProvider.computeWitness(artifacts, args);
    return Promise.resolve(this.zokratesProvider.generateProof(program, witness, provingKey));
  }

  public async verify(vkeyFile: string | string[], proof: Proof): Promise<boolean> {
    const verifyingKey: VerificationKey = (await readJsonFile(vkeyFile)) as VerificationKey;
    return Promise.resolve(this.zokratesProvider.verify(verifyingKey, proof));
  }
}
