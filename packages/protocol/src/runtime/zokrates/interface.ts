import { Proof } from 'zokrates-js';

export interface ZokratesRuntime {
  prove(
    programFile: string | string[],
    abiFile: string | string[],
    provingKeyFile: string | string[],
    args: any[],
  ): Promise<Proof>;
  verify(vkeyFile: string | string[], proof: Proof): Promise<boolean>;
}
