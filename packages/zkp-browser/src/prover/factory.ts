import { ZKProverFactory } from '@mystikonetwork/zkp';
import { initialize, ZoKratesProvider } from 'zokrates-js';
import { ZokratesWasmProver } from './zokrates';

export class ZokratesWasmProverFactory implements ZKProverFactory {
  // eslint-disable-next-line class-methods-use-this
  public create(): Promise<ZokratesWasmProver> {
    return initialize().then((provider: ZoKratesProvider) => new ZokratesWasmProver(provider));
  }
}
