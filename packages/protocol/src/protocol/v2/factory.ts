import { ZKProverFactory } from '@mystikonetwork/zkp';
import { ProtocolFactory } from '../../interface';
import { MystikoProtocolV2 } from './protocol';

export class ProtocolFactoryV2<PO = any> implements ProtocolFactory<PO> {
  private readonly proverFactory: ZKProverFactory<PO>;

  constructor(proverFactory: ZKProverFactory<PO>) {
    this.proverFactory = proverFactory;
  }

  create(options?: PO): Promise<MystikoProtocolV2> {
    return this.proverFactory.create(options).then((prover) => new MystikoProtocolV2(prover));
  }
}
