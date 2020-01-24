
import { Command, flags } from '@oclif/command'

import { x0rro } from '../core'
import { Options, Techniques } from '../models'

export default class Cave extends Command {
  static description = 'Encrypt binary using code cave technique'

  static examples = [
    `$ x0rro cave -x 0xf -s __text,__data myfile`,
  ]

  static flags = {
    xor: flags.string({
      char: 'x',
      description: 'xor key to use in hexadecimal',
      default: '0xf',
    }),
    sections: flags.string({
      char: 's',
      description: 'sections to xor separated by comma',
      default: '__text',
    }),
    help: flags.help({
      char: 'h',
    }),
  }

  static args = [
    { name: 'file' },
  ]



  async run(): Promise<void> {
    const { args, flags } = this.parse(Cave)

    const opts: Options = {
      technique: Techniques.CODE_CAVE,
      xor_key: parseInt(flags.xor, 16),
      sections: flags.sections.split(','),
    }

    await x0rro(args.file, opts)
  }
}
