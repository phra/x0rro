
import { Command, flags } from '@oclif/command'
import { execFileSync } from 'child_process'

import { x0rro } from '../core'
import { Options, Techniques } from '../models'

export default class Section extends Command {
  static description = 'Encrypt binary using code cave technique'

  static examples = [
    `$ x0rro section -x 0xf -s __text,__data myfile`,
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

  print_radare2_version(): void {
    console.log(execFileSync('r2', ['-v'], { encoding: 'utf-8' }))
  }

  async run(): Promise<void> {
    const { args, flags } = this.parse(Section)

    const opts: Options = {
      technique: Techniques.ADD_SECTION,
      xor_key: parseInt(flags.xor, 16),
      sections: flags.sections.split(','),
    }

    await x0rro(args.file, opts)
  }
}
