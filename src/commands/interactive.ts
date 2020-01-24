
import { Command, flags } from '@oclif/command'
import { prompt } from 'inquirer'
import { R2Pipe } from 'r2pipe-promise'

import { x0rro } from '../core'
import { Options, Techniques, Section } from '../models'

export default class Interactive extends Command {
  static description = 'Encrypt binary using code cave technique'

  static examples = [
    `$ x0rro interactive myfile`,
  ]

  static flags = {
    help: flags.help({
      char: 'h',
    }),
  }

  static args = [
    { name: 'file' },
  ]

  async run(): Promise<void> {
    const { args, flags } = this.parse(Interactive)
    const r2 = await R2Pipe.open(args.file)
    const sections = await r2.cmdj('iSj') as Section[]
    await r2.quit()

    const responses: Options = await prompt([
      {
        name: 'xor_key',
        message: 'provide a custom xor_key in hex format [default: 0xf]',
        type: 'input',
        default: '0xf',
        validate: x => x[0] === '0' && x[1] === 'x' && (x.length === 3 || x.length === 4),
      }, {
        name: 'technique',
        message: 'choose a technique to use [default: add section]',
        type: 'list',
        default: 1,
        choices: [
          {
            name: 'Code cave',
            value: Techniques.CODE_CAVE
          }, {
            name: 'Add section',
            value: Techniques.ADD_SECTION
          }
        ],
      }, {
        name: 'sections',
        message: 'choose sections to encrypt [default: __text]',
        type: 'checkbox',
        default: 1,
        choices: sections.map(x => x.name),
      },
    ])

    responses.sections = responses.sections.map(x => x.substr(x.indexOf('.')))

    await x0rro(args.file, responses)
  }
}
