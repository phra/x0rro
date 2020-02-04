
import { Command, flags } from '@oclif/command'
import { prompt } from 'inquirer'
import { R2Pipe } from 'r2pipe-promise'

import { x0rro } from '../core'
import { Options, Techniques, Section } from '../models'
import { print_banner } from '../utils/banner'
import { ensure_file_exists } from '../utils'

export default class Interactive extends Command {
  static description = 'Encrypt binary with an interactive wizard'

  static examples = [
    `$ x0rro interactive myfile`,
  ]

  static flags = {
    help: flags.help({
      char: 'h',
    }),
  }

  static args = [
    { name: 'file', required: true },
  ]

  async run(): Promise<void> {
    print_banner()
    const { args } = this.parse(Interactive)
    ensure_file_exists(args.file)
    const r2 = await R2Pipe.open(args.file)
    const sections = await r2.cmdj('iSj') as Section[]
    await r2.quit()

    const responses: Options = await prompt([
      {
        name: 'xor_key',
        message: 'provide a custom xor_key in hex format [default: 0xf]',
        type: 'input',
        default: '0xf',
        validate: (x: string): boolean => x[0] === '0' && x[1] === 'x' && (x.length === 3 || x.length === 4),
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
        message: 'choose sections to be entirely encrypted [default: __text]',
        type: 'checkbox',
        default: 1,
        choices: sections.map(x => x.name).filter(x => x),
      },
    ])

    const { custom_sections } = await prompt([
      {
        name: 'custom_sections',
        message: 'choose sections to partial encrypt (ie. with manual ranges)',
        type: 'checkbox',
        default: 1,
        choices: sections.map(x => x.name).filter(x => x),
      },
    ])

    for (const custom_section of custom_sections) {
      const section = sections.find(s => s.name.includes(custom_section))
      if (!section) {
        throw new Error('Error when parsing sections')
      }

      const start = '0x' + section.vaddr.toString(16)
      const end = '0x' + (section.vaddr + section.vsize).toString(16)
      const range = (await prompt({
        name: 'range',
        message: `provide a custom range for ${custom_section} in hex format [eg: ${start}-${end}]`,
        type: 'input',
        default: `${start}-${end}`,
        validate: x => {
          let valid = true
          valid = valid && x[0] === '0' && x[1] === 'x' && x.indexOf('-') >= 0
          const start_input = x.split('-')[0]
          const end_input = x.split('-')[1]
          valid = valid && parseInt(start_input, 16) >= section.vaddr
          valid = valid && parseInt(end_input, 16) <= section.vaddr + section.vsize
          return valid
        },
      })).range

      responses.sections.push(`${custom_section}[${range}]`)
    }

    responses.sections = responses.sections.map(x => x.substr(x.indexOf('.')))

    await x0rro(args.file, responses)
  }
}
