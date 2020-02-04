import fs = require('fs')
import { execFileSync } from 'child_process'
import { resolve } from 'path'

import mustache = require('mustache')
import { R2Pipe } from 'r2pipe-promise'

import {
  CodeCave,
  Section,
  EnrichedSection,
  Options,
  Techniques,
  BinaryInfo,
} from '../models'

async function get_binary_info(r2: R2Pipe): Promise<BinaryInfo> {
  return await r2.cmdj(`iaj`) as BinaryInfo
}

async function find_entry_point(r2: R2Pipe): Promise<string> {
  return (await r2.cmd('s')).trim()
}

async function find_entry_point_bytes(r2: R2Pipe, binary_info: BinaryInfo): Promise<string> {
  switch (binary_info.info.bits) {
    case 64:
      return (await r2.cmd('pxq 8')).split(' ')[2]
    case 32:
        return (await r2.cmd('pxw 4')).split(' ')[2]
    default:
      throw new Error(`Bits not supported: ${binary_info.info.bits}`)
  }
}

async function calculate_length_code_cave(r2: R2Pipe, code_cave: string): Promise<number> {
  await r2.cmd(`s ${code_cave}`)
  let length = 0;
  while (!(await r2.cmd(`pr 1`))) {
    length++
    await r2.cmd(`s+ 1`)
  }

  return length
}

function align_to_boundary_16_upper(addr: string): string {
  return '0x' + ((BigInt(addr) & 0xfffffffffffffff0n) + 16n).toString(16)
}

function align_to_boundary_16_lower(addr: string): string {
  return '0x' + (BigInt(addr) & 0xfffffffffffffff0n).toString(16)
}

function get_page_start(addr: number): number {
  return Number(BigInt(addr) >> 12n << 12n)
}

async function get_sections(r2: R2Pipe): Promise<Section[]> {
  return await r2.cmdj('iSj') as Section[]
}

async function find_code_cave(r2: R2Pipe, sections_to_xor: Section[], stub_length: number): Promise<CodeCave> {
  console.log(await r2.cmd(`?E Searching for code caves`))
  const res = (await r2.cmd(`/x ${'00'.repeat(stub_length)}`)).split('\n')
  if (res.length < 2) {
    throw new Error(`Could not find a code cave of length ${stub_length}`)
  }

  const executable_sections = (await get_sections(r2)).filter(x => x.perm.includes('x'))
  const code_caves = res
    .map(x => x.split(' ')[0]) // last is empty line
    .filter(x => x)
    .map(x => align_to_boundary_16_upper(x))
    .filter(code_cave => {
      if (executable_sections.some(x => x.vaddr <= parseInt(code_cave, 16) && (x.vaddr + x.vsize) > parseInt(code_cave, 16))) {
        return code_cave
      }
    })

  const code_caves_with_length: CodeCave[] = []

  for (const x of code_caves) {
    code_caves_with_length.push({
      addr: x,
      length: 0x1000 // await calculate_length_code_cave(r2, x),
    })
  }

  const code_caves_with_length_sorted = code_caves_with_length.sort((x, y) => x.length - y.length).reverse()

  if (!code_caves_with_length_sorted.length) {
    throw new Error(`Could not find an executable code cave of length ${stub_length}`)
  }

  const valid_code_caves = code_caves_with_length_sorted.filter(code_cave => {
    return !sections_to_xor.some(x => x.vaddr <= parseInt(code_cave.addr, 16) && (x.vaddr + x.vsize) > parseInt(code_cave.addr, 16))
  })

  if (!valid_code_caves.length) {
    throw new Error(`Could not find an executable code cave outside the sections to xor of length ${stub_length}`)
  }

  console.log(`CHOOSEN CODE CAVE => ${valid_code_caves[0].addr} [${valid_code_caves[0].length} bytes]`)

  return valid_code_caves[0]
}

async function xor_sections(r2: R2Pipe, sections: Section[], key: number): Promise<void> {
  for (const s of sections) {
    console.log(await r2.cmd(`?E xoring ${s.name}`))
    console.log('before xor:')
    await r2.cmd(`s ${s.vaddr}`)
    console.log(await r2.cmd(`px 32`))
    const values = await r2.cmdj(`pxj ${s.vsize}`) as number[]
    const new_values = values.map(value => (value ^ key).toString(16).padStart(2, '0')).join('')
    fs.writeFileSync(resolve('/tmp/xored'), new_values)
    await r2.cmd(`wxf ${resolve('/tmp/xored')}`)
    console.log('after xor:')
    await r2.cmd(`s ${s.vaddr}`)
    console.log(await r2.cmd(`px 32`))
  }
}

function get_template_name(binary_info: BinaryInfo, opts: Options): string {
  switch (binary_info.info.arch) {
    case 'x86':
      switch (binary_info.info.bits) {
        case 64:
          switch (binary_info.info.bintype) {
            case 'elf':
              return resolve(__dirname, '../../templates/linux/stub.mprotect.asm')
            case 'pe':
              return resolve(__dirname, '../../templates/stub.asm')
            case 'mach0':
              return resolve(__dirname, '../../templates/osx/stub.mprotect.asm')
            default:
              throw new Error(`BinType not supported: ${binary_info.info.bintype}`)
          }
          case 32:
            switch (binary_info.info.bintype) {
              case 'elf':
                return resolve(__dirname, '../../templates/linux/stub.mprotect.x86.asm')
              case 'pe':
                return resolve(__dirname, '../../templates/stub.x86.asm')
              case 'mach0':
                return resolve(__dirname, '../../templates/osx/stub.mprotect.x86.asm')
              default:
                throw new Error(`BinType not supported: ${binary_info.info.bintype}`)
            }
        default:
          throw new Error(`Bits not supported: ${binary_info.info.bits}`)
      }
    default:
      throw new Error(`Architecture not supported: ${binary_info.info.arch}`)
  }
}

async function create_stub(
  r2: R2Pipe,
  binary_info: BinaryInfo,
  sections_xor: Section[],
  entry_point: string,
  opts: Options,
): Promise<number> {
  const template_name = get_template_name(binary_info, opts)
  const template = fs.readFileSync(template_name, { encoding: 'utf-8' })
  const data = {
    sections_xor,
    entry_point,
    xor_key: opts.xor_key,
  }

  const instance = mustache.render(template, data)
  fs.writeFileSync(resolve('/tmp/stub.asm'), instance)
  await r2.cmd('s+ 128') // use far jmp
  return (await r2.cmd(`waF* ${resolve('/tmp/stub.asm')}`)).split(' ')[1].trim().length / 2
}

async function find_sections_xor(r2: R2Pipe, sections: string[], original_sections: Section[]): Promise<EnrichedSection[]> {
  const info = (await r2.cmdj('iaj')).info
  const base_addr = info.baddr
  const bits = info.bits
  const custom_sections = sections.filter(s => s.indexOf('[') >= 0)
  const regular_sections = sections.filter(s => s.indexOf('[') < 0)
  const current_sections = (await get_sections(r2))
  const enriched_sections = (await get_sections(r2))
    .filter(s => regular_sections.some(w => s.name.includes(w)))
    .map(s => ({
      ...s,
      page_start: get_page_start(s.vaddr),
      psize: (s.vaddr - get_page_start(s.vaddr) + s.vsize)
    }));

  (await get_sections(r2))
    .filter(s => custom_sections.some(w => s.name.includes(w.split('[')[0])))
    .forEach(s => {
      const section = custom_sections.find(w => s.name.includes(w.split('[')[0]))
      if (!section) {
        throw new Error(`cannot find section ${s.name}`)
      }

      const section_name = section.split('[')[0]
      const original_section = original_sections.find(s => s.name.includes(section_name))
      const current_section = current_sections.find(s => s.name.includes(section_name))
      if (!original_section || ! current_section) {
        throw new Error(`cannot find section ${section_name}`)
      }

      const offset = current_section.vaddr - original_section.vaddr
      const ranges = section.split('[')[1].split(']')[0].split(',')
      ranges.forEach((range, i) => {
        const start = Number(BigInt(range.split('-')[0])) + offset
        const end = Number(BigInt(range.split('-')[1])) + offset
        const size = end - start

        enriched_sections.push({
          ...s,
          vaddr: start,
          vsize: size,
          name: s.name + i,
          page_start: get_page_start(start),
          psize: (start - get_page_start(start) + size)
        })
      })
    })

  return enriched_sections
}

async function find_sections_mprotect(r2: R2Pipe, sections: string[]): Promise<EnrichedSection[]> {
  return (await get_sections(r2))
    .filter(s => sections.some(w => s.name.includes(w.split('[')[0]) || s.name.includes('text')))
    .map(s => ({
      ...s,
      page_start: get_page_start(s.vaddr),
      psize: (s.vaddr - get_page_start(s.vaddr) + s.vsize)
    }))
}

async function patch_entry_point(r2: R2Pipe, entry_point: string, code_cave: CodeCave): Promise<void> {
  console.log(await r2.cmd(`?E Patching entry point`))
  await r2.cmd(`s ${entry_point}`)
  console.log(`original entry point:\n${await r2.cmd('pd 5')}`)
  await r2.cmd(`"wa jmp ${code_cave.addr}"`)
  console.log(`new entry point:\n${await r2.cmd('pd 5')}`)
}

async function patch_code_cave(r2: R2Pipe, code_cave: CodeCave, stub_length: number): Promise<void> {
  console.log(await r2.cmd(`?E Writing stub`))
  console.log(await r2.cmd(`s ${code_cave.addr}`))
  console.log(`code cave:\n${await r2.cmd('pd 5')}`)
  console.log(await r2.cmd(`waf ${resolve('/tmp/stub.asm')}`))
  if (stub_length > code_cave.length) {
    throw new Error(`The stub doesn't fit. Try to reduce section to encrypt.`)
  }

  console.log(`written stub [${stub_length} bytes]:`)
  console.log(await r2.cmd(`pD ${stub_length}`))
}

async function add_section(r2: R2Pipe, file: string, section_name = '__shellcode'): Promise<void> {
  console.log(await r2.cmd(`?E Adding ${section_name} - ${file}`))
  console.log(execFileSync('python3', [resolve(__dirname, '../../scripts/add-section.py'), file, section_name], { encoding: 'utf-8' }))
}

async function make_segment_rwx(r2: R2Pipe, file: string, segments = []): Promise<void> {
  console.log(await r2.cmd(`?E Making segments rwx: ${segments.join(' ') || 'all'} - ${file}`))
  console.log(execFileSync('python3', [resolve(__dirname, '../../scripts/make-segment-rwx.py'), file, segments.join(' ')], { encoding: 'utf-8' }))
}

async function disable_pie(r2: R2Pipe, file: string): Promise<void> {
  console.log(await r2.cmd(`?E Disabling PIE - ${file}`))
  console.log(execFileSync('python3', [resolve(__dirname, '../../scripts/disable-pie.py'), file], { encoding: 'utf-8' }))
}

async function update_entrypoint(r2: R2Pipe, file: string, addr: string): Promise<void> {
  console.log(await r2.cmd(`?E Updating entry point to ${addr} - ${file}`))
  console.log(execFileSync('python3', [resolve(__dirname, '../../scripts/change-entrypoint.py'), file, addr], { encoding: 'utf-8' }))
}

async function find_shellcode_section(r2: R2Pipe): Promise<CodeCave> {
  const shellcode_section = (await get_sections(r2)).find(x => x.name.includes('shellc'))

  if (!shellcode_section) {
    throw new Error('Cannot find __TEXT.__shellcode section')
  }

  return { addr: '0x' + shellcode_section.vaddr.toString(16), length: 0x1000 }
}

function save_backup(file: string): string {
  const new_filename = file + '-obfuscated'
  fs.copyFileSync(file, new_filename)
  return new_filename
}

function unmap_sections(sections: EnrichedSection[], code_cave: CodeCave): EnrichedSection[] {
  return sections.map(s => ({
    ...s,
    page_start: s.page_start - (parseInt(code_cave.addr, 16) + 9),
    vaddr: s.vaddr - (parseInt(code_cave.addr, 16) + 9),
  }))
}

function unmap_entry_point(entry_point: string, code_cave: CodeCave): string {
  const res = parseInt(entry_point, 16) - (parseInt(code_cave.addr, 16) + 9)
  return res >= 0 ? '0x' + res.toString(16) : '-0x' + res.toString(16).substr(1)
}

export async function x0rro(file: string, opts: Options): Promise<void> {
  try {
    file = save_backup(file)
    let r2 = await R2Pipe.open(file, ['-w', '-e bin.strings=false'])
    const binary_info = await get_binary_info(r2)
    const original_sections = await get_sections(r2)
    console.log(await r2.cmd(`?E Processing ${file}`))
    if (binary_info.info.bintype === 'pe' || binary_info.info.bintype === 'mach0') {
      await make_segment_rwx(r2, file)
    }

    if (opts.technique === Techniques.ADD_SECTION) {
      await add_section(r2, file)
    }

    await r2.quit()
    r2 = await R2Pipe.open(file, ['-w', '-e bin.strings=false'])

    const entry_point = await find_entry_point(r2)
    //const entry_point_bytes = await find_entry_point_bytes(r2, binary_info)
    const sections_xor = await find_sections_xor(r2, opts.sections, original_sections)
    const stub_length = await create_stub(r2, binary_info, sections_xor, entry_point, opts)
    const code_cave = await (opts.technique === Techniques.CODE_CAVE ? find_code_cave(r2, sections_xor, stub_length) : find_shellcode_section(r2))

    if (binary_info.info.bits === 32) {
      const unmapped_section_xor = unmap_sections(sections_xor, code_cave)
      const unmapped_entry_point = unmap_entry_point(entry_point, code_cave)
      await create_stub(r2, binary_info, unmapped_section_xor, unmapped_entry_point, opts)
    }

    await xor_sections(r2, sections_xor, opts.xor_key)
    //await patch_entry_point(r2, entry_point, code_cave)
    await patch_code_cave(r2, code_cave, stub_length)
    update_entrypoint(r2, file, code_cave.addr)
    //await disable_pie(r2, file)
    console.log(await r2.cmd(`?E Done! Check ${file}`))
    return r2.quit()
  } catch (err) {
    console.error(err)
    process.exit(-1)
  }
}
