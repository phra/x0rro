import fs = require('fs')
import mustache = require('mustache')
import { R2Pipe } from 'r2pipe-promise'
import { execFileSync } from 'child_process'

import {
  CodeCave,
  Section,
  EnrichedSection,
  Options,
  Techniques,
} from '../models'

async function find_entry_point(r2: R2Pipe): Promise<string> {
  return (await r2.cmd('s')).trim()
}

async function find_entry_point_bytes(r2: R2Pipe): Promise<string> {
  return (await r2.cmd('pxq 8')).split(' ')[2] // TODO: x86 bits
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
      length: await calculate_length_code_cave(r2, x),
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
    fs.writeFileSync('generated/xored', new_values)
    await r2.cmd(`wxf generated/xored`)
    console.log('after xor:')
    await r2.cmd(`s ${s.vaddr}`)
    console.log(await r2.cmd(`px 32`))
  }
}

async function create_stub(
  r2: R2Pipe,
  sections: Section[],
  entry_point: string,
  entry_point_bytes: string,
  opts: Options,
): Promise<number> {
  const template_name = opts.technique === Techniques.CODE_CAVE ? 'templates/stub.mprotect.asm' : 'templates/stub.asm'
  const template = fs.readFileSync(template_name, { encoding: 'utf-8' })
  const data = {
    sections,
    entry_point,
    entry_point_bytes,
    xor_key: opts.xor_key,
  }

  const instance = mustache.render(template, data)
  fs.writeFileSync('generated/stub.asm', instance)
  await r2.cmd('s+ 128') // use far jmp
  return (await r2.cmd('waF* generated/stub.asm')).split(' ')[1].trim().length / 2
}

async function find_sections(r2: R2Pipe, sections: string[]): Promise<EnrichedSection[]> {
  return (await get_sections(r2))
    .filter(s => sections.some(w => s.name.includes(w)))
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
  console.log(await r2.cmd(`waf generated/stub.asm`))
  if (stub_length > code_cave.length) {
    throw new Error(`The stub doesn't fit. Try to reduce section to encrypt.`)
  }

  console.log(`written stub [${stub_length} bytes]:`)
  console.log(await r2.cmd(`pD ${stub_length}`))
}

async function add_section(r2: R2Pipe, file: string, section_name = '__shellcode'): Promise<void> {
  console.log(await r2.cmd(`?E Adding ${section_name} - ${file}`))
  console.log(execFileSync('python3', ['scripts/add-section.py', file, section_name], { encoding: 'utf-8' }))
}

async function make_segment_rwx(r2: R2Pipe, file: string, segments = []): Promise<void> {
  console.log(await r2.cmd(`?E Making segments rwx: ${segments.join(' ') || 'all'} - ${file}`))
  console.log(execFileSync('python3', ['scripts/make-segment-rwx.py', file, segments.join(' ')], { encoding: 'utf-8' }))
}

async function disable_pie(r2: R2Pipe, file: string): Promise<void> {
  console.log(await r2.cmd(`?E Disabling PIE - ${file}`))
  console.log(execFileSync('python3', ['scripts/disable-pie.py', file], { encoding: 'utf-8' }))
}

async function find_shellcode_section(r2: R2Pipe): Promise<CodeCave> {
  const shellcode_section = (await get_sections(r2))
    .find(x => x.name.includes('shellc'))

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

export async function x0rro(file: string, opts: Options): Promise<void> {
  try {
    file = save_backup(file)
    let r2 = await R2Pipe.open(file, ['-w', '-e bin.strings=false'])
    console.log(await r2.cmd(`?E Processing ${file}`))
    if (opts.technique === Techniques.ADD_SECTION) {
      await make_segment_rwx(r2, file)
      await add_section(r2, file)
      await r2.quit()
      r2 = await R2Pipe.open(file, ['-w', '-e bin.strings=false'])
    }

    const entry_point = await find_entry_point(r2)
    const entry_point_bytes = await find_entry_point_bytes(r2)
    const sections = await find_sections(r2, opts.sections)
    const stub_length = await create_stub(r2, sections, entry_point, entry_point_bytes, opts)
    const code_cave = await (opts.technique === Techniques.CODE_CAVE ? find_code_cave(r2, sections, stub_length) : find_shellcode_section(r2))
    await xor_sections(r2, sections, opts.xor_key)
    await patch_entry_point(r2, entry_point, code_cave)
    await patch_code_cave(r2, code_cave, stub_length)
    //await disable_pie(r2, file)
    console.log(await r2.cmd(`?E Done! Check ${file}`))
    return r2.quit()
  } catch (err) {
    console.error(err)
    process.exit(-1)
  }
}
