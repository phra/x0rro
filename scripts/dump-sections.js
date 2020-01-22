const r2promise = require('r2pipe-promise')

async function main(file) {
  try {
    const r2 = await r2promise.open(file)
    const sections = await r2.cmdj('iSj')
    for (const s of sections) {
      console.log(`dumping section: ${s.name}`)
      await r2.cmd(`s ${s.vaddr}`)
      await r2.cmd(`wtf ${s.name} ${s.vsize}`)
    }
    return r2.quit()
  } catch (err) {
    console.error(err)
  }
}

if (!process.argv[2]) {
    console.log(`Usage: nodejs dump-sections.js <FILE>`)
    return
}

main(process.argv[2])
