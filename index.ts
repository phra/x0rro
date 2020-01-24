#!/usr/bin/env node

'use strict'

import { x0rro } from './src/x0rro'
import { Options } from './src/models'

const BANNER = ` ▄       ▄  ▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░▌     ▐░▌▐░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
 ▐░▌   ▐░▌▐░█░█▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌
  ▐░▌ ▐░▌ ▐░▌▐░▌    ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
   ▐░▐░▌  ▐░▌ ▐░▌   ▐░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌
    ▐░▌   ▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌
   ▐░▌░▌  ▐░▌   ▐░▌ ▐░▌▐░█▀▀▀▀█░█▀▀ ▐░█▀▀▀▀█░█▀▀ ▐░▌       ▐░▌
  ▐░▌ ▐░▌ ▐░▌    ▐░▌▐░▌▐░▌     ▐░▌  ▐░▌     ▐░▌  ▐░▌       ▐░▌
 ▐░▌   ▐░▌▐░█▄▄▄▄▄█░█░▌▐░▌      ▐░▌ ▐░▌      ▐░▌ ▐░█▄▄▄▄▄▄▄█░▌
▐░▌     ▐░▌▐░░░░░░░░░▌ ▐░▌       ▐░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌
 ▀       ▀  ▀▀▀▀▀▀▀▀▀   ▀         ▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀ `

if (!process.argv[2]) {
  console.log(`Usage: nodejs index.js <FILE>`)
  process.exit(-1)
}

const opts: Options = {
  use_code_cave: !!process.argv[3] || false,
  xor_key: parseInt(process.argv[4]) || 0xf,
}

console.log(BANNER)
x0rro(process.argv[2], opts)
