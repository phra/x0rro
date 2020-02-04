import { execFileSync } from 'child_process'
import { unlinkSync } from 'fs'

import { x0rro } from '../src'
import { Techniques } from '../src/models'


describe('works on Linux', () => {
  describe('32-bits', () => {
    beforeEach(() => {
      execFileSync('gcc', ['-m32', '-o', 'generated/test32', 'tests/test.c'])
    })

    afterEach(() => {
      try {
        unlinkSync('generated/test32')
        unlinkSync('generated/test32-obfuscated')
      } catch (ex) {}
    })

    test('add section', async () => {
      await x0rro('generated/test32', { sections: ['rodata'], technique: Techniques.ADD_SECTION, xor_key: 0xf })
      execFileSync('chmod', ['u+x', 'generated/test32'])
      expect(execFileSync('generated/test32', { encoding: 'utf8' })).toMatch('Hello World From 32-bits')
    })
  })

  describe('64-bits', () => {
    beforeEach(() => {
      execFileSync('gcc', ['-o', 'generated/test64', 'tests/test.c'])
    })

    afterEach(() => {
      try {
        unlinkSync('generated/test64')
        unlinkSync('generated/test64-obfuscated')
      } catch (ex) {}
    })

    test('add section', async () => {
      await x0rro('generated/test64', { sections: ['rodata'], technique: Techniques.ADD_SECTION, xor_key: 0xf })
      execFileSync('chmod', ['u+x', 'generated/test64'])
      expect(execFileSync('generated/test64', { encoding: 'utf8' })).toMatch('Hello World From 64-bits')
    })
  })
})
