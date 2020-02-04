x0rro
=====



[![oclif](https://img.shields.io/badge/cli-oclif-brightgreen.svg)](https://oclif.io)
[![Version](https://img.shields.io/npm/v/x0rro.svg)](https://npmjs.org/package/x0rro)
[![CircleCI](https://circleci.com/gh/phra/x0rro/tree/master.svg?style=shield)](https://circleci.com/gh/phra/x0rro/tree/master)
[![Downloads/week](https://img.shields.io/npm/dw/x0rro.svg)](https://npmjs.org/package/x0rro)
[![License](https://img.shields.io/npm/l/x0rro.svg)](https://github.com/phra/x0rro/blob/master/package.json)

<!-- toc -->
* [Usage](#usage)
* [Commands](#commands)
<!-- tocstop -->
# Usage
<!-- usage -->
```sh-session
$ npm install -g x0rro
$ x0rro COMMAND
running command...
$ x0rro (-v|--version|version)
x0rro/1.0.1 linux-x64 node-v13.7.0
$ x0rro --help [COMMAND]
USAGE
  $ x0rro COMMAND
...
```
<!-- usagestop -->
# Commands
<!-- commands -->
* [`x0rro cave FILE`](#x0rro-cave-file)
* [`x0rro help [COMMAND]`](#x0rro-help-command)
* [`x0rro interactive FILE`](#x0rro-interactive-file)
* [`x0rro section FILE`](#x0rro-section-file)

## `x0rro cave FILE`

Encrypt binary using code cave technique

```
USAGE
  $ x0rro cave FILE

OPTIONS
  -h, --help               show CLI help
  -s, --sections=sections  [default: __text] sections to xor separated by comma
  -x, --xor=xor            [default: 0xf] xor key to use in hexadecimal

EXAMPLES
  $ x0rro cave -x 0xf -s __text,__data myfile
  $ x0rro cave -x 0xf -s aogf[0x140004000-0x140004290] test.exe
```

_See code: [src/commands/cave.ts](https://github.com/phra/x0rro/blob/v1.0.1/src/commands/cave.ts)_

## `x0rro help [COMMAND]`

display help for x0rro

```
USAGE
  $ x0rro help [COMMAND]

ARGUMENTS
  COMMAND  command to show help for

OPTIONS
  --all  see all commands in CLI
```

_See code: [@oclif/plugin-help](https://github.com/oclif/plugin-help/blob/v2.2.3/src/commands/help.ts)_

## `x0rro interactive FILE`

Encrypt binary with an interactive wizard

```
USAGE
  $ x0rro interactive FILE

OPTIONS
  -h, --help  show CLI help

EXAMPLE
  $ x0rro interactive myfile
```

_See code: [src/commands/interactive.ts](https://github.com/phra/x0rro/blob/v1.0.1/src/commands/interactive.ts)_

## `x0rro section FILE`

Encrypt binary using a new executable section

```
USAGE
  $ x0rro section FILE

OPTIONS
  -h, --help               show CLI help
  -s, --sections=sections  [default: __text] sections to xor separated by comma
  -x, --xor=xor            [default: 0xf] xor key to use in hexadecimal

EXAMPLES
  $ x0rro section -x 0xf -s __text,__data myfile
  $ x0rro section -x 0xf -s aogf[0x140004000-0x140004290] test.exe
```

_See code: [src/commands/section.ts](https://github.com/phra/x0rro/blob/v1.0.1/src/commands/section.ts)_
<!-- commandsstop -->
