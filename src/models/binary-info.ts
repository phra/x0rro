export interface BinaryInfo {
  info:    Info
  imports: Import[]
  entries: Entry[]
  exports: Export[]
}

export interface Import { }

export interface Entry {
  vaddr:  number
  paddr:  number
  baddr:  number
  laddr:  number
  hvaddr: number
  haddr:  number
  type:   string
}

export interface Export {
  name:        string
  flagname:    string
  realname:    string
  ordinal:     number
  bind:        string
  size:        number
  type:        string
  vaddr:       number
  paddr:       number
  is_imported: boolean
}

export interface Info {
  arch:      string
  baddr:     number
  binsz:     number
  bintype:   string
  bits:      number
  canary:    boolean
  class:     string
  compiled:  string
  compiler:  string
  crypto:    boolean
  dbg_file:  string
  endian:    string
  havecode:  boolean
  guid:      string
  intrp:     string
  laddr:     number
  lang:      string
  linenum:   boolean
  lsyms:     boolean
  machine:   string
  maxopsz:   number
  minopsz:   number
  nx:        boolean
  os:        string
  pcalign:   number
  pic:       boolean
  relocs:    boolean
  rpath:     string
  sanitiz:   boolean
  static:    boolean
  stripped:  boolean
  subsys:    string
  va:        boolean
  checksums: Checksums
}

export interface Checksums {
}
