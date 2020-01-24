export interface Section {
  name: string;
  size: number;
  vsize: number;
  perm: string;
  paddr: number;
  vaddr: number;
}

export interface EnrichedSection extends Section {
  page_start: number;
  psize: number;
}
