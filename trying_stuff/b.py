import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

with open('./sample_exe64.elf', 'rb') as stream:
    elffile = ELFFile(stream)

    print('  %s sections' % elffile.num_sections())
    section = elffile.get_section_by_name('.symtab')
    for i in range(section.num_symbols()):
        print(section.get_symbol(i - 1).name)
