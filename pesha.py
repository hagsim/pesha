#!/usr/bin/env python
import pefile
import hashlib
import subprocess
import os
import tempfile
import logging
import argparse

class bcolors:
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class PESHA():

    def __init__(self, path, dump):
        head, tail = os.path.split(path)
        self.pe_from_disk = pefile.PE(path)
        self.pe_from_mem = None
        self.code_from_disk = None
        self.code_from_mem = None
        self.hash_disk = None
        self.hash_mem = None
        self.filename = tail
        self.dump = dump     

    def overwrite_offset_with_zero(self, pe, section):
        # Using relocation table from PE on disk
        for reloc in self.pe_from_disk.DIRECTORY_ENTRY_BASERELOC:
            entry_idx = 0
            # We only care about relocations in the .text section
            if not section.contains_offset(pe.get_offset_from_rva(reloc.entries[entry_idx].rva)):
                continue
            while entry_idx<len(reloc.entries):
                entry = reloc.entries[entry_idx]
                offset = pe.get_offset_from_rva(entry.rva)
                entry_idx += 1              
                if entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']:
                    pass
                elif entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGH']:
                    pe.set_word_at_offset(offset,( pe.set_word_at_offset(offset, (pe.get_word_at_offset(offset)&0x00ff))))
                elif entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_LOW']:
                    pe.set_word_at_offset(offset, pe.set_word_at_offset(offset, (pe.get_word_at_offset(offset)&0xff00)))
                elif entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
                    pe.set_dword_at_offset(offset,0x00000000)
                elif entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHADJ']:
                    if entry_idx == len(reloc.entries):
                        break
                    entry_idx += 1
                    pe.set_word_at_offset(offset,0x0000)
        return pe

    def create_hash(self):
        self.hash_disk = hashlib.sha256(self.code_from_disk).hexdigest()
        self.hash_mem = hashlib.sha256(self.code_from_mem).hexdigest()

    def compare(self):
        if self.hash_disk == self.hash_mem:
            print 'The code section has ' + bcolors.UNDERLINE + bcolors.BOLD + 'NOT' + bcolors.ENDC +  ' changed'
        else:
            print 'The code section has ' + bcolors.UNDERLINE + bcolors.BOLD + 'changed' + bcolors.ENDC
    def get_pe_from_memory_dump(self, dump):
            tmp = tempfile.NamedTemporaryFile().name + '.txt'
            pid = None
            try:
                FNULL = open(os.devnull, 'w')
                if(os.path.exists('executable.*.exe')):
                    os.remove('executable.*.exe')
                logging.debug('Finding PID...')
                subprocess.call(['vol.py','-f', dump, 'pslist', '--output=text', "--output-file=" + tmp], stdout=FNULL, stderr=subprocess.STDOUT)
                for line in open(tmp):
                    l = line.split()
                    if l[1] == self.filename or l[1] == self.filename[:-4]:
                        pid = l[2]
                        break
                logging.debug('PID is {}'.format(pid))
                os.remove(tmp)
                if not os.path.exists('procdump/'):
                    os.makedirs('procdump/')
                logging.debug('Extracting PE from memory image...')
                subprocess.call(['vol.py','-f', dump, 'procdump', '-D', 'procdump/','-p', pid], stdout=FNULL, stderr=subprocess.STDOUT)
                self.pe_from_mem = pefile.PE('procdump/executable.' + pid + '.exe')
                os.remove('procdump/executable.' + pid + '.exe')
                os.rmdir('procdump/')
            except IOError:
                logging.debug("Error: File does not appear to exist.")
                return 0

    """
    Rebase_and_relocate takes the origian PE and sets the ImageBase to that of the one collected
    from memory. It should also relocate the image accordingly.
    """
    def rebase_and_relocate(self):
        logging.debug('Rebasing and applying relocations to original PE')
        logging.debug('This will take some time...')
        self.pe_from_disk.relocate_image(self.pe_from_mem.OPTIONAL_HEADER.ImageBase)
        self.code_from_disk = self.pe_from_disk.sections[0].get_data()
        self.code_from_mem = self.pe_from_mem.sections[0].get_data()

    def overwrite(self):
        logging.debug('Overwriting offset of RVA entries in file from disk...')
        entrypoint = self.pe_from_disk.OPTIONAL_HEADER.AddressOfEntryPoint
        code_section = self.pe_from_disk.get_section_by_rva(entrypoint)
        self.pe_from_disk = self.overwrite_offset_with_zero(self.pe_from_disk,code_section)
        self.code_from_disk = code_section.get_data()
        logging.debug('Length of .text section in PE on disk: {}'.format(hex(len(self.code_from_disk))))

        logging.debug('Overwriting offset of RVA entries in file from memory...')
        entrypoint = self.pe_from_mem.OPTIONAL_HEADER.AddressOfEntryPoint
        code_section = self.pe_from_mem.get_section_by_rva(entrypoint)
        self.pe_from_mem = self.overwrite_offset_with_zero(self.pe_from_mem, code_section)
        self.code_from_mem = code_section.get_data()
        logging.debug('Length of .text section in PE from mem: {}'.format(hex(len(self.code_from_mem))))

def take_memory_dump():
    logging.debug('Aqcuiring memory dump')
    path = tempfile.NamedTemporaryFile().name
    subprocess.call(['winpmem.1.6.exe', path])
    return path

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Use Pesha to check if the code section has changed after the PE was run.')
    parser.add_argument('-f', '--filename', type=str, help='path/to/memorydump. If not supplied pesha will take a memory dump with winpmem.')
    parser.add_argument('-p', '--pe',type=str, help='path/to/pe')
    parser.add_argument('-d', help='Enable debugging. This also writes the two new PE files to disk', action="store_true")
    parser.add_argument('-o', help='Use the rebase and relocate method. This method is very slow.', action="store_true")
    args = parser.parse_args()
    log = logging.NOTSET
    if args.d:
        log = logging.DEBUG
    if not args.filename:
        logging.debug('Dumping memory with winpmem...')
        args.filename = take_memory_dump()
        logging.debug('Dump saved at {}'.format(args.filename))
    logging.basicConfig(level=log)
    pesha = PESHA(args.pe, args.filename)
    pesha.get_pe_from_memory_dump(pesha.dump)

    if args.o:
        pesha.rebase_and_relocate()
    else:
        pesha.overwrite()

    pesha.create_hash()
    pesha.compare()
    if args.d:
        pesha.pe_from_disk.write('pe_from_disk.exe')
        pesha.pe_from_mem.write('pe_from_mem.exe')
