#!/usr/bin/env python3
import os
import re
import argparse
import struct

class FirmwareDeconstructor:
    """
    A tool for deconstructing WINC1500 firmware dump files.
    """
    def __init__(self, dump_file, output_dir, source_parts_dir=None):
        self.dump_file = dump_file
        self.output_dir = output_dir
        self.source_parts_dir = source_parts_dir
        self.firmware = self._read_file(dump_file)
        self.regions = []

    def _read_file(self, file_path):
        """Reads a binary file and returns its content."""
        with open(file_path, 'rb') as f:
            return f.read()

    def deconstruct(self):
        """
        Deconstructs the firmware dump into its constituent parts.
        """
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        certs_dir = os.path.join(self.output_dir, 'certificates')
        if not os.path.exists(certs_dir):
            os.makedirs(certs_dir)

        self._find_all_regions()
        self._calculate_sizes_and_extract()
        self._generate_config()

    def _verify_part(self, region, name, data):
        """
        Verifies a single extracted part against its source file.
        """
        if not self.source_parts_dir:
            return

        source_file_path = os.path.join(self.source_parts_dir, name)
        if not os.path.exists(source_file_path):
            # Fallback for names that are different in the source directory
            name = name.replace(' ', '_') + '.bin'
            source_file_path = os.path.join(self.source_parts_dir, name)
            if not os.path.exists(source_file_path):
                print(f"Warning: Source file not found for {name}")
                return

        source_data = self._read_file(source_file_path)

        # The source file for schema 1 firmware has a 4-byte header that needs to be stripped
        if 'type' in region and region['type'] == 'firmware' and 'schema' in region and region['schema'] == 1:
            source_data = source_data[4:]

        if data != source_data:
            print(f"Error: Verification failed for {name}")
            # Write both files to disk for inspection
            with open(os.path.join(self.output_dir, name + '.extracted'), 'wb') as f:
                f.write(data)
            with open(os.path.join(self.output_dir, name + '.source'), 'wb') as f:
                f.write(source_data)
            exit(1)
        else:
            print(f"Verified {name}")

    def _find_all_regions(self):
        """
        Finds all known regions in the dump file.
        """
        # Add the fixed regions, as specified in the flash_image.config
        self.regions.append({'name': 'boot firmware', 'offset': 0x0, 'type': 'firmware', 'schema': 1, 'prefix': 'NMIS'})
        self.regions.append({'name': 'control sector', 'offset': 0x1000})
        self.regions.append({'name': 'backup sector', 'offset': 0x2000})
        self.regions.append({'name': 'pll table', 'offset': 0x3000})
        self.regions.append({'name': 'gain table', 'offset': 0x3400})

        # Find all occurrences of the firmware magic numbers
        magic_numbers = {
            'downloader firmware': b'NMIS',
            'wifi firmware': b'NMID',
            'ate firmware': b'FTMA',
        }

        for name, magic in magic_numbers.items():
            occurrence = 0
            if name == 'downloader firmware':
                occurrence = 1

            offset = -1
            for i in range(occurrence + 1):
                offset = self.firmware.find(magic, offset + 1)
                if offset == -1:
                    break

            if offset != -1:
                if name == 'ate firmware':
                    self.regions.append({'name': name, 'offset': offset, 'type': 'firmware', 'schema': 4, 'prefix': 'FTMA'})
                else:
                    self.regions.append({'name': name, 'offset': offset, 'type': 'firmware', 'schema': 1, 'prefix': magic.decode('ascii')})

        # Find all DER certificates, but only before the first firmware region
        der_header = b'\x30\x82'
        offset = 0
        end_of_search = min(r['offset'] for r in self.regions if r.get('type') == 'firmware')

        while True:
            offset = self.firmware.find(der_header, offset, end_of_search)
            if offset == -1:
                break

            length_bytes = self.firmware[offset + 2 : offset + 4]
            length = struct.unpack('>H', length_bytes)[0]
            total_length = 4 + length

            self.regions.append({'name': f'certificate_{hex(offset)}', 'offset': offset, 'size': total_length, 'type': 'certificate'})

            offset += total_length

        self.regions.sort(key=lambda x: x['offset'])

    def _calculate_sizes_and_extract(self):
        """
        Calculates the size of each region, trims trailing 0xFF bytes, and extracts the data.
        """
        for i, region in enumerate(self.regions):
            start = region['offset']

            if 'size' in region:
                size = region['size']
                end = start + size
            elif i + 1 < len(self.regions):
                end = self.regions[i+1]['offset']
                size = end - start
            else:
                end = len(self.firmware)
                size = end - start

            data = self.firmware[start:end]

            # Trim trailing 0xFF bytes
            trimmed_data = data.rstrip(b'\xff')

            # For schema 1 firmware, the actual data starts 8 bytes after the magic number
            if 'type' in region and region['type'] == 'firmware' and 'schema' in region and region['schema'] == 1:
                trimmed_data = trimmed_data[8:]

            name = region['name']

            filename = name.replace(' ', '_')
            if 'type' in region and region['type'] == 'certificate':
                filename += '.der'
                extracted_file_path = os.path.join(self.output_dir, 'certificates', filename)
            else:
                filename += '.bin'
                extracted_file_path = os.path.join(self.output_dir, filename)

            with open(extracted_file_path, 'wb') as f_out:
                f_out.write(trimmed_data)

            self._verify_part(region, name, trimmed_data)

            region['size'] = len(trimmed_data)
            print(f"Extracted {filename} at offset {hex(start)} with size {hex(len(trimmed_data))}")

    def _generate_config(self):
        """
        Generates a new flash_image.config file based on the extracted regions.
        """
        with open(os.path.join(self.output_dir, 'generated_flash_image.config'), 'w') as f:
            f.write('[flash]\n')
            f.write('size is 1M\n')

            for region in self.regions:
                f.write(f"region at {hex(region['offset'])} is [{region['name']}]\n")

            f.write('\n')

            for region in self.regions:
                name = region['name']
                f.write(f'[{name}]\n')
                if 'type' in region:
                    if region['type'] == 'firmware':
                        f.write(f"type is firmware\n")
                        f.write(f"schema is {region['schema']}\n")
                        f.write(f"prefix is {region['prefix']}\n")
                        f.write(f"file is {name.replace(' ', '_')}.bin\n")
                    elif region['type'] == 'certificate':
                        f.write('type is tls certificate\n')
                f.write('\n')

        print("\nGenerated flash_image.config")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Deconstruct a WINC1500 firmware dump file.')
    parser.add_argument('dump_file', help='The firmware dump file.')
    parser.add_argument('output_dir', help='The directory to write the extracted parts to.')
    parser.add_argument('--source_dir', help='The directory containing the source parts (for verification and naming).')
    args = parser.parse_args()

    deconstructor = FirmwareDeconstructor(args.dump_file, args.output_dir, source_parts_dir=args.source_dir)
    deconstructor.deconstruct()
