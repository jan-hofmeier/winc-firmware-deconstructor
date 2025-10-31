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

        self._find_all_regions()
        self._calculate_sizes_and_extract()
        self._generate_config()

    def _find_all_regions(self):
        """
        Finds all known regions in the dump file.
        """
        # Add the fixed regions
        self.regions.append({'name': 'boot firmware', 'offset': 0x0, 'type': 'firmware', 'schema': 1, 'prefix': 'NMIS'})
        self.regions.append({'name': 'control sector', 'offset': 0x1000})
        self.regions.append({'name': 'backup sector', 'offset': 0x2000})
        self.regions.append({'name': 'pll table', 'offset': 0x3000})
        self.regions.append({'name': 'gain table', 'offset': 0x3400})

        # Assert that the boot firmware magic is where we expect it
        assert self.firmware.find(b'NMIS') == 0x0

        # Find the other firmware parts
        downloader_offset = self.firmware.find(b'NMIS', 1)
        assert downloader_offset != -1
        self.regions.append({'name': 'downloader firmware', 'offset': downloader_offset, 'type': 'firmware', 'schema': 1, 'prefix': 'NMIS'})

        wifi_offset = self.firmware.find(b'NMID')
        assert wifi_offset != -1
        self.regions.append({'name': 'wifi firmware', 'offset': wifi_offset, 'type': 'firmware', 'schema': 1, 'prefix': 'NMID'})

        ate_offset = self.firmware.find(b'FTMA')
        assert ate_offset != -1
        self.regions.append({'name': 'ate firmware', 'offset': ate_offset, 'type': 'firmware', 'schema': 4, 'prefix': 'FTMA'})

        # Find all DER certificates
        der_header = b'\x30\x82'
        offset = 0
        while True:
            offset = self.firmware.find(der_header, offset)
            if offset == -1:
                break

            self.regions.append({'name': f'certificate_{hex(offset)}', 'offset': offset, 'type': 'certificate'})

            length_bytes = self.firmware[offset + 2 : offset + 4]
            length = struct.unpack('>H', length_bytes)[0]
            offset += 4 + length

        # The http files region is at a fixed offset
        self.regions.append({'name': 'http files', 'offset': 0x7000})

        self.regions.sort(key=lambda x: x['offset'])

    def _calculate_sizes_and_extract(self):
        """
        Calculates the size of each region and extracts the data.
        """
        for i, region in enumerate(self.regions):
            start = region['offset']
            if i + 1 < len(self.regions):
                end = self.regions[i+1]['offset']
            else:
                end = len(self.firmware)

            size = end - start
            data = self.firmware[start:end]

            name = region['name']

            filename = name.replace(' ', '_')
            if 'type' in region and region['type'] == 'certificate':
                filename += '.der'
            else:
                filename += '.bin'

            extracted_file_path = os.path.join(self.output_dir, filename)
            with open(extracted_file_path, 'wb') as f_out:
                f_out.write(data)

            region['size'] = size
            print(f"Extracted {filename} at offset {hex(start)} with size {hex(size)}")

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
