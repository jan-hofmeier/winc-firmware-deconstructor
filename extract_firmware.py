#!/usr/bin/env python3
import os
import re
import argparse
import struct

class FirmwareExtractor:
    def __init__(self, dump_file, output_dir):
        self.dump_file = dump_file
        self.output_dir = output_dir
        self.firmware = self._read_file(dump_file)
        self.magic_occurrences = {}
        self.extracted_parts = {}

    def _read_file(self, file_path):
        with open(file_path, 'rb') as f:
            return f.read()

    def extract_all(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        self._find_and_extract_certificates()
        self._extract_http_files()
        self._find_and_extract_firmware_parts()
        self._generate_config()

    def _find_and_extract_firmware_parts(self):
        magic_numbers = {
            b'NMIS': 'boot_firmware',
            b'NMID': 'wifi_firmware',
            b'FTMA': 'ate_firmware',
        }

        found_parts = []
        for magic, name in magic_numbers.items():
            offset = 0
            while True:
                offset = self.firmware.find(magic, offset)
                if offset == -1:
                    break
                found_parts.append({'name': name, 'offset': offset})
                offset += len(magic)

        found_parts.sort(key=lambda x: x['offset'])

        for i, part in enumerate(found_parts):
            start = part['offset']
            if i + 1 < len(found_parts):
                end = found_parts[i+1]['offset']
            else:
                end = len(self.firmware)

            size = end - start
            data = self.firmware[start:end]

            name = part['name']
            if len([p for p in found_parts if p['name'] == name]) > 1:
                occurrence = len([p for p in self.extracted_parts if p.startswith(name)])
                name = f"{name}_{occurrence}"

            extracted_file_path = os.path.join(self.output_dir, f'{name}.bin')
            with open(extracted_file_path, 'wb') as f_out:
                f_out.write(data)

            self.extracted_parts[name] = {'offset': start, 'size': size}
            print(f"Reconstructed {name}.bin at offset {hex(start)} with size {hex(size)}")

    def _find_and_extract_certificates(self):
        der_header = b'\x30\x82'
        offset = 0
        while True:
            offset = self.firmware.find(der_header, offset)
            if offset == -1:
                break

            length_bytes = self.firmware[offset + 2 : offset + 4]
            length = struct.unpack('>H', length_bytes)[0]
            total_length = 4 + length

            cert_data = self.firmware[offset : offset + total_length]

            cert_name = f'certificate_{hex(offset)}.der'
            extracted_file_path = os.path.join(self.output_dir, cert_name)
            with open(extracted_file_path, 'wb') as f_out:
                f_out.write(cert_data)

            self.extracted_parts[cert_name] = {'offset': offset, 'size': len(cert_data)}
            print(f"Reconstructed {cert_name} at offset {hex(offset)} with size {hex(len(cert_data))}")

            offset += total_length

    def _extract_http_files(self):
        http_files_offset = 0x7000
        http_files_end = 0x9000
        current_offset = http_files_offset
        filename_len = 32

        while current_offset < http_files_end:
            # Find the next non-null byte to start the file entry
            while current_offset < http_files_end and self.firmware[current_offset] == 0:
                current_offset += 1

            if current_offset >= http_files_end:
                break

            filename_bytes = self.firmware[current_offset : current_offset + filename_len]
            filename = filename_bytes.split(b'\x00', 1)[0].decode('ascii', errors='ignore')

            if not filename:
                break

            size_bytes = self.firmware[current_offset + filename_len : current_offset + filename_len + 4]
            if len(size_bytes) < 4:
                break
            size = struct.unpack('<I', size_bytes)[0]

            data_start = current_offset + filename_len + 4
            if data_start + size > http_files_end:
                break
            data = self.firmware[data_start : data_start + size]

            extracted_file_path = os.path.join(self.output_dir, filename)
            with open(extracted_file_path, 'wb') as f_out:
                f_out.write(data)

            if 'http files' not in self.extracted_parts:
                self.extracted_parts['http files'] = []
            self.extracted_parts['http files'].append({'name': filename, 'offset': current_offset, 'size': size})
            print(f"Reconstructed {filename} at offset {hex(current_offset)} with size {hex(size)}")

            current_offset = data_start + size

    def _generate_config(self):
        with open(os.path.join(self.output_dir, 'generated_flash_image.config'), 'w') as f:
            f.write('[flash]\n')
            f.write('size is 1M\n')

            all_parts = []
            for section, data in self.extracted_parts.items():
                if isinstance(data, list):
                    all_parts.append((data[0]['offset'], section))
                else:
                    all_parts.append((data['offset'], section))
            all_parts.sort()

            for offset, section in all_parts:
                f.write(f'region at {hex(offset)} is [{section}]\n')

            f.write('\n')

        print("\nGenerated flash_image.config")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract firmware parts from a dump file.')
    parser.add_argument('dump_file', help='The firmware dump file.')
    parser.add_argument('output_dir', help='The directory to write the extracted parts to.')
    args = parser.parse_args()

    extractor = FirmwareExtractor(args.dump_file, args.output_dir)
    extractor.extract_all()
