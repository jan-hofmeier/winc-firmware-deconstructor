#!/usr/bin/env python3
import os
import re
import argparse
import struct

class FirmwareExtractor:
    """
    A tool for deconstructing WINC1500 firmware dump files.
    """
    def __init__(self, dump_file, output_dir, source_parts_dir):
        self.dump_file = dump_file
        self.source_parts_dir = source_parts_dir
        self.output_dir = output_dir
        self.firmware = self._read_file(dump_file)
        self.config = self._parse_config()
        self.extracted_parts = {}

    def _read_file(self, file_path):
        """Reads a binary file and returns its content."""
        with open(file_path, 'rb') as f:
            return f.read()

    def _parse_config(self):
        """
        Parses a flash_image.config file. This is needed for http file
        extraction and for generating a more complete config file.
        """
        config = {}
        if self.source_parts_dir:
            for root, dirs, files in os.walk(self.source_parts_dir):
                for file in files:
                    if file.endswith('.config'):
                        with open(os.path.join(root, file), 'r') as f:
                            current_section = None
                            for line in f:
                                line = line.strip()
                                if not line or line.startswith('#'):
                                    continue

                                section_match = re.match(r'\[(.*)\]', line)
                                if section_match:
                                    current_section = section_match.group(1)
                                    config[current_section] = {}
                                elif current_section:
                                    key_value_match = re.match(r'(\w+(?:\s\w+)*)\s*is\s*(.*)', line)
                                    if key_value_match:
                                        key = key_value_match.group(1).strip()
                                        value = key_value_match.group(2).strip()
                                        if key in config[current_section]:
                                            if not isinstance(config[current_section][key], list):
                                                config[current_section][key] = [config[current_section][key]]
                                            config[current_section][key].append(value)
                                        else:
                                            config[current_section][key] = value
        return config

    def extract_all(self):
        """
        Extracts all known regions from the firmware dump.
        """
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        self._find_and_extract_firmware_parts()
        self._find_and_extract_certificates()
        self._extract_http_files()
        self._generate_config()

    def _find_and_extract_firmware_parts(self):
        """
        Finds and extracts all firmware parts based on their magic numbers.
        This method requires the source directory to get the size of the parts.
        """
        if not self.source_parts_dir:
            print("Source directory needed for firmware part extraction.")
            return

        for section, data in self.config.items():
            if data.get('type') == 'firmware':
                self._extract_firmware_part(section, data)

    def _extract_firmware_part(self, section, data):
        name = os.path.basename(data.get('file'))
        magic = data.get('prefix').encode('ascii')
        schema = int(data.get('schema', 1))

        occurrence = 0
        if section == 'downloader firmware':
            occurrence = 1

        source_file_path = os.path.join(self.source_parts_dir, 'firmware', name)
        if not os.path.exists(source_file_path):
            print(f"Source file not found: {source_file_path}")
            return

        with open(source_file_path, 'rb') as f_source:
            source_data_full = f_source.read()

        data_len = len(source_data_full)

        magic_offset = -1
        for i in range(occurrence + 1):
            magic_offset = self.firmware.find(magic, magic_offset + 1)
            if magic_offset == -1:
                break

        if magic_offset == -1:
            print(f"Magic number for {name} (occurrence {occurrence}) not found.")
            return

        dump_data_start = magic_offset
        dump_data_end = dump_data_start + data_len

        if schema == 4:
            dump_data_end += 4

        dump_data = self.firmware[dump_data_start:dump_data_end]

        extracted_file_path = os.path.join(self.output_dir, name)
        with open(extracted_file_path, 'wb') as f_out:
            f_out.write(dump_data)

        self.extracted_parts[section] = {'offset': magic_offset, 'size': len(dump_data)}
        print(f"Reconstructed {name} at offset {hex(magic_offset)} with size {hex(len(dump_data))}")

    def _find_and_extract_certificates(self):
        # ... (rest of the code is the same as before)
        pass

    def _extract_http_files(self):
        # ... (rest of the code is the same as before)
        pass

    def _generate_config(self):
        # ... (rest of the code is the same as before)
        pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract firmware parts from a dump file.')
    parser.add_argument('dump_file', help='The firmware dump file.')
    parser.add_argument('output_dir', help='The directory to write the extracted parts to.')
    parser.add_argument('source_dir', help='The directory containing the source firmware parts.')
    args = parser.parse_args()

    extractor = FirmwareExtractor(args.dump_file, args.output_dir, source_parts_dir=args.source_dir)
    extractor.extract_all()
