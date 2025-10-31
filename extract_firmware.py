#!/usr/bin/env python3
import os
import re
import argparse

def extract_firmware(dump_file, source_parts_dir, output_dir):
    """
    Extracts firmware parts from a dump file by aligning the data payload
    from the source files with the data in the dump.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(dump_file, 'rb') as f:
        firmware = f.read()

    # These are the standard firmware parts with a 4-byte header.
    # The burst_tx_firmware has a different schema and is not included.
    firmware_parts = {
        'boot_firmware.bin': b'NMIS',
        'wifi_firmware.bin': b'NMID',
    }

    for name, magic in firmware_parts.items():
        source_file_path = os.path.join(source_parts_dir, name)
        if not os.path.exists(source_file_path):
            print(f"Source file not found: {source_file_path}")
            continue

        with open(source_file_path, 'rb') as f_source:
            source_data_full = f_source.read()

        # The header is the first 4 bytes of the source file.
        header = source_data_full[:4]
        # The data payload is the rest of the file.
        source_data_payload = source_data_full[4:]

        # Find the magic number in the dump file.
        magic_offset = firmware.find(magic)
        if magic_offset == -1:
            print(f"Magic number for {name} not found.")
            continue

        # The data in the dump starts 8 bytes after the magic number
        # (4 for the magic, 4 for the dump-specific header).
        dump_data_start = magic_offset + 8
        dump_data_end = dump_data_start + len(source_data_payload)
        dump_data_payload = firmware[dump_data_start:dump_data_end]

        # Reconstruct the full firmware part by prepending the header
        # from the source file to the data from the dump.
        reconstructed_part = header + dump_data_payload

        # Write the reconstructed part to the output directory.
        extracted_file_path = os.path.join(output_dir, name)
        with open(extracted_file_path, 'wb') as f_out:
            f_out.write(reconstructed_part)

        print(f"Reconstructed {name}")

        # Verify that the reconstructed part matches the original source file.
        if reconstructed_part == source_data_full:
            print(f"  - Verification successful.")
        else:
            print(f"  - Verification failed.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract firmware parts from a dump file.')
    parser.add_argument('dump_file', help='The firmware dump file.')
    parser.add_argument('source_dir', help='The directory containing the source firmware parts.')
    parser.add_argument('output_dir', help='The directory to write the extracted parts to.')
    args = parser.parse_args()

    extract_firmware(args.dump_file, args.source_dir, args.output_dir)
