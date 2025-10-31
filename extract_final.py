import os
import re

def extract_firmware(dump_file, output_dir, source_parts_dir):
    """
    Extracts firmware parts by stripping the header from the source file
    and aligning with the data in the dump.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(dump_file, 'rb') as f:
        firmware = f.read()

    firmware_parts = {
        'boot_firmware.bin': b'NMIS',
        'wifi_firmware.bin': b'NMID',
        'burst_tx_firmware.bin': b'FTMA'
    }

    for name, magic in firmware_parts.items():
        source_file_path = os.path.join(source_parts_dir, name)
        if not os.path.exists(source_file_path):
            print(f"Source file not found: {source_file_path}")
            continue

        with open(source_file_path, 'rb') as f_source:
            source_data_full = f_source.read()

        header = source_data_full[:4]
        source_data_payload = source_data_full[4:]

        magic_offset = firmware.find(magic)
        if magic_offset == -1:
            print(f"Magic number for {name} not found.")
            continue

        dump_data_start = magic_offset + 8
        dump_data_end = dump_data_start + len(source_data_payload)
        dump_data_payload = firmware[dump_data_start:dump_data_end]

        reconstructed_part = header + dump_data_payload

        extracted_file_path = os.path.join(output_dir, name)
        with open(extracted_file_path, 'wb') as f_out:
            f_out.write(reconstructed_part)

        print(f"Reconstructed {name}")

        if reconstructed_part == source_data_full:
            print(f"  - Verification successful.")
        else:
            print(f"  - Verification failed.")


if __name__ == '__main__':
    dump_file = 'firmwares/dump_19.7.7.bin'
    output_dir = 'extracted_parts'
    source_parts_dir = 'firmwares/sourceparts/19.7.7/firmware'
    extract_firmware(dump_file, output_dir, source_parts_dir)
