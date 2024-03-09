#!/bin/python3

import argparse
import subprocess
import os
import json
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature,Prehashed

DEFAULT_MEMMAP_FILE = "./memmap.ld"
FLASH_SIZE = 4 * 1024 * 1024  # 4M
APP_SIZE = 1 * 1024 * 1024  # 1M
BOOTLOADER_SIZE = 128 * 1024  # 128K
DEFAULT_HEADER_SIZE = 0x1000  # 4K
XIP_BASE = 0x10000000
BUILD_CONFIG = {}


# OPTIONS BITS
OPTIONS_APP_SIGNED_BIT = 0


def crc32c(buf):
    crc = 0xFFFFFFFF
    crctable = [
        0x00000000,
        0xF26B8303,
        0xE13B70F7,
        0x1350F3F4,
        0xC79A971F,
        0x35F1141C,
        0x26A1E7E8,
        0xD4CA64EB,
        0x8AD958CF,
        0x78B2DBCC,
        0x6BE22838,
        0x9989AB3B,
        0x4D43CFD0,
        0xBF284CD3,
        0xAC78BF27,
        0x5E133C24,
        0x105EC76F,
        0xE235446C,
        0xF165B798,
        0x030E349B,
        0xD7C45070,
        0x25AFD373,
        0x36FF2087,
        0xC494A384,
        0x9A879FA0,
        0x68EC1CA3,
        0x7BBCEF57,
        0x89D76C54,
        0x5D1D08BF,
        0xAF768BBC,
        0xBC267848,
        0x4E4DFB4B,
        0x20BD8EDE,
        0xD2D60DDD,
        0xC186FE29,
        0x33ED7D2A,
        0xE72719C1,
        0x154C9AC2,
        0x061C6936,
        0xF477EA35,
        0xAA64D611,
        0x580F5512,
        0x4B5FA6E6,
        0xB93425E5,
        0x6DFE410E,
        0x9F95C20D,
        0x8CC531F9,
        0x7EAEB2FA,
        0x30E349B1,
        0xC288CAB2,
        0xD1D83946,
        0x23B3BA45,
        0xF779DEAE,
        0x05125DAD,
        0x1642AE59,
        0xE4292D5A,
        0xBA3A117E,
        0x4851927D,
        0x5B016189,
        0xA96AE28A,
        0x7DA08661,
        0x8FCB0562,
        0x9C9BF696,
        0x6EF07595,
        0x417B1DBC,
        0xB3109EBF,
        0xA0406D4B,
        0x522BEE48,
        0x86E18AA3,
        0x748A09A0,
        0x67DAFA54,
        0x95B17957,
        0xCBA24573,
        0x39C9C670,
        0x2A993584,
        0xD8F2B687,
        0x0C38D26C,
        0xFE53516F,
        0xED03A29B,
        0x1F682198,
        0x5125DAD3,
        0xA34E59D0,
        0xB01EAA24,
        0x42752927,
        0x96BF4DCC,
        0x64D4CECF,
        0x77843D3B,
        0x85EFBE38,
        0xDBFC821C,
        0x2997011F,
        0x3AC7F2EB,
        0xC8AC71E8,
        0x1C661503,
        0xEE0D9600,
        0xFD5D65F4,
        0x0F36E6F7,
        0x61C69362,
        0x93AD1061,
        0x80FDE395,
        0x72966096,
        0xA65C047D,
        0x5437877E,
        0x4767748A,
        0xB50CF789,
        0xEB1FCBAD,
        0x197448AE,
        0x0A24BB5A,
        0xF84F3859,
        0x2C855CB2,
        0xDEEEDFB1,
        0xCDBE2C45,
        0x3FD5AF46,
        0x7198540D,
        0x83F3D70E,
        0x90A324FA,
        0x62C8A7F9,
        0xB602C312,
        0x44694011,
        0x5739B3E5,
        0xA55230E6,
        0xFB410CC2,
        0x092A8FC1,
        0x1A7A7C35,
        0xE811FF36,
        0x3CDB9BDD,
        0xCEB018DE,
        0xDDE0EB2A,
        0x2F8B6829,
        0x82F63B78,
        0x709DB87B,
        0x63CD4B8F,
        0x91A6C88C,
        0x456CAC67,
        0xB7072F64,
        0xA457DC90,
        0x563C5F93,
        0x082F63B7,
        0xFA44E0B4,
        0xE9141340,
        0x1B7F9043,
        0xCFB5F4A8,
        0x3DDE77AB,
        0x2E8E845F,
        0xDCE5075C,
        0x92A8FC17,
        0x60C37F14,
        0x73938CE0,
        0x81F80FE3,
        0x55326B08,
        0xA759E80B,
        0xB4091BFF,
        0x466298FC,
        0x1871A4D8,
        0xEA1A27DB,
        0xF94AD42F,
        0x0B21572C,
        0xDFEB33C7,
        0x2D80B0C4,
        0x3ED04330,
        0xCCBBC033,
        0xA24BB5A6,
        0x502036A5,
        0x4370C551,
        0xB11B4652,
        0x65D122B9,
        0x97BAA1BA,
        0x84EA524E,
        0x7681D14D,
        0x2892ED69,
        0xDAF96E6A,
        0xC9A99D9E,
        0x3BC21E9D,
        0xEF087A76,
        0x1D63F975,
        0x0E330A81,
        0xFC588982,
        0xB21572C9,
        0x407EF1CA,
        0x532E023E,
        0xA145813D,
        0x758FE5D6,
        0x87E466D5,
        0x94B49521,
        0x66DF1622,
        0x38CC2A06,
        0xCAA7A905,
        0xD9F75AF1,
        0x2B9CD9F2,
        0xFF56BD19,
        0x0D3D3E1A,
        0x1E6DCDEE,
        0xEC064EED,
        0xC38D26C4,
        0x31E6A5C7,
        0x22B65633,
        0xD0DDD530,
        0x0417B1DB,
        0xF67C32D8,
        0xE52CC12C,
        0x1747422F,
        0x49547E0B,
        0xBB3FFD08,
        0xA86F0EFC,
        0x5A048DFF,
        0x8ECEE914,
        0x7CA56A17,
        0x6FF599E3,
        0x9D9E1AE0,
        0xD3D3E1AB,
        0x21B862A8,
        0x32E8915C,
        0xC083125F,
        0x144976B4,
        0xE622F5B7,
        0xF5720643,
        0x07198540,
        0x590AB964,
        0xAB613A67,
        0xB831C993,
        0x4A5A4A90,
        0x9E902E7B,
        0x6CFBAD78,
        0x7FAB5E8C,
        0x8DC0DD8F,
        0xE330A81A,
        0x115B2B19,
        0x020BD8ED,
        0xF0605BEE,
        0x24AA3F05,
        0xD6C1BC06,
        0xC5914FF2,
        0x37FACCF1,
        0x69E9F0D5,
        0x9B8273D6,
        0x88D28022,
        0x7AB90321,
        0xAE7367CA,
        0x5C18E4C9,
        0x4F48173D,
        0xBD23943E,
        0xF36E6F75,
        0x0105EC76,
        0x12551F82,
        0xE03E9C81,
        0x34F4F86A,
        0xC69F7B69,
        0xD5CF889D,
        0x27A40B9E,
        0x79B737BA,
        0x8BDCB4B9,
        0x988C474D,
        0x6AE7C44E,
        0xBE2DA0A5,
        0x4C4623A6,
        0x5F16D052,
        0xAD7D5351,
    ]

    for byte in buf:
        crc = (crc >> 8) ^ crctable[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFFFFFF


def replace_line_with_string(filename, search_string, replacement):
    # Read the file and store its lines
    with open(filename, "r") as file:
        lines = file.readlines()

    # Find the line containing the search string
    for i, line in enumerate(lines):
        if search_string in line:
            # Replace the line with the replacement string
            lines[i] = replacement + "\n"  # Adding '\n' to maintain line endings
            break

    # Write the modified lines back to the file
    with open(filename, "w") as file:
        file.writelines(lines)


def modify_comment_around_text(
    input_file,
    output_file,
    target_text,
    comment=True,
    comment_start="/*",
    comment_end="*/",
):
    """
    Reads content from input_file, finds target_text, and adds/comments around it if not already commented.
    Writes the modified content to output_file.
    """
    # Open input file and read its contents
    with open(input_file, "r") as f:
        text = f.read()

    # Check if the target text is already surrounded by comments
    if comment:
        # Comment the text if not already commented
        if text.find(comment_start + "\n" + target_text + "\n" + comment_end) == -1:
            text = text.replace(
                target_text, f"{comment_start}\n{target_text}\n{comment_end}"
            )
            print("Text commented successfully!")
        else:
            print("Text is already commented. No modifications needed.")
    else:
        # Uncomment the text if commented
        if text.find(comment_start + "\n" + target_text + "\n" + comment_end) != -1:
            text = text.replace(
                comment_start + "\n" + target_text + "\n" + comment_end, target_text
            )
            print("Text uncommented successfully!")
        else:
            print("Text is already uncommented. No modifications needed.")

    # Write the modified text to the output file
    with open(output_file, "w") as f:
        f.write(text)


def prepare_app_position(ld_file: str, pos: int):

    # max possible positions
    max_poitions = int((FLASH_SIZE - BOOTLOADER_SIZE) / APP_SIZE)

    # check if pos is invalid
    if pos < 0 or pos > max_poitions - 1:
        raise Exception("invalid position")

    origin_address = XIP_BASE + (pos * APP_SIZE) + BOOTLOADER_SIZE + DEFAULT_HEADER_SIZE

    print(origin_address)

    replace_line_with_string(
        f"{ld_file}",
        "FLASH(rx)",
        f"    FLASH(rx) : ORIGIN = {hex(origin_address)}, LENGTH = 1024k",
    )

    return origin_address - DEFAULT_HEADER_SIZE


def enable_disable_boot2_section(ld_file: str, disable_boot2_section: bool):
    print("Disabling 2nd Stage Bootloader...")

    modify_comment_around_text(
        ld_file,
        ld_file,
        """.boot2 : {
        __boot2_start__ = .;
        KEEP (*(.boot2))
        __boot2_end__ = .;
    } > FLASH

    ASSERT(__boot2_end__ - __boot2_start__ == 256,
        "ERROR: Pico second stage bootloader must be 256 bytes in size")""",
        disable_boot2_section,
    )

    print("Disabled 2nd Stage Bootloader.")
    return


def start_make_build(build_directory: str):

    try:
        # Execute the 'make' command in the specified directory
        subprocess.run(["make"], cwd=build_directory, check=True)
        print("Make command executed successfully in", build_directory)
    except subprocess.CalledProcessError as e:
        print("Error executing make command:", e)
    except FileNotFoundError:
        print("Error: Makefile not found in", build_directory)

    return


def load_private_key_from_file(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
    return private_key


def load_public_key_from_file(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )
    return public_key


def ecc_sign_hash(hash: bytes, keypath: str) -> bytes:

    print("Performing ECDSA for signature...")
    print(f"Performing ECDSA on Hash: {hash.hex()}")

    private_key = load_private_key_from_file(keypath)


    algorithm = Prehashed(hashes.SHA256())

    signature = private_key.sign(
        hash,
        ec.ECDSA(algorithm),
    )

    print(f"Curve: {private_key.curve.name}")
    print(f"Signature: {list(signature)}")

    r, s = decode_dss_signature(signature)
    # print(f"R: {r}")
    # print(f"S: {s}")

    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder="big")
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder="big")

    print(f"R: {r_bytes.hex()}")
    print(f"S: {s_bytes.hex()}")

    print(f"Performed ECDSA signature.")

    # optional public key test
    # public_key = load_public_key_from_file("./public-key.pem")
    # try:
    #     public_key.verify(signature, hash, ec.ECDSA(hashes.SHA256()))
    #     print("Valid Sign")
    # except Exception:
    #     print("Failed to Verify Sign")
    #####

    return r_bytes + s_bytes


def set_or_clear_bit(num, bit_position, set_bit=True):
    if set_bit:
        return num | (1 << bit_position)  # Set the bit
    else:
        return num & ~(1 << bit_position)  # Clear the bit


def options_prepare(is_signed: bool) -> bytes:

    options = 0

    if is_signed:
        print("options: setting signed bit")
        options = set_or_clear_bit(options, OPTIONS_APP_SIGNED_BIT, True)

    return options.to_bytes(4, "little")


def prepare_final_binary(build_directory: str, pos: int, ecc_key_path: str):
    print("Preparing final binary...")

    # get the binary file
    bin_file = ""
    for filename in os.listdir(build_directory):
        if filename.endswith(".bin"):
            bin_file = os.path.join(build_directory, filename)

    if bin_file == "":
        raise Exception("unable to find generated binary file")

    print(f"Using bin file: {bin_file}")

    # read bin data

    bin_data = open(bin_file, "rb").read()

    # calculate sha256
    bin_hash = bytes()
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(bin_data)
    bin_hash = digest.finalize()

    print(f"Calculated Hash: {bin_hash.hex()}")

    # prepare headers

    header = [0x00 for i in range(DEFAULT_HEADER_SIZE)]

    # options
    header[0:4] = options_prepare(len(ecc_key_path) > 0)

    # version
    header[4:8] = int(BUILD_CONFIG["majorVersion"]).to_bytes(4, "little")
    header[8:12] = int(BUILD_CONFIG["minorVersion"]).to_bytes(4, "little")
    header[12:16] = int(BUILD_CONFIG["buildNumber"]).to_bytes(4, "little")

    # hash
    header[16:48] = bin_hash

    # sign
    if len(ecc_key_path) > 0:
        sign = ecc_sign_hash(bin_hash, ecc_key_path)
        header[48:112] = sign

    # size
    header[112:116] = int(len(bin_data)).to_bytes(4, "little")

    # variable
    # header[116:120] = variables

    # time
    curr_time = int(time.time()) & 0xFFFFFFFF
    header[120:124] = curr_time.to_bytes(4, "little")

    print(f"Time Unix: {curr_time}")

    # crc32
    crc = crc32c(header[:124])
    header[124:128] = crc.to_bytes(4, "little")

    print(f"Calculated CRC: {crc}, {list(crc.to_bytes(4,'little'))}")

    print(f"Generated Header: {header[:128]} with length: {len(header)}")

    # prepend generated header and write the new bin file

    new_bin_name = f"bin_{pos}.bin"

    f = open(os.path.join(new_bin_name), "wb")
    f.write(bytearray(header) + bin_data)
    f.close()

    print("Prepared final binary.")


def main():

    global DEFAULT_MEMMAP_FILE
    global FLASH_SIZE
    global APP_SIZE
    global BOOTLOADER_SIZE
    global DEFAULT_HEADER_SIZE

    # Create argument parser
    parser = argparse.ArgumentParser(
        description="Prepare RP2040 C/C++ project build for OTA support."
    )

    # Add arguments
    parser.add_argument(
        "-l",
        "--ld_file",
        type=str,
        default=f"{DEFAULT_MEMMAP_FILE}",
        help="Path to the linker script(memmap).",
    )
    parser.add_argument(
        "-p",
        "--binary_position",
        type=int,
        default=0,
        help="Position of the binary in the flash.",
    )

    parser.add_argument(
        "-d",
        "--disable_boot2",
        type=bool,
        default=True,
        help="Remove the 2nd stage bootloader from build.",
    )

    parser.add_argument(
        "-a",
        "--auto_build",
        type=bool,
        default=False,
        help="Start the make process automatically.",
    )

    parser.add_argument(
        "-b",
        "--build_directory",
        type=str,
        default="./build",
        help="Build directory of the project.",
    )

    parser.add_argument(
        "-o",
        "--prepare_final_bin",
        type=bool,
        default=True,
        help="Prepare the final binary by adding necessary headers.",
    )

    parser.add_argument(
        "-c",
        "--build_config",
        type=str,
        default="./build_config.json",
        help="JSON file for build configuration.",
    )

    parser.add_argument(
        "-k",
        "--ecc_key_path",
        type=str,
        default="",
        help="ECC key to use for signature.",
    )

    # Parse arguments
    args = parser.parse_args()

    # Access parsed arguments
    ld_file = args.ld_file
    binary_position = args.binary_position
    disable_boot2 = args.disable_boot2
    auto_build = args.auto_build
    build_directory = args.build_directory
    prepare_final_bin = args.prepare_final_bin
    build_config = args.build_config
    ecc_key_path = args.ecc_key_path

    # verify
    # if binary_position == 0 and disable_boot2:
    #     print(
    #         "WARNING: binary position is 0 that means it is the main app and disabling 2nd stage bootloader is not allowed. Enabling 2nd stage bootloader."
    #     )
    #     disable_boot2 = False
    # elif binary_position > 0 and not disable_boot2:
    #     print(
    #         "WARNING: binary position is NOT 0 that means it is NOT the main app and 2nd stage bootloader should be disabled. Disabling 2nd stage bootloader."
    #     )
    #     disable_boot2 = True

    # Parsed arguments
    print("LD File(memmap):", ld_file)
    print("Binary Position:", binary_position)
    print("Disable boot2:", disable_boot2)
    print("Auto Build:", auto_build)
    print("Build Directory:", build_directory)
    print("Prepare Final Binary:", prepare_final_bin)
    print("ECC Key Path:", ecc_key_path)

    # json load build config
    global BUILD_CONFIG
    BUILD_CONFIG = json.loads(open(build_config, "r").read())

    # change default vars
    DEFAULT_MEMMAP_FILE = BUILD_CONFIG["defaultMemmapFile"]
    FLASH_SIZE = BUILD_CONFIG["flashSize"]
    APP_SIZE = BUILD_CONFIG["appSize"]
    BOOTLOADER_SIZE = BUILD_CONFIG["bootloaderSize"]
    DEFAULT_HEADER_SIZE = BUILD_CONFIG["defaultHeaderSize"]

    print("Build Config:", BUILD_CONFIG)

    # Run logic
    origin_address = prepare_app_position(ld_file, binary_position)

    enable_disable_boot2_section(ld_file, disable_boot2)

    if auto_build:
        start_make_build(build_directory)

    if prepare_final_bin:
        prepare_final_binary(build_directory, binary_position, ecc_key_path)

    print("DONE!")
    print(f"Flash app at {hex(origin_address)}.")


if __name__ == "__main__":
    main()
