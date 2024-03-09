# RP2040 3rd Stage Bootloader

## 3rd stage bootloader for the Raspberry Pi RP2040 MCU based on it's C/C++ SDK.

#### ( ! ) A bootloader selects the correct application to boot from various contenders. A Bootloader is also supposed to be secure i.e. once written to flash it cannot be changed or read(?). This implementation of a bootloader is not secure in this sense. This bootloader implementation helps the user to select the correct app and provide OTA support as well. For more security the user might use a special flash IC to protect the areas where the bootloader is written from change or reading.

### Features
- App Selection
- OTA
- App Rollback
- Integrity Check
- Signature Check (!)

( ! ): This is not secure at all as the public key on the flash can be changed easily. At best some obfuscation techniques can be employed or a special secure flash IC can be used.

### Strategy

Letting the user specify the flash storage size and the number of apps on flash storage they want. Each app has a certain address in the flash. The apps are prepended with a header containing meta data about the app which follows. And then compiling the app for different locations without the boot2 section. The application numbering starts from 0.  <b>The 0<sup>th</sup> app is required</b>.

### Bootloader Build Process

The 3rd stage bootloader is a straight forward C/C++ application for the RP2040 MCU. It doesn't need any special compiling process. The user just needs to set the ECC SECP256R1 public key in the file `bootloader/public_key.h` as hexadecimal representation of bytes.

Example public key:

```
#define PUBLIC_KEY_BYTES "\x4\x99\x15\x69\x80\x40\xed\x97\xdd\xc\x7f\x0\x1e\xa4\xea\x7a\xfd\x54\x25\xcc\x5c\xbf\x61\x5d\xd9\x37\xea\xe2\x1a\x55\x1\x96\x4d\xeb\x39\x8a\xff\x54\x4\x1c\x6\xb4\x5f\xd1\xd3\x22\x5c\x48\xfe\x75\xe9\x72\x81\x41\xb8\x23\xc4\x78\xfe\xe9\xc4\x83\x90\xc8\x37"
```

The bootloader depends on mbedtls for hashing and for verifing the sign.

Compile:
```
cd bootloader
mkdir build
cd build
cmake ..
make
```
### Bootloader Flashing

Flash the bootloader at address 0x00 through your preferred means. 

### Application Build Process

Before starting the application build process the user has to identify the project to be built and modify that project's CMakeLists.txt to use a specific linker file which will be automatically modified to build the project.

Steps to add the linker file to the project:

- Copy the linker script at `src/rp2_common/pico_standard_link/memmap_default.ld` in the pico sdk to the desired project.
- Add `pico_set_linker_script(...)` in the CMakeLists.txt of the project.
Example: `pico_set_linker_script(main ${CMAKE_CURRENT_SOURCE_DIR}/memmap_default.ld)`
 

The user can now start the application build process.

A convenient Python script called the `build.py` is provided in the `app_build/` directory to build the apps.

The `build.py` script uses JSON config file `build_config.json` to prepare the build process. The user can modify the following keys accoriding to the requirements.
- majorVersion
- minorVersion
- buildNumber
- defaultMemmapFile
- flashSize
- appSize
- bootloaderSize
- defaultHeaderSize 

An app for the 0th location can be built using the `build.py` script as follows.

```
cd app_build
./build.py -p=0 -l <path_to_the_linker_script> -b=<build_directory_of_the_project> -k <path_to_the_private_key>
```

You can omit the `-k` flag if you dont want to sign the app.

A binary file named `bin_0.bin` will be generated in the `app_build` directory.   

The script will also out the address at which to write the generated app.

### Application Flashing

Flash the generated app at address given by the build script through your preferred means. 

The address for the 0<sup>th</sup> app is always 0x10020000.
The address for the n<sup>th</sup> app is calculated using (appPosition * appSize) + bootloaderSize + 0x1000.