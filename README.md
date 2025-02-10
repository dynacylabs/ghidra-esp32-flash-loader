# ESP32 Flash Image Loader for Ghidra

This extension allows you to import ESP32 flash images into Ghidra.
It can load either a full flash image with the bootloader and application or just the application part.

In both cases, the image will be fully loaded into Ghidra with the correct address offsets and annotations.
Additionally, the extension will load the ESP32 peripherals and their registers from the SVD files provided by
Espressif.
The ROM code for the associated ESP32 chip will also be loaded into Ghidra, so the code can be properly analyzed.

It also includes several SVD-related scripts

## Supported ESP32 chips:


- ESP32
- ESP32-S2
- ESP32-C3

## Installation

1. Download the latest release from the [releases page](https://github.com/saibotk/ghidra-esp32-flash-loader/releases)
2. Extract the zip file, it contains the actual extension zip file
3. In Ghidra, go to `File -> Install Extensions...`
4. Select the + icon in the top right corner
5. Select the downloaded zip file and click OK
6. Done! Restart Ghidra and you should be able to load ESP32 flash images

## Building the extension

The extension can be built using gradle.
The following commands will build the extension and store it in the `dist/` directory.

*Please adjust the installation directory to your Ghidra directory*

```bash
# For Flatpak installations:
# GHIDRA_INSTALL_DIR=/var/lib/flatpak/app/org.ghidra_sre.Ghidra/current/active/files/lib/ghidra
export GHIDRA_INSTALL_DIR=/opt/ghidra/

gradle
```

Now you can install the extension as described above just select the zip file in the `dist/` directory.

## Licenses

This project and its code is licensed under Apache 2.0, unless specified otherwise.
You can find the full license text in the [LICENSE](./LICENSE) file.
Some folders contain third-party content, subject to their own licensing as described in the section below.

The license was agreed upon in this discussion: 
https://github.com/tslater2006/esp32_flash_loader/issues/6

### Third party licenses

- Espressif SVD files ([/data/svd](./data/svd)): Licensed under Apache 2.0.
- ESP32 ROM files ([/data/*.elf](./data)): Licensed under Apache 2.0., ROMs contain additional third-party-libraries, see
  [here](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/COPYRIGHT.html#rom-source-code-copyrights).

## Thanks

A big thanks to the original upstream project for their contribution to open source their work.
Also thanks to all the other contributors for their forks and improvements making this fork possible.
We build upon the work of the following projects:

- https://github.com/tslater2006/esp32_flash_loader (Original project)
- https://github.com/Ebiroll/esp32_flash_loader (Fork)
- https://github.com/dynacylabs/ghidra-esp32-flash-loader (Fork)

## Adding scripts


To add the checked-out Git repository to your Ghidra-Scripts search paths:
- Open the 'CodeBrowser' from the 'Tool Chest'
- Open Window -> Script Manager
- In the new window click on the 'Manage Script Directories' icon on the top right of the window
- In the new window click on the 'Display file chooser to add bundles to list' icon on the top right of the window
- Select the folder containing your clone of the SVD-Loader-Ghidra repository
- Close the Bundle Manager Window
- Search for 'SVD' in your Script Manager
- Check the checkbox for the 'SVD-Loader.py'
- Close the Script Manager


