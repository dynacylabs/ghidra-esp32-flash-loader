# Changelog

All notable changes to the extension will be documented here. Inspired
by [keep a changelog](https://keepachangelog.com/en/1.0.0/)

## Unreleased

## [v1.0.0](https://github.com/saibotk/ghidra-esp32-flash-loader/tree/v1.0.0) (2024-11-04)

### Added

- Support for the ESP32-C3
- Automatic suggestion for the correct languages for the image on import
- Detection and parsing of extended header information in the image
- Uniquely name the code blocks in Ghidra to avoid conflicts
- ROM files for all currently available ESP32 chips
- Use the official SVD files from Espressif for the peripherals of all ESP32 chips

### Changed

- Refactored large portions of the code
- Dedicated ChipId enum to easier handle the different ESP32 chips
- Correctly loaded the offsets, especially for when loading a full flash image with a partition table

### Removed

- SVD loader Ghidra scripts, if you need them download them separately
- ESP32Analyzer, which only annotated the application image info