package esp32_loader.flash;

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;

public class ESP32AppSegment {

    public long PhysicalOffset;
    public int LoadAddress;
    public int Length;
    public byte[] Data;
    public SegmentType type;

    public ESP32AppSegment(ESP32AppImage app, BinaryReader reader) throws IOException {
        PhysicalOffset = reader.getPointerIndex();
        LoadAddress = reader.readNextInt();
        Length = reader.readNextInt();
        Data = reader.readNextByteArray(Length);

        // These can be found in the esptool targets: https://github.com/espressif/esptool/blob/master/esptool/targets/esp32c3.py
        // And then need to be renamed to match the tables from the technical specification memory section.
        switch (app.ChipId) {
            case ESP32C3 -> {
                if (LoadAddress >= 0x00000000 && LoadAddress < 0x00010000) {
                    type = SegmentType.PADDING;
                } else if (LoadAddress >= 0x3C000000 && LoadAddress < 0x3C800000) {
                    type = SegmentType.EXT_DROM;
                } else if (LoadAddress >= 0x3FC80000 && LoadAddress < 0x3FCE0000) {
                    type = SegmentType.DRAM1;
                } else if (LoadAddress >= 0x3FC88000 && LoadAddress < 0x3FD00000) {
                    type = SegmentType.UNKNOWN; // -> BYTE_ACCESSIBLE;
                } else if (LoadAddress >= 0x3FF00000 && LoadAddress < 0x3FF20000) {
                    type = SegmentType.DROM1;
                } else if (LoadAddress >= 0x40000000 && LoadAddress < 0x40040000) {
                    type = SegmentType.IROM0;
                } else if (LoadAddress >= 0x40040000 && LoadAddress < 0x40060000) {
                    type = SegmentType.IROM1; // -> IROM_MASK;
                } else if (LoadAddress >= 0x42000000 && LoadAddress < 0x42800000) {
                    type = SegmentType.EXT_IRAM;
                } else if (LoadAddress >= 0x4037C000 && LoadAddress < 0x40380000) {
                    type = SegmentType.IRAM0;
                } else if (LoadAddress >= 0x40380000 && LoadAddress < 0x403E0000) {
                    type = SegmentType.IRAM1;
                } else if (LoadAddress >= 0x50000000 && LoadAddress < 0x50002000) {
                    type = SegmentType.RTC_RAM;
                } else if (LoadAddress >= 0x600FE000 && LoadAddress < 0x60100000) {
                    type = SegmentType.UNKNOWN; // -> MEM_INTERNAL2;
                } else {
                    type = SegmentType.UNKNOWN;
                }
            }
            case ESP32S2 -> {
                /* determine access type via memory map */
                /*
                 * Loading section .flash.rodata, size 0x576c lma 0x3f000020 DROM0 Loading
                 * section .dram0.data, size 0x1e74 lma 0x3ffbe150 Loading section
                 * .iram0.vectors, size 0x403 lma 0x40024000 Loading section .iram0.text, size
                 * 0x9d40 lma 0x40024404 Loading section .flash.text, size 0x147f7 lma
                 * 0x40080020
                 */
                if (LoadAddress >= 0x3FFB0000 && LoadAddress <= 0x3FFB7FFF) {
                    type = SegmentType.DRAM0;
                } else if (LoadAddress >= 0x3FFB8000 && LoadAddress <= 0x3FFFFFFF) {
                    type = SegmentType.DRAM1;
                } else if (LoadAddress >= 0x40080000 && LoadAddress <= 0x40080000 + 4194304) {
                    type = SegmentType.IF_TXT;
                } else if (LoadAddress >= 0x40020000 && LoadAddress <= 0x40027FFF) {
                    type = SegmentType.IRAM0;
                } else if (LoadAddress >= 0x40028000 && LoadAddress <= 0x4006FFFF) {
                    type = SegmentType.IRAM1;
                } else if (LoadAddress >= 0x3F000000 && LoadAddress <= 0x3F3F0000) {
                    type = SegmentType.DF_ROA;
                } else if (LoadAddress >= 0x3F800000 && LoadAddress <= 0x3F800000 + 4194304) {
                    type = SegmentType.F_DATA;
                } else {
                    type = SegmentType.IRAM;
                }
            }
            case ESP32 -> {
                /* determine access type via memory map */
                if (LoadAddress >= 0x40800000 && LoadAddress <= 0x40800000 + 4194304) {
                    type = SegmentType.IROM0;
                } else if (LoadAddress >= 0x40000000 && LoadAddress <= 0x40000000 + 4194304) {
                    type = SegmentType.IRAM0;
                } else if (LoadAddress >= 0x40400000 && LoadAddress <= 0x40400000 + 4194304) {
                    type = SegmentType.IRAM1;
                } else if (LoadAddress >= 0x3F400000 && LoadAddress <= 0x3F400000 + 4194304) {
                    type = SegmentType.DROM0;
                } else if (LoadAddress >= 0x3FF80000 && LoadAddress <= 0x3FF80000 + 524288) {
                    type = SegmentType.DRAM0;
                } else if (LoadAddress >= 0x3F800000 && LoadAddress <= 0x3F800000 + 4194304) {
                    type = SegmentType.DRAM1;
                } else {
                    type = SegmentType.IRAM;
                }
            }
            default -> type = SegmentType.UNKNOWN;
        }
    }

    public long PhysicalDataOffset() {
        // The data starts 8 bytes after the segment header, this is important when loading this segment mapped to the
        // load address. Because the LoadAddress starts at this offset instead of the physical offset.
        return PhysicalOffset + 8;
    }

    public boolean isWrite() {
        // There are definitely code segments that are writable, but it seems like it is
        // common for the compiler to stick function pointers in the code
        // segments. This means the decompiler will show the pointer being cast to
        // `code *` and called, making it more difficult to read. If the
        // pointers are not writable, then the decompiler will helpfully show a function
        // pointer call as a normal function call.
        return this.type != null &&
               this.type != SegmentType.DROM0 &&
               this.type != SegmentType.DROM1 &&
               this.type != SegmentType.IROM0 &&
               this.type != SegmentType.IROM1 &&
               this.type != SegmentType.EXT_DROM &&
               !this.isCodeSegment();
    }

    public boolean isRead() {
        return this.type != null && this.type != SegmentType.F_DATA;
    }

    public boolean isExecute() {
        return this.isCodeSegment();
    }

    public boolean isVolatile() {
        return this.type != null &&
               (this.type == SegmentType.IRAM ||
                this.type == SegmentType.RTC_RAM ||
                this.type == SegmentType.EXT_IRAM ||
                this.type == SegmentType.IRAM0 ||
                this.type == SegmentType.IRAM1 ||
                this.type == SegmentType.DRAM0 ||
                this.type == SegmentType.DRAM1);
    }

    public boolean isCodeSegment() {
        return this.type != null &&
               (this.type == SegmentType.IF_TXT ||
                this.type == SegmentType.RTC_RAM ||
                this.type == SegmentType.EXT_IRAM ||
                this.type == SegmentType.IRAM ||
                this.type == SegmentType.IRAM0 ||
                this.type == SegmentType.IRAM1 ||
                this.type == SegmentType.IROM0 ||
                this.type == SegmentType.IROM1);
    }

    public boolean isDromSegment() {
        return this.type != null &&
               (this.type == SegmentType.DROM0 ||
                this.type == SegmentType.DROM1 ||
                this.type == SegmentType.EXT_DROM);
    }

    public boolean isDramSegment() {
        return this.type != null &&
               (this.type == SegmentType.DRAM0 ||
                this.type == SegmentType.DRAM1);
    }

    public enum SegmentType {
        RTC_RAM,
        DRAM0,
        DRAM1,
        IRAM,
        IRAM0,
        IRAM1,
        EXT_IRAM,

        DROM0,
        DROM1,
        IROM0,
        IROM1,
        EXT_DROM,

        IF_TXT,
        DF_ROA,
        F_DATA,

        PADDING,
        UNKNOWN
    }
}
