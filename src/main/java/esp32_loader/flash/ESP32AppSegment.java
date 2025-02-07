package esp32_loader.flash;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class ESP32AppSegment {

	public enum SegmentType {
		DRAM0, DRAM1, IF_TXT, IRAM0, IRAM1, DF_ROA, F_DATA, IRAM, IROM0, DROM0
	}

	public int PhysicalOffset;
	public int LoadAddress;
	public int Length;
	public byte[] Data;

	public SegmentType type;
	public boolean IsEsp32 = false;

	public ESP32AppSegment(ESP32AppImage app, BinaryReader reader, boolean isEsp32S2) throws IOException {
		// TODO Auto-generated constructor stub
		IsEsp32 = isEsp32S2;
		LoadAddress = reader.readNextInt();
		Length = reader.readNextInt();
		Data = reader.readNextByteArray(Length);
		/* fully consume the segment */
		if (isEsp32S2) {
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

		} else {
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
	}

	public boolean isWrite() {
		// There are definitely code segments that are writable, but it seems like it is
		// common for the compiler to stick function pointers in the code
		// segments. This means the decompiler will show the pointer being casted to
		// `code *` and called, making it more difficult to read. If the
		// pointers are not writable, then the decompiler will helpfully show a function
		// pointer call as a normal function call.
		return this.type != null && this.type != SegmentType.DROM0 && this.type != SegmentType.IROM0
				&& !this.isCodeSegment();
	}

	public boolean isRead() {
		return this.type != null && this.type != SegmentType.F_DATA;
	}

	public boolean isExecute() {
		return this.isCodeSegment();
	}

	public boolean isCodeSegment() {
		return this.type != null && (this.type == SegmentType.IF_TXT || this.type == SegmentType.IRAM
				|| this.type == SegmentType.IRAM0 || this.type == SegmentType.IRAM1 || this.type == SegmentType.IROM0);
	}
}
