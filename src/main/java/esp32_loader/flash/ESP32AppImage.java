package esp32_loader.flash;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;

public class ESP32AppImage {
	public byte SegmentCount;
	public int EntryAddress;
	public boolean HashAppended;
	public boolean IsEsp32S2;

	public ArrayList<ESP32AppSegment> Segments = new ArrayList<ESP32AppSegment>();

	public ESP32AppImage(BinaryReader reader) throws IOException {
		var magic = reader.readNextByte();
		this.SegmentCount = reader.readNextByte();
		var spiByte = reader.readNextByte(); // SPI Byte
		var spiSize = reader.readNextByte(); // SPI Size
		this.EntryAddress = reader.readNextInt();

		var wpPin = reader.readNextByte(); // WP Pin
		var spiPinDrv = reader.readNextByteArray(3); // SPIPinDrv
		var chipID = reader.readNextShort(); // Chip ID
		var minChipRev = reader.readNextByte(); // MinChipRev
		var reserved = reader.readNextByteArray(8); // Reserved
		this.HashAppended = (reader.readNextByte() == 0x01);
		IsEsp32S2 = false;
		if (chipID == 2) {
			IsEsp32S2 = true;
			System.out.println("ESP32S2 Image found!");
		}

		for (var x = 0; x < this.SegmentCount; x++) {
			var seg = new ESP32AppSegment(this, reader, IsEsp32S2);
			Segments.add(seg);
		}

		/* get to 16 byte boundary */
		while ((reader.getPointerIndex() + 1) % 0x10 != 0) {
			reader.readNextByte();
		}

		reader.readNextByte(); // checksum byte
		if (HashAppended) {
			reader.readNextByteArray(0x20); // hash
		}
	}
}
