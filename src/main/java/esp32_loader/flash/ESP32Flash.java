package esp32_loader.flash;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;

public class ESP32Flash {
	public ESP32AppImage SecondaryBootloader;
	public ArrayList<ESP32Partition> Partitions = new ArrayList<ESP32Partition>();

	public ESP32Flash(BinaryReader reader) throws IOException {

		/* first 0x1000 bytes are empty */
		byte[] skipped = reader.readNextByteArray(0x1000);
		var idx1 = reader.getPointerIndex();
		byte[] bootLoader = reader.readNextByteArray(0x7000);

		var idx2 = reader.getPointerIndex();
		/* should be at the partition table now */
		while (reader.peekNextShort() == 0x50AA) {
			var part = new ESP32Partition(reader);
			Partitions.add(part);
		}
	}

	public ESP32Partition GetPartitionByName(String name) {
		for (var x = 0; x < Partitions.size(); x++) {
			if (Partitions.get(x).Name.equals(name)) {
				return Partitions.get(x);
			}
		}
		return null;
	}
}
