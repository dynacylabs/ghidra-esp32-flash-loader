package esp32_loader.flash;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;

import java.io.IOException;
import java.util.ArrayList;

public class ESP32Flash {
    public ArrayList<ESP32Partition> Partitions = new ArrayList<ESP32Partition>();

    public ESP32Flash(BinaryReader reader, MessageLog log) throws IOException {
        log.appendMsg("Reading Partition Table at 0x8000");

        // Usually the default partition table offset
        reader.setPointerIndex(0x8000);

        /* should be at the partition table now */
        while (reader.peekNextShort() == 0x50AA) {
            var part = new ESP32Partition(reader);

            log.appendMsg("Partition: " + part.Name);

            Partitions.add(part);
        }
    }

    public ESP32Partition GetPartitionByName(String name) {
        for (ESP32Partition partition : Partitions) {
            if (partition.Name.equals(name)) {
                return partition;
            }
        }
        return null;
    }
}
