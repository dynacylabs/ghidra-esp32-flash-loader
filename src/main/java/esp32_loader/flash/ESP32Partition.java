package esp32_loader.flash;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;

import java.io.IOException;

public class ESP32Partition {
    public String Name;
    public byte Type;
    public byte SubType;
    public int Offset;
    public int Length;
    public byte[] Data;

    public ESP32Partition(BinaryReader reader) throws IOException {
        reader.readNextShort(); // magic
        Type = reader.readNextByte();
        SubType = reader.readNextByte();
        Offset = reader.readNextInt();
        Length = reader.readNextInt();
        Name = reader.readNextAsciiString(20);
        Data = reader.readByteArray(Offset, Length);
    }

    public ESP32AppImage ParseAppImage(MessageLog log) throws Exception {
        if (Byte.toUnsignedInt(Data[0]) != 0xE9) {
            /* E9 is the magic for an app image, this doesn't have it... */
            throw new Exception("Selected Partition is not a valid App Image");
        }

        ByteArrayProvider dataProv = new ByteArrayProvider(Data);

        var appImage = new ESP32AppImage(new BinaryReader(dataProv, true), log);

        // Correct the physical offsets of the segments based on the partition offset
        for (var seg : appImage.Segments) {
            seg.PhysicalOffset += Offset;
        }

        return appImage;
    }

}
