package esp32_loader.flash;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;

import java.io.IOException;
import java.util.ArrayList;

public class ESP32AppImage {
    public static int MAGIC_WORD = 0xE9;

    public byte SegmentCount;
    public int EntryAddress;
    public boolean HashAppended;
    public ESP32Chip ChipId;

    public ESP32BootloaderInfo BootloaderInfo;
    public ESP32AppInfo AppInfo;

    public ArrayList<ESP32AppSegment> Segments = new ArrayList<ESP32AppSegment>();

    public ESP32AppImage(BinaryReader reader, MessageLog log) throws IOException {
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

        this.ChipId = ESP32Chip.from(chipID);

        for (var x = 0; x < this.SegmentCount; x++) {
            var seg = new ESP32AppSegment(this, reader);

            log.appendMsg("Segment " + x + ": " + seg.type.toString());

            Segments.add(seg);
        }

        var dromSegment = Segments.stream()
                                  .filter(ESP32AppSegment::isDromSegment)
                                  .reduce((seg1, seg2) -> {
                                      if (seg1.LoadAddress > seg2.LoadAddress) {
                                          return seg2;
                                      }
                                      return seg1;
                                  });

        var dramSegment = Segments.stream()
                                  .filter(ESP32AppSegment::isDramSegment)
                                  .reduce((seg1, seg2) -> {
                                      if (seg1.LoadAddress > seg2.LoadAddress) {
                                          return seg2;
                                      }
                                      return seg1;
                                  });

        if (dromSegment.isPresent() && ESP32AppInfo.isAppInfo(dromSegment.get().Data)) {
            this.AppInfo = new ESP32AppInfo(dromSegment.get().Data);

            log.appendMsg("Application information");
            log.appendMsg("=".repeat(20));
            log.appendMsg("Project name: " + this.AppInfo.ProjectName);
            log.appendMsg("App version: " + this.AppInfo.AppVersion);
            log.appendMsg("Compile time: " +
                          this.AppInfo.CompileDate +
                          " " +
                          this.AppInfo.CompileTime);
            log.appendMsg("ELF file SHA256: " + byteArrayToHex(this.AppInfo.ELFSha256));
            log.appendMsg("ESP-IDF: " + this.AppInfo.IDFVersion);
            log.appendMsg("Secure version: " + this.AppInfo.SecureVersion + "\n");

        }

        if (dramSegment.isPresent() &&
            dramSegment.get().Length > 80 &&
            ESP32BootloaderInfo.isBootloaderInfo(dramSegment.get().Data)
        ) {
            this.BootloaderInfo = new ESP32BootloaderInfo(dramSegment.get().Data);

            log.appendMsg("Bootloader information");
            log.appendMsg("=".repeat(20));
            log.appendMsg("Bootloader version: " + this.BootloaderInfo.Version);
            log.appendMsg("ESP-IDF: " + this.BootloaderInfo.IDFVersion);
            log.appendMsg("Compile time: " + this.BootloaderInfo.CompileTime + "\n");
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

    public static boolean isAppImage(BinaryReader reader, long offset) throws IOException {
        return (reader.readByte(offset) & 0xFF) == MAGIC_WORD;
    }

    protected static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
