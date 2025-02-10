package esp32_loader.flash;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public class ESP32BootloaderInfo {
    public static int ESP32_BOOTLOADER_DESC_MAGIC = 0x50;

    public int Version;
    public String IDFVersion;
    public String CompileTime;

    public ESP32BootloaderInfo(byte[] data) {
        if (data.length < 80) {
            throw new IllegalArgumentException("Invalid bootloader description size, too small (min 80): " +
                                               data.length);
        }

        ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        byte magic_byte = buffer.get();

        if ((magic_byte & 0xFF) != ESP32_BOOTLOADER_DESC_MAGIC) {
            throw new IllegalArgumentException("Invalid bootloader description magic byte: " + magic_byte);
        }

        byte[] reserv1 = new byte[3];
        buffer.get(reserv1);
        int version = buffer.getInt();
        byte[] idf_ver = new byte[32];
        buffer.get(idf_ver);
        byte[] date_time = new byte[24];
        buffer.get(date_time);
        byte[] reserved2 = new byte[16];
        buffer.get(reserved2);

        this.Version = version;
        this.IDFVersion = new String(idf_ver, StandardCharsets.UTF_8);
        this.CompileTime = new String(date_time, StandardCharsets.UTF_8);
    }

    public static boolean isBootloaderInfo(byte[] data) {
        return (data[0] & 0xFF) == ESP32_BOOTLOADER_DESC_MAGIC;
    }
}
