package esp32_loader.flash;

import java.util.Arrays;

public class ESP32AppInfo {
    public static int ESP32_APP_DESC_MAGIC = 0xABCD5432;

    public String ProjectName;
    public String AppVersion;
    public String CompileTime;
    public String CompileDate;
    public byte[] ELFSha256;
    public String IDFVersion;
    public int SecureVersion;

    public ESP32AppInfo(byte[] data) {
        if (data.length < 256) {
            throw new IllegalArgumentException("Invalid app description size, too small (min 256): " + data.length);
        }

        if (!isAppInfo(data)) {
            throw new IllegalArgumentException("Invalid app description magic bytes");
        }

        this.SecureVersion = (data[4] & 0xFF) |
                             ((data[5] & 0xFF) << 8) |
                             ((data[6] & 0xFF) << 16) |
                             ((data[7] & 0xFF) << 24);

        // Read reserv1 (8 bytes)
        byte[] reserv1 = Arrays.copyOfRange(data, 8, 16);

        // Read strings (trimmed)
        this.AppVersion = new String(data, 16, 32).trim();
        this.ProjectName = new String(data, 48, 32).trim();
        this.CompileTime = new String(data, 80, 16).trim();
        this.CompileDate = new String(data, 96, 16).trim();
        this.IDFVersion = new String(data, 112, 32).trim();

        // Read app_elf_sha256 (32 bytes)
        this.ELFSha256 = Arrays.copyOfRange(data, 144, 176);

        // Read reserv2 (80 bytes)
        byte[] reserv2 = Arrays.copyOfRange(data, 176, 256);
    }

    public static boolean isAppInfo(byte[] data) {
        int magic = (data[0] & 0xFF) | ((data[1] & 0xFF) << 8) | ((data[2] & 0xFF) << 16) | ((data[3] & 0xFF) << 24);
        return magic == ESP32_APP_DESC_MAGIC;
    }
}
