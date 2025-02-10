package esp32_loader.flash;

import ghidra.program.model.lang.LanguageCompilerSpecPair;

// Chip IDs are defined here https://github.com/espressif/esp-idf/blob/46acfdce969f03c02b001fe4d24fa9e98f6adc5e/components/bootloader_support/include/esp_app_format.h#L19
public enum ESP32Chip {
    ESP32(0x0000),      /*!< chip ID: ESP32 */
    ESP32S2(0x0002),    /*!< chip ID: ESP32-S2 */
    ESP32C3(0x0005),     /*!< chip ID: ESP32-C3 */
    ESP32S3(0x0009),     /*!< chip ID: ESP32-S3 */
    ESP32C2(0x000C),     /*!< chip ID: ESP32-C2 */
    ESP32C6(0x000D),     /*!< chip ID: ESP32-C6 */
    ESP32H2(0x0010),     /*!< chip ID: ESP32-H2 */
    ESP32P4(0x0012),     /*!< chip ID: ESP32-P4 */
    ESP32C5(0x0017),     /*!< chip ID: ESP32-C5 */
    INVALID(0xFFFF);      /*!< Invalid chip ID */

    private final int id;

    ESP32Chip(int id) {
        this.id = id;
    }

    public static ESP32Chip from(int id) {
        for (ESP32Chip chipId : ESP32Chip.values()) {
            if (chipId.getId() == id) {
                return chipId;
            }
        }

        return INVALID;
    }

    public int getId() {
        return id;
    }

    public LanguageCompilerSpecPair getLoadSpec() {
        // Taken from the SVD files
        return switch (this) {
            case ESP32, ESP32S3, ESP32S2 -> new LanguageCompilerSpecPair("Xtensa:LE:32:default", "default");
            case ESP32C3, ESP32C2 -> new LanguageCompilerSpecPair("RISCV:LE:32:RV32IMC", "gcc");
            // C6 has IMAC extensions, but we don't have a language spec for that in Ghidra
            case ESP32C6 -> new LanguageCompilerSpecPair("RISCV:LE:32:RV32IMC", "gcc");
            // H2 has IMAC extensions, but we don't have a language spec for that in Ghidra
            case ESP32H2 -> new LanguageCompilerSpecPair("RISCV:LE:32:RV32IMC", "gcc");
            // P4 has IMAFC extensions, but we don't have a language spec for that in Ghidra
            case ESP32P4 -> new LanguageCompilerSpecPair("RISCV:LE:32:RV32IMC", "gcc");
            // We do not have an SVD file currently but assume this is the same as other C models
            case ESP32C5 -> new LanguageCompilerSpecPair("RISCV:LE:32:RV32IMC", "gcc");
            default -> null;
        };
    }
}