package esp32_loader.datatype;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.Writeable;
import ghidra.program.model.data.*;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.io.RandomAccessFile;

public class EspAppDesc implements StructConverter, Comparable<EspAppDesc>, Writeable {
    long magic_word;
    long secure_version;
    int[] reserv1;
    char[] version;
    char[] project_name;
    char[] time;
    char[] date;
    char[] idf_ver;
    byte[] app_elf_sha256;
    long[] reserv2;

    public EspAppDesc(BinaryReader reader) throws IOException {
        magic_word = reader.readNextUnsignedInt();
        secure_version = reader.readNextUnsignedInt();
    }

    @Override
    public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
        // TODO Auto-generated method stub
    }

    @Override
    public int compareTo(EspAppDesc o) {
        return 0;
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType(new CategoryPath("/ESP32"), "esp_app_desc_t", 0);
        struct.add(DWordDataType.dataType, "magic_word", null);
        struct.add(DWordDataType.dataType, "secure_version", null);
        struct.add(new ArrayDataType(DWordDataType.dataType, 2, 0), "reserv1", null);
        struct.add(new ArrayDataType(CharDataType.dataType, 32, 0), "version", null);
        struct.add(new ArrayDataType(CharDataType.dataType, 32, 0), "project_name", null);
        struct.add(new ArrayDataType(CharDataType.dataType, 16, 0), "time", null);
        struct.add(new ArrayDataType(CharDataType.dataType, 16, 0), "date", null);
        struct.add(new ArrayDataType(CharDataType.dataType, 32, 0), "idf_ver", null);
        struct.add(new ArrayDataType(ByteDataType.dataType, 32, 0), "app_elf_sha256", null);
        struct.add(new ArrayDataType(DWordDataType.dataType, 20, 0), "reserv2", null);
        return struct;
    }
}
