/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package esp32_loader;

import esp32_loader.flash.ESP32AppImage;
import esp32_loader.flash.ESP32Chip;
import esp32_loader.flash.ESP32Flash;
import esp32_loader.flash.ESP32Partition;
import generic.jar.ResourceFile;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.Application;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public class esp32_loaderLoader extends AbstractLibrarySupportLoader {
    ESP32Flash parsedFlash = null;
    ESP32AppImage entryAppImage = null;

    @Override
    public String getName() {
        return "ESP32 Flash Image";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // Examine the bytes in 'provider' to determine if this loader can load
        // it. If it
        // can load it, return the appropriate load specifications.
        BinaryReader reader = new BinaryReader(provider, true);

        boolean isAppImage = ESP32AppImage.isAppImage(reader, 0x00);

        if (!isAppImage) {
            System.out.println("Did not find an app image at the beginning of the file. Cannot provide anything.");

            return loadSpecs;
        }

        MessageLog log = new MessageLog();
        entryAppImage = new ESP32AppImage(reader, log);
        System.out.print(log);

        if (entryAppImage.BootloaderInfo != null) {
            System.out.println("Found a bootloader in the image, we need to find the app image.");
            // we have a bootloader, we need to load the entire flash image
            reader.setPointerIndex(0);

            MessageLog flashLog = new MessageLog();
            parsedFlash = new ESP32Flash(reader, flashLog);
            System.out.print(flashLog);
        }

        loadSpecs.add(new LoadSpec(this, 0, entryAppImage.ChipId.getLoadSpec(), true));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log) {
        FlatProgramAPI api = new FlatProgramAPI(program);

        if (entryAppImage == null) {
            throw new RuntimeException("No ESP32 App Image found at the beginning of the file.");
        }

        log.appendMsg("Loading ROM ELF Image from extension storage");
        try {
            processELF(program, entryAppImage.ChipId, loadSpec, monitor, log);
        } catch (Exception ex) {
            String exceptionTxt = ex.toString();
            System.out.println(exceptionTxt);
        }

        if (entryAppImage.BootloaderInfo != null) {
            log.appendMsg("Loading Bootloader ESP32 App Image segments");
            processAppImage(program, entryAppImage, api, provider, monitor, log, "bootloader");

            /*
             * they probably gave us a firmware file with a bootloader, lets load that and get the partition
             * they selected
             */
            var partOpt = (String) (options.getFirst().getValue());
            ESP32Partition part = parsedFlash.GetPartitionByName(partOpt);

            try {
                var imageToLoad = part.ParseAppImage(log);

                log.appendMsg("Loading App Image from partition: " + part.Name);
                processAppImage(program, imageToLoad, api, provider, monitor, log, "app");
            } catch (Exception ex) {
                log.appendException(ex);
            }
        } else {
            log.appendMsg("Loading ESP32 App Image segments");
            processAppImage(program, entryAppImage, api, provider, monitor, log, "app");
        }

        try {
            log.appendMsg("Loading SVD file for peripherals");
            /* Create Peripheral Device Memory Blocks */
            processSVD(program, api, entryAppImage.ChipId, log);
        } catch (Exception e) {
            log.appendException(e);
        }
    }

    private void processAppImage(Program program, ESP32AppImage imageToLoad, FlatProgramAPI api, ByteProvider provider, TaskMonitor monitor, MessageLog log, String imageName) {
        try {
            AddressSetPropertyMap codeProp = program.getAddressSetPropertyMap("CodeMap");
            if (codeProp == null) {
                codeProp = program.createAddressSetPropertyMap("CodeMap");
            }

            for (var x = 0; x < imageToLoad.SegmentCount; x++) {
                var curSeg = imageToLoad.Segments.get(x);

                FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program,
                                                                       provider,
                                                                       curSeg.PhysicalDataOffset(),
                                                                       curSeg.Length,
                                                                       monitor);

                if (!program.getMemory().contains(api.toAddr(curSeg.LoadAddress),
                                                  api.toAddr(curSeg.LoadAddress + curSeg.Length))
                ) {
                    var blockName = imageName +
                                    "_" +
                                    curSeg.type.name() +
                                    "_" +
                                    Integer.toHexString(curSeg.LoadAddress);
                    var memBlock = program.getMemory().createInitializedBlock(blockName, api.toAddr(curSeg.LoadAddress),
                                                                              fileBytes, 0x00, curSeg.Length, false);
                    memBlock.setPermissions(curSeg.isRead(), curSeg.isWrite(), curSeg.isExecute());
                    memBlock.setVolatile(curSeg.isVolatile());
                    memBlock.setSourceName("ESP32 Loader");

                } else {
                    /* memory block already exists... */
                    MemoryBlock existingBlock = program.getMemory().getBlock(api.toAddr(curSeg.LoadAddress));
                    if (existingBlock != null) {
                        existingBlock.setName(imageName +
                                              "_" +
                                              curSeg.type.name() +
                                              "_" +
                                              Integer.toHexString(curSeg.LoadAddress));

                        if (!existingBlock.isInitialized()) {
                            program.getMemory().convertToInitialized(existingBlock, (byte) 0x0);
                        }

                        try {
                            existingBlock.putBytes(api.toAddr(curSeg.LoadAddress), curSeg.Data);
                        } catch (Exception ex) {
                            log.appendException(ex);
                        }

                        existingBlock.setSourceName(existingBlock.getSourceName() + " + ESP32 Loader");
                    } else {
                        /*
                         * whoa, there be dragons here, the block exists but doesn't contain our start
                         * address... what?
                         */
                    }
                }

                /* Mark Instruction blocks as code */
                if (curSeg.isCodeSegment()) {
                    codeProp.add(api.toAddr(curSeg.LoadAddress), api.toAddr(curSeg.LoadAddress + curSeg.Length));
                }

            }

            /* set the entry point */
            program.getSymbolTable().addExternalEntryPoint(api.toAddr(imageToLoad.EntryAddress));

        } catch (Exception e) {
            log.appendException(e);
        }
    }

    private void processELF(Program program, ESP32Chip chipId, LoadSpec loadSpec, TaskMonitor monitor, MessageLog log)
            throws Exception {
        List<ResourceFile> elfFileList = Application.findFilesByExtensionInMyModule("elf");

        if (elfFileList.isEmpty()) {
            return;
        }

        String elfFileName = chipId.name().toLowerCase() + "_rom.elf";

        Optional<ResourceFile> elfFile = elfFileList.stream().filter(f -> f.getName().equals(elfFileName)).findFirst();

        if (elfFile.isEmpty()) {
            return;
        }

        byte[] elfData = Files.readAllBytes(Paths.get(elfFile.get().getAbsolutePath()));
        ByteArrayProvider bap = new ByteArrayProvider(elfFileName, elfData);
        ElfLoader loader = new ElfLoader();

        List<Option> elfOpts = loader.getDefaultOptions(bap, loadSpec, null, true);
        loader.load(bap, loadSpec, elfOpts, program, monitor, log);
    }

    protected void processSVD(Program program, FlatProgramAPI api, ESP32Chip chipId, MessageLog log) throws Exception {
        List<ResourceFile> svdFileList = Application.findFilesByExtensionInMyModule("svd");

        if (svdFileList.isEmpty()) {
            return;
        }

        // Search for the SVD file that matches the chip name
        Optional<ResourceFile> svdFile = svdFileList.stream()
                                                    .filter(f -> f.getName()
                                                                  .equals(chipId.name().toLowerCase() + ".svd"))
                                                    .findFirst();

        if (svdFile.isEmpty()) {
            return;
        }

        /* grab the first svd file ... */
        String svdFilePath = svdFile.get().getAbsolutePath();

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();

        Document doc = builder.parse(svdFilePath);

        Element root = doc.getDocumentElement();

        NodeList peripherals = root.getElementsByTagName("peripheral");

        for (var x = 0; x < peripherals.getLength(); x++) {
            processPeripheral(program, api, (Element) peripherals.item(x), log);
        }
    }

    private void processPeripheral(Program program, FlatProgramAPI api, Element peripheral, MessageLog log)
            throws DuplicateNameException, InvalidInputException, CodeUnitInsertionException, LockException,
            MemoryConflictException, AddressOverflowException {
        String baseAddrString = ((Element) (peripheral.getElementsByTagName("baseAddress").item(0))).getTextContent();
        int baseAddr = Integer.decode(baseAddrString);

        String peripheralName = ((Element) (peripheral.getElementsByTagName("name").item(0))).getTextContent();
        Element addressBlock = (Element) peripheral.getElementsByTagName("addressBlock").item(0);
        int size = Integer.decode(addressBlock.getElementsByTagName("size").item(0).getTextContent());

        registerPeripheralBlock(program, api, baseAddr, baseAddr + size - 1, peripheralName);

        StructureDataType struct = new StructureDataType(peripheralName, size);

        NodeList registers = peripheral.getElementsByTagName("register");

        try {
            for (var x = 0; x < registers.getLength(); x++) {
                Element register = (Element) registers.item(x);
                String registerName = register.getElementsByTagName("name").item(0).getTextContent();
                String offsetString = register.getElementsByTagName("addressOffset")
                                              .item(0).getTextContent();
                int offsetValue = Integer.decode(offsetString);
                struct.replaceAtOffset(offsetValue, new UnsignedLongDataType(), 4, registerName, "");

            }
        } catch (Exception e) {
            log.appendException(e);
        }

        var dtm = program.getDataTypeManager();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var listing = program.getListing();
        var symbolTable = program.getSymbolTable();
        var namespace = symbolTable.getNamespace("Peripherals", null);
        if (namespace == null) {
            namespace = program.getSymbolTable().createNameSpace(null, "Peripherals", SourceType.ANALYSIS);
        }

        var addr = space.getAddress(baseAddr);
        dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
        listing.createData(addr, struct);
        symbolTable.createLabel(addr, peripheralName, namespace, SourceType.USER_DEFINED);
    }

    private void registerPeripheralBlock(Program program, FlatProgramAPI api, int startAddr, int endAddr, String name)
            throws LockException, MemoryConflictException, AddressOverflowException {
        var block = program.getMemory()
                           .createUninitializedBlock(name, api.toAddr(startAddr), endAddr - startAddr + 1, false);
        block.setRead(true);
        block.setWrite(true);
        block.setVolatile(true);
        block.setSourceName("SVD Loader");
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject, boolean isLoadIntoProgram) {
        List<Option> list = new ArrayList<>();

        if (parsedFlash != null) {
            list.add(new PartitionOption(parsedFlash));
        }

        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
        if (options.getFirst().getValue() == null || options.getFirst().getValue().equals("")) {
            return "App partition not found in image.";
        }

        return null;
    }
}
