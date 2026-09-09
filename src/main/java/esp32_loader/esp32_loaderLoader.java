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
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.Application;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public class esp32_loaderLoader extends AbstractLibrarySupportLoader {
    /** Width of an SVD register in bytes; the per-register {@code <size>} element is not honored. */
    static final int REGISTER_BYTES = 4;

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
    protected void load(Program program, ImporterSettings settings) throws IOException, CancelledException {
        ByteProvider provider = settings.provider();
        LoadSpec loadSpec = settings.loadSpec();
        List<Option> options = settings.options();
        TaskMonitor monitor = settings.monitor();
        MessageLog log = settings.log();
        FlatProgramAPI api = new FlatProgramAPI(program);

        if (entryAppImage == null) {
            throw new RuntimeException("No ESP32 App Image found at the beginning of the file.");
        }

        // Check if ROM ELF loading is enabled
        boolean loadRomElf = true;
        for (Option option : options) {
            if (option.getName().equals("Load ROM ELF")) {
                loadRomElf = (Boolean) option.getValue();
                break;
            }
        }

        if (loadRomElf) {
            log.appendMsg("Loading ROM ELF Image from extension storage");
            try {
                processELF(program, entryAppImage.ChipId, loadSpec, monitor, log);
            } catch (Exception ex) {
                String exceptionTxt = ex.toString();
                System.out.println(exceptionTxt);
            }
        } else {
            log.appendMsg("ROM ELF loading disabled by option");
        }

        if (entryAppImage.BootloaderInfo != null) {
            log.appendMsg("Loading Bootloader ESP32 App Image segments");
            processAppImage(program, entryAppImage, api, provider, monitor, log, "bootloader");

            /*
             * they probably gave us a firmware file with a bootloader, lets load that and
             * get the partition
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

        // Check if SVD loading is enabled
        boolean loadSvd = true;
        for (Option option : options) {
            if (option.getName().equals("Load SVD")) {
                loadSvd = (Boolean) option.getValue();
                break;
            }
        }

        if (loadSvd) {
            try {
                log.appendMsg("Loading SVD file for peripherals");
                /* Create Peripheral Device Memory Blocks */
                processSVD(program, api, entryAppImage.ChipId, log);
            } catch (Exception e) {
                log.appendException(e);
            }
        } else {
            log.appendMsg("SVD loading disabled by option");
        }
    }

    private void processAppImage(Program program, ESP32AppImage imageToLoad, FlatProgramAPI api, ByteProvider provider,
            TaskMonitor monitor, MessageLog log, String imageName) {
        try {
            for (var x = 0; x < imageToLoad.SegmentCount; x++) {
                var curSeg = imageToLoad.Segments.get(x);

                try {
                    Address startSegAddr = api.toAddr(curSeg.LoadAddress);
                    Address endSegAddr = startSegAddr.add(curSeg.Length - 1);

                    FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program,
                            provider,
                            curSeg.PhysicalDataOffset(),
                            curSeg.Length,
                            monitor);

                    // this checks if the ENTIRE block already exists, there is a chance that the
                    // previous block only collides by a fraction
                    if (!program.getMemory().contains(startSegAddr, endSegAddr)) {
                        var blockName = imageName +
                                "_" +
                                curSeg.type.name() +
                                "_" +
                                Integer.toHexString(curSeg.LoadAddress);

                        // this try / catch will remove uninitialized memory if it collides with the
                        // block being loaded
                        try {
                            var memBlock = program.getMemory().createInitializedBlock(blockName,
                                    startSegAddr,
                                    fileBytes, 0x00, curSeg.Length, false);
                            memBlock.setPermissions(curSeg.isRead(), curSeg.isWrite(), curSeg.isExecute());
                            memBlock.setVolatile(curSeg.isVolatile());
                            memBlock.setSourceName("ESP32 Loader");

                        } catch (ghidra.program.model.mem.MemoryConflictException memException) {
                            log.appendMsg("MemoryConflictExcetion while loading segment index " + x);
                            log.appendMsg("Searching for colliding blocks...");

                            // search for the colliding block
                            for (MemoryBlock block : program.getMemory().getBlocks()) {
                                Address blockStartAddr = block.getStart();
                                Address blockEndAddr = block.getEnd();

                                if (blockStartAddr.compareTo(endSegAddr) <= 0
                                        && blockEndAddr.compareTo(startSegAddr) >= 0) {

                                    log.appendMsg(String.format("Found colliding block %s at start: 0x%X, end: 0x%X",
                                            block.getName(), blockStartAddr.getOffset(), blockEndAddr.getOffset()));

                                    if (!block.isInitialized()) {
                                        log.appendMsg("Colliding block is uninitialized, trying to remove it");

                                        // if block is completely inside, remove the block completely.
                                        if ((blockStartAddr.compareTo(startSegAddr) >= 0)
                                                && (blockEndAddr.compareTo(endSegAddr) <= 0)) {

                                            program.getMemory().removeBlock(block, monitor);
                                            log.appendMsg("Removed overlapped area");
                                        }

                                        // if block expands from the lower end, remove higher half.
                                        else if ((blockStartAddr.compareTo(startSegAddr) < 0)
                                                && (blockEndAddr.compareTo(startSegAddr) >= 0)
                                                && (blockEndAddr.compareTo(endSegAddr) <= 0)) {

                                            program.getMemory().split(block, startSegAddr);
                                            program.getMemory().removeBlock(program.getMemory().getBlock(startSegAddr),
                                                    monitor);
                                            log.appendMsg("Removed overlapped area");

                                        }

                                        // if block expand from the higher end, remove lower half.
                                        else if ((blockStartAddr.compareTo(startSegAddr) >= 0)
                                                && (blockStartAddr.compareTo(endSegAddr) <= 0)
                                                && (blockEndAddr.compareTo(endSegAddr) > 0)) {
                                            program.getMemory().split(block, endSegAddr.add(1));
                                            program.getMemory().removeBlock(program.getMemory().getBlock(endSegAddr),
                                                    monitor);
                                            log.appendMsg("Removed overlapped area");

                                        }

                                        // if block expands from the lower and higher end, make a hole and remove it.
                                        else if ((blockStartAddr.compareTo(startSegAddr) < 0)
                                                && (blockEndAddr.compareTo(endSegAddr) > 0)) {
                                            program.getMemory().split(block, startSegAddr);
                                            program.getMemory().split(program.getMemory().getBlock(startSegAddr),
                                                    endSegAddr.add(1));
                                            program.getMemory().removeBlock(program.getMemory().getBlock(endSegAddr),
                                                    monitor);
                                            log.appendMsg("Removed overlapped area");

                                        } else {
                                            log.appendMsg("This condition is imposible, something is fucked up");
                                        }

                                    } else {
                                        log.appendMsg("The colliding block is initialized, NOT touching it");
                                    }
                                }
                            }
                            log.appendMsg("Trying to create segment again...");
                            var memBlock = program.getMemory().createInitializedBlock(blockName,
                                    startSegAddr,
                                    fileBytes, 0x00, curSeg.Length, false);
                            memBlock.setPermissions(curSeg.isRead(), curSeg.isWrite(), curSeg.isExecute());
                            memBlock.setVolatile(curSeg.isVolatile());
                            memBlock.setSourceName("ESP32 Loader");
                        }

                    } else {
                        /* memory block already exists... */
                        MemoryBlock existingBlock = program.getMemory().getBlock(startSegAddr);
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
                                existingBlock.putBytes(startSegAddr, curSeg.Data);
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
                } catch (Exception segEx) {
                    log.appendMsg(
                            "Failed to load segment index " + x + " at 0x" + Integer.toHexString(curSeg.LoadAddress));
                    log.appendException(segEx);
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

        List<Option> elfOpts = loader.getDefaultOptions(bap, loadSpec, null, true, false);
        ImporterSettings elfSettings = new ImporterSettings(bap, elfFileName, null, null, false, loadSpec, elfOpts, null, log, monitor);
        loader.load(program, elfSettings);
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

        // Index peripherals by name so derivedFrom references can be resolved
        Map<String, Element> peripheralsByName = new HashMap<>();
        for (var x = 0; x < peripherals.getLength(); x++) {
            Element peripheral = (Element) peripherals.item(x);
            String name = childText(peripheral, "name");
            if (name != null) {
                peripheralsByName.put(name, peripheral);
            }
        }

        for (var x = 0; x < peripherals.getLength(); x++) {
            try {
                processPeripheral(program, api, (Element) peripherals.item(x), peripheralsByName, log);
            } catch (Exception e) {
                log.appendException(e);
            }
        }
    }

    private void processPeripheral(Program program, FlatProgramAPI api, Element peripheral,
            Map<String, Element> peripheralsByName, MessageLog log)
            throws DuplicateNameException, InvalidInputException, LockException,
            MemoryConflictException, AddressOverflowException {
        // The name is never inherited; a derived peripheral must declare its own
        String peripheralName = childText(peripheral, "name");
        if (peripheralName == null) {
            log.appendMsg("Skipping peripheral without a name");
            return;
        }

        // SVD inheritance is per element, so the baseAddress, the addressBlock and the
        // registers are each taken from the nearest peripheral in the derivedFrom
        // chain that has them
        Element baseAddress = resolveRequired(peripheral, peripheralName, "baseAddress", peripheralsByName, log);
        if (baseAddress == null) {
            return;
        }
        int baseAddr = Integer.decode(baseAddress.getTextContent());

        Element addressBlock = resolveRequired(peripheral, peripheralName, "addressBlock", peripheralsByName, log);
        if (addressBlock == null) {
            return;
        }

        NodeList registers = resolveInherited(peripheral, "register", peripheralsByName, log);
        List<RegisterField> fields = registers == null ? List.of() : parseRegisters(registers, log);

        int size = peripheralExtent(addressBlock, fields);

        registerPeripheralBlock(program, api, baseAddr, baseAddr + size - 1, peripheralName);

        StructureDataType struct = new StructureDataType(peripheralName, size);

        for (RegisterField field : fields) {
            try {
                struct.replaceAtOffset(field.offset(), UnsignedLongDataType.dataType, REGISTER_BYTES, field.name(), "");
            } catch (Exception e) {
                // peripheralExtent sizes the struct past every register, so this only
                // guards malformed SVDs (e.g. a negative addressOffset)
                log.appendException(e);
            }
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
        try {
            listing.createData(addr, struct);
        } catch (CodeUnitInsertionException e) {
            // Overlapping peripherals (e.g. ESP32-S3 INTERRUPT_CORE0/1 share a base
            // address) can only have one struct applied; keep the label regardless
            log.appendMsg("Could not apply struct for " + peripheralName + " at " + addr + ": " + e.getMessage());
        }
        symbolTable.createLabel(addr, peripheralName, namespace, SourceType.USER_DEFINED);
    }

    /** A register's name and byte offset from the peripheral base address. */
    record RegisterField(String name, int offset) {
    }

    /**
     * Parses the name and addressOffset of each register element, logging and
     * skipping malformed entries so one bad register does not drop the rest.
     */
    static List<RegisterField> parseRegisters(NodeList registers, MessageLog log) {
        List<RegisterField> fields = new ArrayList<>();
        for (var x = 0; x < registers.getLength(); x++) {
            Element register = (Element) registers.item(x);
            try {
                String name = childText(register, "name");
                if (name == null) {
                    log.appendMsg("Skipping register without a name");
                    continue;
                }
                fields.add(new RegisterField(name, decodeChildInt(register, "addressOffset")));
            } catch (Exception e) {
                log.appendException(e);
            }
        }
        return fields;
    }

    /**
     * Returns the text of the first direct child element with the given tag, or null if
     * absent. Deliberately not a descendant search: a peripheral missing its own
     * {@code <name>} must not borrow one from a nested register.
     */
    static String childText(Element element, String tagName) {
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() == Node.ELEMENT_NODE && child.getNodeName().equals(tagName)) {
                return child.getTextContent();
            }
        }
        return null;
    }

    /** Decodes the integer content of the first child element with the given tag. */
    static int decodeChildInt(Element element, String tagName) {
        String text = childText(element, tagName);
        if (text == null) {
            throw new IllegalArgumentException("Missing " + tagName + " element");
        }
        return Integer.decode(text);
    }

    /** As above, but returns defaultValue when the element has no such child. */
    static int decodeChildInt(Element element, String tagName, int defaultValue) {
        String text = childText(element, tagName);
        return text == null ? defaultValue : Integer.decode(text);
    }

    /**
     * Returns the number of bytes the peripheral occupies from its base address. The
     * addressBlock offset is relative to the base address, so the block reaches to
     * offset + size, and some SVDs declare a block smaller than the span of the
     * registers, whose addressOffset is relative to the base address as well.
     */
    static int peripheralExtent(Element addressBlock, List<RegisterField> fields) {
        int extent = decodeChildInt(addressBlock, "size") + decodeChildInt(addressBlock, "offset", 0);

        for (RegisterField field : fields) {
            extent = Math.max(extent, field.offset() + REGISTER_BYTES);
        }
        return extent;
    }

    /**
     * Walks the derivedFrom chain from the given peripheral and returns the requested
     * elements from the nearest peripheral that declares them, or null if none does.
     * Elements already visited terminate the walk so that a cycle cannot hang the import.
     * The descendant search is intentional here: registers live under a nested
     * {@code <registers>} element, not as direct children of the peripheral.
     */
    static NodeList resolveInherited(Element peripheral, String tagName, Map<String, Element> peripheralsByName,
            MessageLog log) {
        // DOM elements do not override equals, so a HashSet tracks visits by identity
        Set<Element> visited = new HashSet<>();
        Element source = peripheral;
        while (source != null) {
            if (!visited.add(source)) {
                log.appendMsg("Cyclic derivedFrom chain at peripheral "
                        + Objects.requireNonNullElse(childText(source, "name"), "<unnamed>")
                        + " while resolving " + tagName);
                return null;
            }
            NodeList matches = source.getElementsByTagName(tagName);
            if (matches.getLength() > 0) {
                return matches;
            }
            String derivedFrom = source.getAttribute("derivedFrom");
            if (derivedFrom.isEmpty()) {
                return null;
            }
            source = peripheralsByName.get(derivedFrom);
        }
        return null;
    }

    /**
     * The first element with the given tag resolved through the derivedFrom chain, or
     * null — with the skip logged — when no peripheral in the chain declares it.
     */
    static Element resolveRequired(Element peripheral, String peripheralName, String tagName,
            Map<String, Element> peripheralsByName, MessageLog log) {
        NodeList matches = resolveInherited(peripheral, tagName, peripheralsByName, log);
        if (matches == null) {
            log.appendMsg("Skipping peripheral " + peripheralName + ": no " + tagName);
            return null;
        }
        return (Element) matches.item(0);
    }

    private void registerPeripheralBlock(Program program, FlatProgramAPI api, int startAddr, int endAddr, String name)
            throws LockException, MemoryConflictException, AddressOverflowException {
        var memory = program.getMemory();
        // Overlapping peripherals or already-loaded segments may cover part of this
        // range; only create blocks for the parts that are still unmapped
        var uncovered = new AddressSet(api.toAddr(startAddr), api.toAddr(endAddr)).subtract(memory);
        var fragment = 0;
        for (var range : uncovered) {
            var block = memory.createUninitializedBlock(fragment == 0 ? name : name + "_" + fragment,
                    range.getMinAddress(), range.getLength(), false);
            block.setRead(true);
            block.setWrite(true);
            block.setVolatile(true);
            block.setSourceName("SVD Loader");
            fragment++;
        }
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject, boolean isLoadIntoProgram, boolean mirrorFsLayout) {
        List<Option> list = new ArrayList<>();

        if (parsedFlash != null) {
            list.add(new PartitionOption(parsedFlash));
        }
        list.add(new Option("Load ROM ELF", true));
        list.add(new Option("Load SVD", true));

        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
        // Find the partition option to validate
        for (Option option : options) {
            if (option.getName().equals("App Partition")) {
                if (option.getValue() == null || option.getValue().equals("")) {
                    return "App partition not found in image.";
                }
                break;
            }
        }

        return null;
    }
}
