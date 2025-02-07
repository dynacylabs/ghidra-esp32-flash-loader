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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

import esp32_loader.flash.ESP32Flash;
import esp32_loader.flash.ESP32Partition;
import generic.jar.ResourceFile;
import esp32_loader.flash.ESP32AppImage;
import esp32_loader.flash.ESP32AppSegment.SegmentType;
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
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
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
import org.w3c.dom.*;
import javax.xml.parsers.*;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class esp32_loaderLoader extends AbstractLibrarySupportLoader {
	ESP32Flash parsedFlash = null;
	ESP32AppImage parsedAppImage = null;

	@Override
	public String getName() {

		// TODO: Name the loader. This name must match the name of the loader in the
		// .opinion
		// files.
		return "ESP32 Flash Image";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// TODO: Examine the bytes in 'provider' to determine if this loader can load
		// it. If it
		// can load it, return the appropriate load specifications.
		BinaryReader reader = new BinaryReader(provider, true);

		/* 2nd stage bootloader is at 0x1000, should start with an 0xE9 byte */
		if (reader.length() > 0x1000) {
			var magic = reader.readByte(0x1000);

			if ((magic & 0xFF) == 0xE9) {
				try {
					/* parse the flash... */
					parsedFlash = new ESP32Flash(reader);
					loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(
							new LanguageID("Xtensa:LE:32:default"), new CompilerSpecID("default")), true));
				} catch (Exception ex) {
				}
			} else {
				/* maybe they fed us an app image directly */
				if ((reader.readByte(0x00) & 0xFF) == 0xE9) {
					/* App image magic is first byte */
					try {
						parsedAppImage = new ESP32AppImage(reader);
						loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(
								new LanguageID("Xtensa:LE:32:default"), new CompilerSpecID("default")), true));
					} catch (Exception ex) {
					}
				}
			}
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

		try {
			processELF(program, options, monitor, log);
		} catch (Exception ex) {
			String exceptionTxt = ex.toString();
			System.out.println(exceptionTxt);
		}

		FlatProgramAPI api = new FlatProgramAPI(program);
		ESP32AppImage imageToLoad = null;
		if (parsedAppImage != null) {
			imageToLoad = parsedAppImage;
		} else {
			/*
			 * they probably gave us a firmware file, lets load that and get the partition
			 * they selected
			 */
			var partOpt = (String) (options.get(0).getValue());

			ESP32Partition part = parsedFlash.GetPartitionByName(partOpt);
			try {
				imageToLoad = part.ParseAppImage();
			} catch (Exception ex) {
				log.appendException(ex);
			}
		}

		try {
			AddressSetPropertyMap codeProp = program.getAddressSetPropertyMap("CodeMap");
			if (codeProp == null) {
				codeProp = program.createAddressSetPropertyMap("CodeMap");
			}

			for (var x = 0; x < imageToLoad.SegmentCount; x++) {
				var curSeg = imageToLoad.Segments.get(x);

				FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, new ByteArrayProvider(curSeg.Data),
						0x00, curSeg.Length, monitor);
				if (program.getMemory().contains(api.toAddr(curSeg.LoadAddress),
						api.toAddr(curSeg.LoadAddress + curSeg.Length)) == false) {
					var blockName = curSeg.type.name();
					if (curSeg.type != SegmentType.DROM0 && curSeg.type != SegmentType.IROM0) {
						blockName += "_" + Integer.toHexString(curSeg.LoadAddress);
					}
					var memBlock = program.getMemory().createInitializedBlock(blockName, api.toAddr(curSeg.LoadAddress),
							fileBytes, 0x00, curSeg.Length, false);
					memBlock.setPermissions(curSeg.isRead(), curSeg.isWrite(), curSeg.isExecute());
					memBlock.setSourceName("ESP32 Loader");
				} else {
					/* memory block already exists... */
					MemoryBlock existingBlock = program.getMemory().getBlock(api.toAddr(curSeg.LoadAddress));
					if (existingBlock != null) {
						existingBlock.setName(curSeg.type.name() + "_" + Integer.toHexString(curSeg.LoadAddress));
						if (!existingBlock.isInitialized()) {
							program.getMemory().convertToInitialized(existingBlock, (byte) 0x0);
						}
						try {
							existingBlock.putBytes(api.toAddr(curSeg.LoadAddress), curSeg.Data);
						} catch (Exception ex) {
							log.appendException(ex);
						}
						existingBlock.setSourceName("ELF + ESP32 Loader");
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

			/* Create Peripheral Device Memory Blocks */
			if (imageToLoad.IsEsp32S2) {
				log.appendMsg("Process esp32s2 svd");
			}
			processSVD(program, api, imageToLoad.IsEsp32S2);

		} catch (Exception e) {
			log.appendException(e);
		}

		// TODO: Load the bytes from 'provider' into the 'program'.

	}

	private void processELF(Program program, List<Option> options, TaskMonitor monitor, MessageLog log)
			throws Exception {
		List<ResourceFile> elfFileList = Application.findFilesByExtensionInMyModule("elf");

		if (elfFileList.size() > 0) {
			if (elfFileList.get(0).getName().equals("esp32_rom.elf")) {
				/* load the ESP 32 BootROM elf */
				byte[] elfData = Files.readAllBytes(Paths.get(elfFileList.get(0).getAbsolutePath()));
				ByteArrayProvider bap = new ByteArrayProvider(elfData);
				ElfLoader loader = new ElfLoader();

				LoadSpec esp32LoadSpec = new LoadSpec(this, 0, new LanguageCompilerSpecPair(
						new LanguageID("Xtensa:LE:32:default"), new CompilerSpecID("default")), true);

				List<Option> elfOpts = loader.getDefaultOptions(bap, esp32LoadSpec, null, true);
				loader.load(bap, esp32LoadSpec, elfOpts, program, monitor, log);
			}
		}
	}

	private void processSVD(Program program, FlatProgramAPI api, boolean isESP32S2) throws Exception {
		// TODO Auto-generated method stub
		List<ResourceFile> svdFileList = Application.findFilesByExtensionInMyModule("svd");
		if (svdFileList.size() > 0) {
			/* grab the first svd file ... */
			String svdFile = svdFileList.get(0).getAbsolutePath();
			boolean isFound = svdFile.indexOf("esp32s2") != -1 ? true : false;
			if (isESP32S2) {
				if (!isFound) {
					svdFile = svdFileList.get(1).getAbsolutePath();
				}
			} else {
				if (isFound) {
					svdFile = svdFileList.get(1).getAbsolutePath();
				}
			}
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();

			Document doc = builder.parse(svdFile);

			Element root = doc.getDocumentElement();

			NodeList peripherals = root.getElementsByTagName("peripheral");
			for (var x = 0; x < peripherals.getLength(); x++) {
				processPeripheral(program, api, (Element) peripherals.item(x));
			}
		}
	}

	private void processPeripheral(Program program, FlatProgramAPI api, Element peripheral)
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

		for (var x = 0; x < registers.getLength(); x++) {
			Element register = (Element) registers.item(x);
			String registerName = ((Element) (register.getElementsByTagName("name").item(0))).getTextContent();
			String offsetString = ((Element) (register.getElementsByTagName("addressOffset").item(0))).getTextContent();
			int offsetValue = Integer.decode(offsetString);

			struct.replaceAtOffset(offsetValue, new UnsignedLongDataType(), 4, registerName, "");

		}

		var dtm = program.getDataTypeManager();
		var space = program.getAddressFactory().getDefaultAddressSpace();
		var listing = program.getListing();
		var symtbl = program.getSymbolTable();
		var namespace = symtbl.getNamespace("Peripherals", null);
		if (namespace == null) {
			namespace = program.getSymbolTable().createNameSpace(null, "Peripherals", SourceType.ANALYSIS);
		}

		var addr = space.getAddress(baseAddr);
		dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
		listing.createData(addr, struct);
		symtbl.createLabel(addr, peripheralName, namespace, SourceType.USER_DEFINED);
	}

	private void registerPeripheralBlock(Program program, FlatProgramAPI api, int startAddr, int endAddr, String name)
			throws LockException, DuplicateNameException, MemoryConflictException, AddressOverflowException {
		// TODO Auto-generated method stub
		var block = program.getMemory().createUninitializedBlock(name, api.toAddr(startAddr), endAddr - startAddr + 1,
				false);
		block.setRead(true);
		block.setWrite(true);

		/*
		 * var memBlock = program.getMemory().createInitializedBlock(curSeg.SegmentName
		 * + "_" + Integer.toHexString(curSeg.LoadAddress),
		 * api.toAddr(curSeg.LoadAddress), fileBytes, 0x00, curSeg.Length, false);
		 * memBlock.setPermissions(curSeg.IsRead, curSeg.IsWrite, curSeg.IsExecute);
		 */
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = new ArrayList<Option>();

		if (parsedFlash != null) {
			// TODO: If this loader has custom options, add them to 'list'
			list.add(new PartitionOption(parsedFlash));
		}
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here. Not all options
		// require
		// validation.
		if (options.get(0).getValue() == null || options.get(0).getValue().equals("")) {
			return "App partition not found in image.";
		}
		return null;
		// return super.validateOptions(provider, loadSpec, options, program);
	}
}
