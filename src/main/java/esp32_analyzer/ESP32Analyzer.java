package esp32_analyzer;

import esp32_loader.datatype.EspAppDesc;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ESP32Analyzer implements Analyzer {

	@Override
	public String getName() {
		return "ESP32 Data Analyzer";
	}

	@Override
	public AnalyzerType getAnalysisType() {
		return AnalyzerType.DATA_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean supportsOneTimeAnalysis() {
		return true;
	}

	@Override
	public String getDescription() {
		return "Annotates common ESP32 datatypes";
	}

	@Override
	public AnalysisPriority getPriority() {
		return AnalysisPriority.DATA_ANALYSIS;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().toString().equals("Xtensa");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		// TODO Auto-generated method stub
		var DROM0 = program.getMemory().getBlock("DROM0");
		if(DROM0 == null) {
			return true;
		}

		ByteProvider provider = new MemoryByteProvider(program.getMemory(), DROM0.getStart());
		BinaryReader reader = new BinaryReader(provider, true);
		try {
			var appDesc = new EspAppDesc(reader);
			program.getListing().createData(DROM0.getStart(), appDesc.toDataType());
		} catch(Exception e) {
			return false;
		}
		return true;
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// TODO Auto-generated method stub

	}

	@Override
	public void optionsChanged(Options options, Program program) {
		// TODO Auto-generated method stub

	}

	@Override
	public void analysisEnded(Program program) {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean isPrototype() {
		return false;
	}

}
