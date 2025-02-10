package esp32_loader;

import docking.widgets.combobox.GComboBox;
import esp32_loader.flash.ESP32Flash;
import ghidra.app.util.Option;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

public class PartitionOption extends Option implements ItemListener {

    ESP32Flash parsedFlash;
    GComboBox<String> cb = new GComboBox<String>();

    public PartitionOption(ESP32Flash parsedFlash) {
        super("App Partition", "factory", String.class, "-partition");
        this.setValue(this.processPartitions(parsedFlash));
        this.parsedFlash = parsedFlash;
    }

    private String processPartitions(ESP32Flash parsedFlash) {
        var defaultSelection = "";

        if (!parsedFlash.Partitions.isEmpty()) {
            cb.setName(getName());

            for (var partition : parsedFlash.Partitions) {
                /* Only add "App" partitions */
                if (partition.Type == 0x00) {

                    if (partition.SubType >= 0x10 && partition.SubType <= 0x1F) {
                        /* This is an OTA partition, check its StartBytes for a validity smell test */
                        if (partition.Data[0] != -1) {
                            cb.addItem(partition.Name);
                        }
                    } else {
                        cb.addItem(partition.Name);
                    }
                }
            }

            var firstPartition = parsedFlash.Partitions.get(0);
            cb.setSelectedItem(firstPartition.Name);
            cb.addItemListener(this);

            defaultSelection = cb.getItemAt(0);
        }

        return defaultSelection;
    }

    @Override
    public Component getCustomEditorComponent() {
        return this.cb;
    }

    public void itemStateChanged(ItemEvent evt) {
        setValue(cb.getSelectedItem());
    }

    @Override
    public Option copy() {
        PartitionOption opt = new PartitionOption(parsedFlash);
        opt.setValue(this.getValue());
        return opt;
    }
}
