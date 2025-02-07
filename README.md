
# flash loader plugin for ghidra

Build with gradle

    export GHIDRA_INSTALL_DIR=/opt/ghidra/
    gradle
    
Put the ./dist/ghidra_9.1_DEV_20200613_esp32_flash_loader.zip
Into /opt/ghidra/Extensions/Ghidra/
Then enable the extension

TODO, Use Dockerfile from here https://github.com/blacktop/docker-ghidra to build the extension

To add the checked-out Git repository to your Ghidra-Scripts search paths:
- Open the 'CodeBrowser' from the 'Tool Chest'
- Open Window -> Script Manager
- In the new window click on the 'Manage Script Directories' icon on the top right of the window
- In the new window click on the 'Display file chooser to add bundles to list' icon on the top right of the window
- Select the folder containing your clone of the SVD-Loader-Ghidra repository
- Close the Bundle Manager Window
- Search for 'SVD' in your Script Manager
- Check the checkbox for the 'SVD-Loader.py'
- Close the Script Manager

If loading an elf file, load svd manually before doing analysis

https://leveldown.de/blog/svd-loader/

