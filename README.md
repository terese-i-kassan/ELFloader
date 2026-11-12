# ELFloader

# ABOUT

A Aroma plugin that allows for elf built with wut to be loaded on aroma. It works by using the source of elf2rpl and converting it into a rpx file that then get loaded. Keep in mind that not allot of elf files are built with wut. Also keep in mind that if you load a elf file that uses allot of ram the wii u will run out of memory and get an error code. ALSO CODE IS MADE BY CLUADE.

# INSTALLATION 
1. Download the wps file from the releases and put it in the plugins folder of your sd card located in "sd:/wiiu/environments/aroma/plugins"
2. Put your elf files into the folder "sd:/wiiu/elf" if you don't got this folder just make it. (also if you put non wut built elf files the files will not load)
3. When you return to your wii u menu hold down l +down + - to open up the plugin menu. Navigate to the ELFloader plugin then choose a elf file from the menu and press A. When exiting the elf file should have loaded if not its probably not built with wut or and other error has occurred and is logged at "sd:/wiiu/elfelf_loader.log"
4. Converted files will be stored into "sd:/wiiu/elf/.cache"

# BUILDING
    
    docker build -t elfloader-builder .
    docker run -it --rm -v ${PWD}:/project elfloader-builder make

# LIMITS

Only ELFs built with wut convert. Old libwiiu / HBL-era ELFs use a different
memory layout and will fail with an "unsupported relocation" error (or won't run) they need
recompiling against wut

