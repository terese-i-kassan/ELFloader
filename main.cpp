
#include <wups.h>
#include <wups/config/WUPSConfigCategory.h>
#include <wups/config/WUPSConfigItemMultipleValues.h>
#include <wups/config/WUPSConfigItemStub.h>
#include <wups/config_api.h>

#include <coreinit/debug.h>
#include <rpxloader/rpxloader.h>

#include "elf2rpl.h"

#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <exception>
#include <string>
#include <strings.h>
#include <sys/stat.h>
#include <vector>

WUPS_PLUGIN_NAME("ELF Loader");
WUPS_PLUGIN_DESCRIPTION("Launch wut-built .elf files from sd:/wiiu/elf/ by converting them to .rpx without needing to remove your sd card.");
WUPS_PLUGIN_VERSION("v0.1");
WUPS_PLUGIN_AUTHOR("tereseikassan");
WUPS_PLUGIN_LICENSE("MIT");

WUPS_USE_WUT_DEVOPTAB();

// Absolute paths (through the wut devoptab) and the same location relative to
// the SD root, which is what RPXLoader expects.
#define ELF_DIR_ABS   "fs:/vol/external01/wiiu/elf"
#define CACHE_DIR_ABS "fs:/vol/external01/wiiu/elf/.cache"
#define LOG_PATH_ABS  "fs:/vol/external01/wiiu/elf/elf_loader.log"
#define CACHE_DIR_REL "wiiu/elf/.cache"

static bool sRpxLoaderReady = false;

// Kept alive for the lifetime of the open config menu.
static std::vector<std::string> sElfNames;
static std::vector<std::string> sLabels;
static std::vector<WUPSConfigItemMultipleValues::ValuePair> sPairs;

static void logf(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    OSReport("[elf_loader] %s\n", buf);

    if (FILE *f = fopen(LOG_PATH_ABS, "a")) {
        fprintf(f, "%s\n", buf);
        fclose(f);
    }
}

static bool endsWithElf(const char *name) {
    size_t n = strlen(name);
    return n > 4 && strcasecmp(name + n - 4, ".elf") == 0 && name[0] != '.';
}

static void scanElfs() {
    sElfNames.clear();
    DIR *d = opendir(ELF_DIR_ABS);
    if (!d) {
        return;
    }
    while (struct dirent *e = readdir(d)) {
        if (e->d_type != DT_DIR && endsWithElf(e->d_name)) {
            sElfNames.emplace_back(e->d_name);
        }
    }
    closedir(d);
    std::sort(sElfNames.begin(), sElfNames.end());
}

static bool cacheIsFresh(const std::string &elfPath, const std::string &rpxPath) {
    struct stat es, rs;
    if (stat(elfPath.c_str(), &es) != 0 || stat(rpxPath.c_str(), &rs) != 0) {
        return false;
    }
    return rs.st_size > 0 && rs.st_mtime >= es.st_mtime;
}

static void launchElf(const std::string &name) {
    const std::string base    = name.substr(0, name.size() - 4);
    const std::string elfPath = std::string(ELF_DIR_ABS) + "/" + name;
    const std::string rpxPath = std::string(CACHE_DIR_ABS) + "/" + base + ".rpx";
    const std::string rpxRel  = std::string(CACHE_DIR_REL) + "/" + base + ".rpx";

    if (!sRpxLoaderReady) {
        logf("RPXLoader is not available (is RPXLoadingModule loaded?)");
        return;
    }

    if (!cacheIsFresh(elfPath, rpxPath)) {
        logf("converting %s ...", name.c_str());

        if (mkdir(CACHE_DIR_ABS, 0777) != 0 && errno != EEXIST) {
            logf("could not create %s (errno %d)", CACHE_DIR_ABS, errno);
            return;
        }

        // Convert to a temp file first so a failed/interrupted conversion can
        // never be mistaken for a valid cached .rpx.
        const std::string tmpPath = rpxPath + ".tmp";
        std::string err;
        bool ok = false;
        try {
            ok = elf2rpl::convert(elfPath, tmpPath, false, err);
        } catch (const std::exception &e) {
            err = std::string("exception: ") + e.what(); // e.g. out of memory
        }

        if (!ok) {
            logf("conversion of %s failed: %s", name.c_str(), err.c_str());
            remove(tmpPath.c_str());
            return;
        }

        remove(rpxPath.c_str());
        if (rename(tmpPath.c_str(), rpxPath.c_str()) != 0) {
            logf("could not move converted file into place (errno %d)", errno);
            return;
        }
    }

    logf("launching %s", rpxRel.c_str());
    RPXLoaderStatus st = RPXLoader_LaunchHomebrew(rpxRel.c_str());
    if (st != RPX_LOADER_RESULT_SUCCESS) {
        logf("launch failed: %s", RPXLoader_GetStatusStr(st));
    }
}

// Called by WUPS when the config menu closes AND the selection changed.
static void onElfSelected(ConfigItemMultipleValues *, uint32_t newValue) {
    if (newValue == 0 || newValue > sElfNames.size()) {
        return; // "- select an ELF -"
    }
    launchElf(sElfNames[newValue - 1]);
}

static WUPSConfigAPICallbackStatus onConfigMenuOpened(WUPSConfigCategoryHandle rootHandle) {
    WUPSConfigCategory root(rootHandle);

    try {
        scanElfs();

        if (sElfNames.empty()) {
            root.add(WUPSConfigItemStub::Create("No .elf files found in sd:/wiiu/elf/"));
            return WUPSCONFIG_API_CALLBACK_RESULT_SUCCESS;
        }

        // Build all strings first, then the string_view pairs, so nothing dangles.
        sLabels.clear();
        sLabels.emplace_back("- select an ELF -");
        for (const auto &n : sElfNames) {
            sLabels.push_back(n.substr(0, n.size() - 4));
        }
        sPairs.clear();
        for (size_t i = 0; i < sLabels.size(); ++i) {
            sPairs.push_back({static_cast<uint32_t>(i), sLabels[i]});
        }

        root.add(WUPSConfigItemMultipleValues::CreateFromIndex(
                "elf_select", "Launch ELF (applies when menu closes)",
                0, 0, sPairs, onElfSelected));
        root.add(WUPSConfigItemStub::Create("Errors are logged to sd:/wiiu/elf/elf_loader.log"));
    } catch (const std::exception &e) {
        logf("creating config menu failed: %s", e.what());
        return WUPSCONFIG_API_CALLBACK_RESULT_ERROR;
    }

    return WUPSCONFIG_API_CALLBACK_RESULT_SUCCESS;
}

static void onConfigMenuClosed() {
}

INITIALIZE_PLUGIN() {
    RPXLoaderStatus st = RPXLoader_InitLibrary();
    sRpxLoaderReady    = (st == RPX_LOADER_RESULT_SUCCESS);
    if (!sRpxLoaderReady) {
        OSReport("[elf_loader] RPXLoader_InitLibrary failed: %s\n", RPXLoader_GetStatusStr(st));
    }

    WUPSConfigAPIOptionsV1 options = {.name = "ELF Loader"};
    if (WUPSConfigAPI_Init(options, onConfigMenuOpened, onConfigMenuClosed) != WUPSCONFIG_API_RESULT_SUCCESS) {
        OSReport("[elf_loader] failed to init config api\n");
    }
}
