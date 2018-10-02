#include "coreclrhost.h"
#include "dep.h"
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <iostream>
#include <map>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

namespace fs = std::filesystem;

#define EXPORT extern "C" __attribute__((__visibility__("default")))

static std::vector<void *> mods;

void loadMods(fs::path path, std::set<fs::path> &others) {
  static std::set<void (*)()> set;
  auto deps = getDependencies(path);
  for (auto const &dep : deps) {
    auto name = path.parent_path();
    name /= dep;
    if (others.count(name) > 0) {
      others.erase(name);
      loadMods(name, others);
      others.erase(name);
    }
  }
  printf("Loading mod: %s\n", path.stem().c_str());
  void *mod = dlopen(path.c_str(), RTLD_NOW);
  if (!mod) {
    fprintf(stderr, "Failed to load %s: %s\n", path.stem().c_str(), dlerror());
    return;
  }
  mods.emplace_back(mod);
  auto mod_init = (void (*)(void))dlsym(mod, "mod_init");
  if (mod_init && set.count(mod_init) == 0) {
    mod_init();
    set.insert(mod_init);
  }
}

void loadModsFromDirectory(fs::path base) {
  if (fs::exists(base) && fs::is_directory(base)) {
    std::set<fs::path> modsToLoad;
    for (auto mod : fs::recursive_directory_iterator{ base, fs::directory_options::follow_directory_symlink }) {
      if (mod.path().extension() == ".so") { modsToLoad.insert(mod.path()); }
    }
    while (!modsToLoad.empty()) {
      auto it   = modsToLoad.begin();
      auto path = *it;
      modsToLoad.erase(it);

      loadMods(path, modsToLoad);
    }
    std::set<void (*)()> set;
    for (auto mod : mods) {
      auto mod_exec = (void (*)(void))dlsym(mod, "mod_exec");
      if (mod_exec && set.count(mod_exec) == 0) {
        mod_exec();
        set.insert(mod_exec);
      }
    }
  }
}

const char *GetEnvValueBoolean(const char *envVariable) {
  const char *envValue = std::getenv(envVariable);
  if (envValue == nullptr) { envValue = "0"; }
  return (std::strcmp(envValue, "1") == 0 || strcasecmp(envValue, "true") == 0) ? "true" : "false";
}

void addToTpa(fs::path directory, std::string &tpaList) {
  const char *const tpaExtensions[] = {
    ".ni.dll", // Probe for .ni.dll first so that it's preferred if ni and il coexist in the same dir
    ".dll",
    ".ni.exe",
    ".exe",
  };

  std::set<std::string> addedAssemblies;

  for (auto &ext : tpaExtensions) {
    for (auto &entry : fs::recursive_directory_iterator(directory, fs::directory_options::follow_directory_symlink)) {
      auto path = entry.path();
      if (entry.is_regular_file() && path.extension() == ext) {
        if (addedAssemblies.count(path.stem()) == 0) {
          addedAssemblies.insert(path.filename());
          tpaList.append(fs::absolute(path));
          tpaList.append(":");
        }
      }
    }
  }
}

void addToPathsRec(fs::path directory, std::string &list) {
  list.append(fs::canonical(directory));
  list.append("/:");
  for (auto &entry : fs::recursive_directory_iterator(directory, fs::directory_options::follow_directory_symlink)) {
    if (entry.is_directory()) {
      list.append(fs::canonical(entry.path()));
      list.append("/:");
    }
  }
}

void addToPaths(fs::path directory, std::string &list) {
  list.append(fs::canonical(directory));
  list.append("/:");
}

// clang-format off
static const char *propertyKeys[] = { "TRUSTED_PLATFORM_ASSEMBLIES", "NATIVE_DLL_SEARCH_DIRECTORIES", "AppDomainCompatSwitch", "System.GC.Server", "System.Globalization.Invariant" };
// clang-format on

struct CoreCLR {
  void *hostHandle;
  unsigned int domainId;
  bool success = false;
  CoreCLR() {
    std::string tpa;
    std::string nativePaths;
    addToTpa("net", tpa);
    addToTpa(std::getenv("DOTNET_RUNTIME"), tpa);
    addToPathsRec("mods", nativePaths);
    addToPaths(".", nativePaths);
    const char *useServerGc            = GetEnvValueBoolean("COMPlus_gcServer");
    const char *globalizationInvariant = GetEnvValueBoolean("CORECLR_GLOBAL_INVARIANT");
    const char *appdomainSwitch        = "UseLatestBehaviorWhenTFMNotSpecified";
    const char *propertyValues[]       = { tpa.c_str(), nativePaths.c_str(), appdomainSwitch, useServerGc, globalizationInvariant };
    int st = coreclr_initialize(fs::canonical("/proc/self/exe").c_str(), "bdsm", sizeof(propertyValues) / sizeof(void *), propertyKeys,
                                propertyValues, &hostHandle, &domainId);
    if (st < 0)
      fprintf(stderr, "coreclr_initialize failed - status: 0x%08x\n", st);
    else
      success = true;
  }

  void *getDelegate(const char *entryPoint, const char *typeName, const char *methodName) {
    if (!success) return nullptr;
    void *ret;
    auto st = coreclr_create_delegate(hostHandle, domainId, "BDSM.Net", "BDSM.Net.Bridge", "Init", &ret);
    if (st < 0) {
      fprintf(stderr, "create_delegate failed - status: 0x%08x\n", st);
      return nullptr;
    }
    return ret;
  }
  template <typename T> auto fetchDelegate(const char *entryPoint, const char *typeName, const char *methodName) {
    return reinterpret_cast<T *>(getDelegate(entryPoint, typeName, methodName));
  }
};

EXPORT CoreCLR &getCLR() {
  static CoreCLR clr;
  return clr;
}

EXPORT void initString(const char *inp, std::string *data) { new (data) std::string(inp); }

EXPORT void setString(const char *inp, std::string *data) { *data = inp; }

EXPORT void deleteString(std::string *str) { str->~basic_string(); }

struct Executor {
  Executor() {
    if (fs::canonical("/proc/self/exe").filename() != "bedrock_server") return;
    std::cout << "Loading mods..." << std::endl;
    loadModsFromDirectory("core");
    loadModsFromDirectory("mods");
    auto fn = getCLR().fetchDelegate<void()>("BDSM.Net", "BDSM.Net.Bridge", "Init");
    if (fn) fn();
  }
} executor;