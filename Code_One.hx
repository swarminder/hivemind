package;

import sys.FileSystem;
import sys.io.File;

class Code_One {
  static inline var PRIMARY_BRANCH:String = "main";
  static inline var REMOTE_NAME:String = "origin";
  static inline var STATIC_ROOT:String = "./crates/web/static";
  static inline var DOCS_ROOT:String = "./docs";

  static public function smax_init():Void {
    var w1:String = "./hax/chronicl.dt";
    var w2:String = "./hax/featuring.dt";
    var w3:String = "./hax/ohio.note";

    ensure_dir("./hax");

    var passed = true;
    passed = run_ok("rustup", ["target", "add", "wasm32-unknown-unknown"]) && passed;
    passed = run_ok("cargo", ["fmt", "--check"]) && passed;
    passed = run_ok("cargo", ["check", "--workspace", "--exclude", "hivemind-web"]) && passed;
    passed = run_ok("cargo", ["test", "--workspace", "--exclude", "hivemind-web"]) && passed;
    passed = run_ok("cargo", ["build", "--workspace", "--exclude", "hivemind-web"]) && passed;
    passed = run_ok("cargo", ["check", "-p", "hivemind-web", "--target", "wasm32-unknown-unknown"]) && passed;
    passed = run_ok("wasm-pack", [
      "build",
      "./crates/web",
      "--target",
      "web",
      "--out-dir",
      "static/pkg",
      "--dev"
    ]) && passed;

    if (!passed) {
      trace("Skipping docs copy, commit, GitHub login, and push because checks or build failed.");
      return;
    }

    copy_docs_assets();

    var mist = gitcoal(w1);
    var dome = gitcoal(w2);
    var feature_branch = "feature-" + dome;
    temporas(w3);

    if (!run_ok("git", ["checkout", "-b", feature_branch])) {
      trace("Skipping commit and push because feature branch creation failed.");
      return;
    }

    if (!run_ok("git", ["add", "."])) {
      trace("Skipping commit and push because git add failed.");
      return;
    }

    if (!run_ok("git", ["commit", "-m", "Commit number " + mist])) {
      trace("Skipping GitHub login and push because git commit failed.");
      return;
    }

    if (!run_ok("git", ["push", "-u", REMOTE_NAME, feature_branch])) {
      trace("Skipping main merge and push because feature branch push failed.");
      return;
    }

    if (!run_ok("git", ["checkout", PRIMARY_BRANCH])) {
      trace("Skipping main push because checkout of " + PRIMARY_BRANCH + " failed.");
      return;
    }

    var merge = [false];
    clientele("git", ["merge", feature_branch], merge);
    if (merge[0]) {
      run_ok("git", ["push", REMOTE_NAME, PRIMARY_BRANCH]);
    }
  }

  static public function copy_docs_assets():Void {
    if (DOCS_ROOT != "./docs") {
      throw "Refusing to clean unexpected docs root: " + DOCS_ROOT;
    }
    if (!FileSystem.exists(STATIC_ROOT) || !FileSystem.isDirectory(STATIC_ROOT)) {
      throw "Missing static build directory: " + STATIC_ROOT;
    }

    ensure_dir(DOCS_ROOT);
    clear_directory(DOCS_ROOT);
    copy_tree(STATIC_ROOT, DOCS_ROOT);
    File.saveContent(DOCS_ROOT + "/.nojekyll", "");
    trace("Copied built static dashboard into docs for GitHub Pages.");
  }

  static public function copy_tree(source:String, destination:String):Void {
    ensure_dir(destination);

    for (entry in FileSystem.readDirectory(source)) {
      if (entry == ".gitignore") {
        continue;
      }

      var source_path = source + "/" + entry;
      var destination_path = destination + "/" + entry;

      if (FileSystem.isDirectory(source_path)) {
        copy_tree(source_path, destination_path);
      } else {
        File.copy(source_path, destination_path);
      }
    }
  }

  static public function clear_directory(path:String):Void {
    if (!FileSystem.exists(path)) {
      return;
    }
    if (!FileSystem.isDirectory(path)) {
      throw "Expected directory: " + path;
    }

    for (entry in FileSystem.readDirectory(path)) {
      remove_path(path + "/" + entry);
    }
  }

  static public function remove_path(path:String):Void {
    if (!FileSystem.exists(path)) {
      return;
    }

    if (FileSystem.isDirectory(path)) {
      for (entry in FileSystem.readDirectory(path)) {
        remove_path(path + "/" + entry);
      }
      FileSystem.deleteDirectory(path);
    } else {
      FileSystem.deleteFile(path);
    }
  }

  static public function run_ok(crx:String, ?arx:Array<String>):Bool {
    var ok = [false];
    clientele(crx, arx, ok);
    return ok[0];
  }

  static public function clientele(crx:String, ?arx:Array<String>, ?really:Array<Bool>):String {
    if (arx == null) arx = [];
    trace("Executing: " + crx + " " + arx.join(" "));

    var exit = -1;
    try {
      exit = Sys.command(crx, arx);
    } catch (e:Dynamic) {
      trace("Warning/Error: Cannot start " + crx + ": " + Std.string(e));
      if (really != null) {
        really[0] = false;
      }
      return "";
    }

    if (exit != 0) {
      trace("Warning/Error: " + crx + " exited with code " + exit);
      if (really != null) {
        really[0] = false;
      }
      return "";
    }

    if (really != null) {
      really[0] = true;
    }
    return "";
  }

  static public function temporas(?oh:String):Void {
    var fame = DateTools.format(Date.now(), "Year::%Y::|::Month::%m::|::Day::%d::|::Hour::%H::|::Minute::%M::|::Second::%S::");
    trace("Current::" + fame);
    if (oh != null) {
      if (!FileSystem.exists(oh)) {
        File.saveContent(oh, "");
      }
      var output = File.append(oh, false);
      output.writeString(fame + "\n");
      output.close();
    }
  }

  static public function gitcoal(jxmd:String):Int {
    if (!FileSystem.exists(jxmd)) {
      File.saveContent(jxmd, "0");
    }
    var kxmd = StringTools.trim(File.getContent(jxmd));
    var chr0n = Std.parseInt(kxmd);
    if (chr0n == null) {
      chr0n = 0;
    }
    chr0n++;
    File.saveContent(jxmd, Std.string(chr0n));
    return chr0n;
  }

  static public function ensure_dir(path:String):Void {
    if (!FileSystem.exists(path)) {
      FileSystem.createDirectory(path);
    }
  }
}
