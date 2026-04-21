# Shared helpers for tests/phase*.sh. Source at the top of any phase script.

# Re-exec under nix-shell with libstdc++ + libz on LD_LIBRARY_PATH when we're
# on NixOS. No-op on other platforms. Idempotent (guarded by WAFLAB_TESTS_NIX).
waflab_nix_reexec() {
  if command -v nix-build >/dev/null 2>&1 && [[ -z "${WAFLAB_TESTS_NIX:-}" ]]; then
    export WAFLAB_TESTS_NIX=1
    local script="$1"; shift
    exec nix-shell -p stdenv.cc.cc.lib zlib \
         --run "LD_LIBRARY_PATH=\$(nix-build --no-out-link '<nixpkgs>' -A stdenv.cc.cc.lib)/lib:\$(nix-build --no-out-link '<nixpkgs>' -A zlib)/lib:\$LD_LIBRARY_PATH bash '$script' $*"
  fi
}
