{
  description = "A blocklist downloader.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    crane.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, crane, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        craneLib = crane.lib.${system};
        blocklistdownloadthing =
          craneLib.buildPackage {
            src = craneLib.cleanCargoSource ./.;
          };
      in
      {
        defaultPackage = blocklistdownloadthing;
        packages = {
          inherit blocklistdownloadthing;
        };
      }
    );
}
