{
  description = "A blocklist downloader.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk = {
      url = "github:nmattia/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, naersk, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        blocklistdownloadthing =
          let
            naersk-lib = naersk.lib."${system}".override {
              cargo = pkgs.cargo;
              rustc = pkgs.rustc;
            };
          in
          naersk-lib.buildPackage {
            src = ./.;
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
