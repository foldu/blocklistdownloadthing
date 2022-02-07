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
    {
      overlay = final: prev: {
        blocklistdownloadthing =
          let
            pkgs = nixpkgs.legacyPackages.${prev.system};
            naersk-lib = naersk.lib."${prev.system}".override {
              cargo = pkgs.cargo;
              rustc = pkgs.rustc;
            };
          in
          naersk-lib.buildPackage {
            src = ./.;
          };
      };
    } // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ self.overlay ];
        };
      in
      {
        defaultPackage = pkgs.blocklistdownloadthing;
      }
    );
}
