{
  description = "A blocklist downloader.";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    naersk = {
      url = "github:nmattia/naersk";
      inputs.nixpkgs.follows = "/nixpkgs";
    };
  };

  outputs = { self, nixpkgs, naersk, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs { inherit system; };
      in
        {
          defaultPackage = naersk.lib.${system}.buildPackage {
            src = ./.;
          };
          defaultApp = {
            type = "app";
            program = "${self.defaultPackage.${system}}/bin/blocklistdownloadthing";
          };
        }
    );
}
