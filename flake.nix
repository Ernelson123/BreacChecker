{
  # 1. INPUTS (Entradas)
  # Define de onde virão os pacotes.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  # 2. OUTPUTS (Saídas)
  # Define o que este flake fornece ao mundo.
  outputs = { self, nixpkgs }: let
    # Define o sistema alvo (geralmente x86_64-linux para PCs comuns)
    sys = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${sys};
  in {
    # 3. DEV SHELLS (Ambientes de Desenvolvimento)
    # Cria um ambiente chamado 'default' que é ativado com 'nix develop'.
    devShells.${sys}.default = pkgs.mkShell {
      # 4. BUILD INPUTS (Ferramentas)
      # Lista tudo o que deve estar disponível no terminal quando o ambiente estiver ativo.
      buildInputs = [ 
        pkgs.uv          # Gestor de pacotes Python (Fase 1)
        pkgs.go_1_25     
        pkgs.git         
        pkgs.curl        # Cliente HTTP (testes de API)
        pkgs.gnumake     # Automação de build (Makefile)
      ];
      
      # 5. SHELL HOOK (Script de Inicialização)
      # Comandos que rodam automaticamente assim que você entra no ambiente.
      shellHook = ''
        echo "Ambiente pronto."
        echo "uv: $(uv --version)"
        echo "Go: $(go version)"
      '';
    };
  };
}