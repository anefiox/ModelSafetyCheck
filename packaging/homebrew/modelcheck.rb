# Homebrew formula for modelcheck. Rendered per release by packaging/render.sh; publish it in a tap (see packaging/README.md).
class Modelcheck < Formula
  desc "Scan local AI models, chat templates and runner setups for malicious content"
  homepage "https://github.com/{{REPO}}"
  version "{{VERSION}}"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/{{REPO}}/releases/download/{{TAG}}/modelcheck-{{TAG}}-osx-arm64.tar.gz"
      sha256 "{{SHA256_osx-arm64}}"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/{{REPO}}/releases/download/{{TAG}}/modelcheck-{{TAG}}-linux-x64.tar.gz"
      sha256 "{{SHA256_linux-x64}}"
    end
    on_arm do
      url "https://github.com/{{REPO}}/releases/download/{{TAG}}/modelcheck-{{TAG}}-linux-arm64.tar.gz"
      sha256 "{{SHA256_linux-arm64}}"
    end
  end

  def install
    # The ONNX Runtime library (for the optional --classifier) must sit next to the executable.
    libexec.install Dir["*"]
    bin.install_symlink libexec/"modelcheck"
  end

  test do
    assert_match "modelcheck", shell_output("#{bin}/modelcheck --help")
  end
end
