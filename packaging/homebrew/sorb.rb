# Homebrew formula for the standalone sorb bundle.
# Templated at release: {{VERSION}} / {{SHA256_*}} are filled by the release
# pipeline, which also Sigstore-signs the artifacts (verified by `sorb verify`).
class Sorb < Formula
  desc "Evidence-backed dependency analysis and SBOM generation"
  homepage "https://github.com/SorbetSecurity/sorbet-cli"
  version "{{VERSION}}"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/SorbetSecurity/sorbet-cli/releases/download/v{{VERSION}}/sorb-macos-arm64.tar.gz"
      sha256 "{{SHA256_MACOS_ARM64}}"
    end
    on_intel do
      url "https://github.com/SorbetSecurity/sorbet-cli/releases/download/v{{VERSION}}/sorb-macos-x86_64.tar.gz"
      sha256 "{{SHA256_MACOS_X86_64}}"
    end
  end

  on_linux do
    url "https://github.com/SorbetSecurity/sorbet-cli/releases/download/v{{VERSION}}/sorb-linux-x86_64.tar.gz"
    sha256 "{{SHA256_LINUX_X86_64}}"
  end

  def install
    bin.install "sorb"
  end

  test do
    assert_match "sorb", shell_output("#{bin}/sorb --version")
  end
end
