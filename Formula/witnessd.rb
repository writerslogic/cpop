# Homebrew formula for witnessd
# To install from source: brew install --build-from-source ./Formula/witnessd.rb

class Witnessd < Formula
  desc "Cryptographic authorship witnessing - kinetic proof of provenance"
  homepage "https://github.com/writerslogic/witnessd"
  # Dual license: Non-commercial free, commercial license required for business use
  # See LICENSE file for details. Patent pending: USPTO App. No. 19/460,364
  license :cannot_represent
  head "https://github.com/writerslogic/witnessd.git", branch: "main"

  # Stable release URL will be filled in by goreleaser
  # url "https://github.com/writerslogic/witnessd/archive/refs/tags/v0.1.0.tar.gz"
  # sha256 "..."

  depends_on "go" => :build

  def install
    ldflags = %W[
      -s -w
      -X main.Version=#{version}
      -X main.Commit=#{Utils.git_short_head}
      -X main.BuildTime=#{time.iso8601}
    ]

    system "go", "build", *std_go_args(ldflags:), "-o", bin/"witnessd", "./cmd/witnessd"
    system "go", "build", *std_go_args(ldflags:), "-o", bin/"witnessctl", "./cmd/witnessctl"

    man1.install "docs/man/witnessd.1"
    man1.install "docs/man/witnessctl.1"
  end

  def caveats
    <<~EOS
      To get started with witnessd:

        1. Initialize witnessd:
           witnessd init

        2. Calibrate VDF for your machine:
           witnessd calibrate

        3. Create your first checkpoint:
           witnessd commit your-document.md -m "Initial draft"

      For documentation:
        man witnessd
        man witnessctl

      Privacy note: Keystroke tracking counts keystrokes only.
      It does NOT capture which keys are pressed.
    EOS
  end

  test do
    assert_match "witnessd", shell_output("#{bin}/witnessd version")
    assert_match "witnessctl", shell_output("#{bin}/witnessctl -version")

    # Test init creates the directory structure
    system bin/"witnessd", "init"
    assert_predicate testpath/".witnessd", :directory?
    assert_predicate testpath/".witnessd/signing_key", :file?
  end
end
