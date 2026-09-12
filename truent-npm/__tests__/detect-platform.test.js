describe("Platform Detection", () => {
  const { detectPlatform, TRUENT_VERSION, GITHUB_REPO, BINARY_DIR } = require("../lib/detect-platform");
  const os = require("os");

  const originalPlatform = os.platform;
  const originalArch = os.arch;

  afterEach(() => {
    // Restore original functions
    os.platform = originalPlatform;
    os.arch = originalArch;
  });

  test("linux-x86_64 detected correctly", () => {
    os.platform = jest.fn(() => "linux");
    os.arch = jest.fn(() => "x64");

    const info = detectPlatform();

    expect(info.platform).toBe("linux");
    expect(info.arch).toBe("x86_64");
    expect(info.binaryName).toBe("truent");
    expect(info.target).toBe("x86_64-unknown-linux-gnu");
    expect(info.archiveFormat).toBe("tar.gz");
    expect(info.archiveName).toContain("x86_64-unknown-linux-gnu");

    // Must exactly match the asset name release.yml actually uploads
    // ("truent-v<version>-<target>.<ext>", "v" immediately after "truent-"),
    // or the download (and the SHA256SUMS lookup keyed on this same name) 404s.
    const { version } = require("../package.json");
    expect(info.archiveName).toBe(
      `truent-v${version}-x86_64-unknown-linux-gnu.tar.gz`
    );
  });

  test("macos-aarch64 detected correctly", () => {
    os.platform = jest.fn(() => "darwin");
    os.arch = jest.fn(() => "arm64");

    const info = detectPlatform();

    expect(info.platform).toBe("macos");
    expect(info.arch).toBe("aarch64");
    expect(info.binaryName).toBe("truent");
    expect(info.target).toBe("aarch64-apple-darwin");
    expect(info.archiveFormat).toBe("tar.gz");
  });

  test("windows-x86_64 detected correctly", () => {
    os.platform = jest.fn(() => "win32");
    os.arch = jest.fn(() => "x64");

    const info = detectPlatform();

    expect(info.platform).toBe("windows");
    expect(info.arch).toBe("x86_64");
    expect(info.binaryName).toBe("truent.exe");
    expect(info.target).toBe("x86_64-pc-windows-msvc");
    expect(info.archiveFormat).toBe("zip");
  });

  test("unsupported platform throws helpful error", () => {
    os.platform = jest.fn(() => "sunos");
    os.arch = jest.fn(() => "x64");

    expect(() => {
      detectPlatform();
    }).toThrow(/does not support your platform/);

    expect(() => {
      detectPlatform();
    }).toThrow(/sunos-x64/);

    expect(() => {
      detectPlatform();
    }).toThrow(/github.com\/Emmyhack\/Truent\/issues/);
  });

  test("exports correct version", () => {
    const { version } = require("../package.json");
    expect(TRUENT_VERSION).toBe(version);
  });

  test("exports correct GitHub repo", () => {
    expect(GITHUB_REPO).toBe("Emmyhack/Truent");
  });

  test("exports binary directory path", () => {
    expect(BINARY_DIR).toContain(".truent-bin");
  });

  test("download URL is correctly formatted", () => {
    const { version } = require("../package.json");
    os.platform = jest.fn(() => "linux");
    os.arch = jest.fn(() => "x64");

    const info = detectPlatform();

    expect(info.downloadUrl).toContain("https://github.com");
    expect(info.downloadUrl).toContain("releases/download");
    expect(info.downloadUrl).toContain(`v${version}`);
    expect(info.downloadUrl).toContain("x86_64-unknown-linux-gnu");
  });
});
