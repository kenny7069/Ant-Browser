package backend

import "runtime"

// suiteReleaseLayout names the mandatory Suite payload entries for one target.
// Every installed-release check requires the manifest target to equal the
// running GOOS/GOARCH, so callers resolve the layout from the current target.
type suiteReleaseLayout struct {
	GUI      string
	Client   string
	Xray     string
	SingBox  string
	Chromium string
}

var suiteWindowsReleaseLayout = suiteReleaseLayout{
	GUI:      "AntBrowser.exe",
	Client:   "ant-farm-client.exe",
	Xray:     "runtime/xray.exe",
	SingBox:  "runtime/sing-box.exe",
	Chromium: "runtime/chrome/chrome.exe",
}

// macOS keeps the signed bundles intact: the GUI and Chromium are .app
// bundles whose main executables are the covered binaries.
var suiteDarwinReleaseLayout = suiteReleaseLayout{
	GUI:      "AntBrowser.app/Contents/MacOS/AntBrowser",
	Client:   "ant-farm-client",
	Xray:     "runtime/xray",
	SingBox:  "runtime/sing-box",
	Chromium: "runtime/chrome/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
}

func suiteReleaseLayoutFor(goos string) suiteReleaseLayout {
	if goos == "darwin" {
		return suiteDarwinReleaseLayout
	}
	return suiteWindowsReleaseLayout
}

func suiteCurrentReleaseLayout() suiteReleaseLayout {
	return suiteReleaseLayoutFor(runtime.GOOS)
}

func (layout suiteReleaseLayout) required() []string {
	return []string{layout.GUI, layout.Client, layout.Xray, layout.SingBox, layout.Chromium, "LICENSES.json"}
}
